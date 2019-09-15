#include <float.h>
#include <pthread.h>

#ifndef KMEANS_H
#include "kmeans.h"
#endif

struct dataset {
	DATATYPE *data;		/* len = ndata*ndim */
	DATATYPE *centers;	/* len = ncls*ndim */
	int *cls;		/* len = ndata */
	int ndata;
	int ndim;
	int ncls;
};

/*
	DATATYPE： double
	ndata： number of data
	ndim： for each data， it has dimension and ndim denotes the dimension
	cls：cluster
	ncls： number of clustes
 */

struct datapart {
	struct dataset *global;
	int *cls_tmp;		/* len = ncls */
	DATATYPE *centers_tmp;	/* len = ncls*ndim */
	int start;
	int end;
	DATATYPE dtot;
	pthread_t thr;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	int doorbell;
};

/* K-means */
static void cluster(struct datapart *work){
	//extract dataset from work
	struct dataset *set = work->global;
	int i, j, k;
	work->dtot = 0;
	for (i = work->start; i < work->end; ++i) {
		DATATYPE dmin = D_MAX; //double max
		for (k = 0; k < set->ncls; ++k) {
			DATATYPE d = 0;
			for (j = 0; j < set->ndim; ++j) {
				DATATYPE t;
				t = set->data[i*set->ndim+j] - set->centers[k*set->ndim+j];
				d += t*t;
			}
			if (d < dmin) {
				/*
					Could be updated multiple times
				*/
				dmin = d;
				set->cls[i] = k;
			}
		}
		work->dtot += dmin;
	}
}

static void calcmean(struct datapart *work){
	struct dataset *set = work->global;
	int i, j, k;

	for (i = 0; i < set->ncls*set->ndim; ++i) {
		work->centers_tmp[i] = 0;
	}
	/*
		For each class, how many points belong to this class
	 */
	for (i = 0; i < set->ncls; ++i) {
		work->cls_tmp[i] = 0;
	}

	for (i = work->start; i < work->end; ++i) {
		k = set->cls[i];
		for (j = 0; j < set->ndim; ++j) {
			work->centers_tmp[k*set->ndim+j] += set->data[i*set->ndim+j];
		}
		++work->cls_tmp[k];
	}
}

static DATATYPE collect_dtot(struct datapart *work, int nwork)
{
	int i;
	DATATYPE dtot = 0;
	
	for (i = 0; i < nwork; ++i) {
		dtot += work[i].dtot;
	}
	
	return dtot;
}

static void collect_mean(struct datapart *work, int nwork)
{
	int i, j, k, c;
	struct dataset *set = work[0].global;

	for (i = 0; i < set->ncls*set->ndim; ++i) {
		set->centers[i] = 0;
	}
	
	for (k = 0; k < set->ncls; ++k) {
		c = 0;
		for (i = 0; i < nwork; ++i) {
			c += work[i].cls_tmp[k];
			for (j = 0; j < set->ndim; ++j) {
				int idx = k*set->ndim+j;
				set->centers[idx] += work[i].centers_tmp[idx];
			}
		}

		for (j = 0; j < set->ndim; ++j) {
			set->centers[k*set->ndim+j] /= c;
		}
	}
}

void *threadproc(void *p)
{
	struct datapart *w = (struct datapart *)p;
	int running = 1;
	while(running) {
		pthread_mutex_lock(&w->mutex);
		while (!w->doorbell) {
			pthread_cond_wait(&w->cond, &w->mutex);
		}
		pthread_mutex_unlock(&w->mutex);
		switch(w->doorbell) {
		case 1:
			cluster(w);
			break;
		case 2:
			calcmean(w);
			break;
		case 3:
		default:
			running = 0;
			break;
		}
		pthread_mutex_lock(&w->mutex);
		if (!w->doorbell) {
			fail("State error.\n");
		}
		w->doorbell = 0;
		pthread_cond_signal(&w->cond);
		pthread_mutex_unlock(&w->mutex);
	}
	return NULL;
}

/* Signal all auxilary threads to go one more step */
void stepall(struct datapart *work, int n, int d)
{
	int i;
	for (i = 1; i < n; ++i) {
		struct datapart *w = &work[i];
		pthread_mutex_lock(&w->mutex);
		if (w->doorbell) {
			fail("State error.\n");
		}
		w->doorbell = d;
		pthread_cond_signal(&w->cond);
		pthread_mutex_unlock(&w->mutex);
	}
}

/* Wait reply from all auxilary threads */
void waitall(struct datapart *work, int n)
{
	int i;
	for (i = 1; i < n; ++i) {
		struct datapart *w = &work[i];
		pthread_mutex_lock(&w->mutex);
		while (w->doorbell) {
			pthread_cond_wait(&w->cond, &w->mutex);
		}
		pthread_mutex_unlock(&w->mutex);
	}
}

void kmeans(DATATYPE *data, DATATYPE *centers, int *cls, int ndata, int ndim, int ncls, int maxiter, int threads)
{
	int i, j;
	DATATYPE dtot, dlast;
	struct dataset set;
	struct datapart *work;
	work = (struct datapart *)safe_zalloc(threads * sizeof(struct datapart));
	set.data = data;
	set.centers = centers;
	set.cls = cls;
	set.ndata = ndata;
	set.ndim = ndim;
	set.ncls = ncls;
	j = set.ndata / threads;
	for (i = 0; i < threads; ++i) {
		work[i].global = &set;
		work[i].cls_tmp = (int *)safe_zalloc(set.ncls*sizeof(int));
		work[i].centers_tmp = (DATATYPE *)safe_zalloc(set.ncls*set.ndim*sizeof(DATATYPE));
		work[i].start = i * j;
		work[i].end = (i+1)*j;
		work[i].doorbell = 0;
		pthread_mutex_init(&work[i].mutex, NULL);
		pthread_cond_init(&work[i].cond, NULL);
	}
	work[threads-1].end = set.ndata;

	/* Init centers as the first nc data points. */
	for (i = 0; i < ncls; ++i) {
		for (j = 0; j < ndim; ++j) {
			set.centers[i * ndim + j] = set.data[i * ndim + j];
		}
	}

	/* Create n-1 auxilary worker threads */
	for (i = 1; i < threads; ++i) {
		pthread_create(&work[i].thr, NULL, threadproc, &work[i]);
	}

	stepall(work, threads, 1);
	cluster(&work[0]);
	waitall(work, threads);
	dlast = collect_dtot(work, threads);
	for (i = 0; i < maxiter; ++i) {
		stepall(work, threads, 2);
		calcmean(&work[0]);
		waitall(work, threads);
		collect_mean(work, threads);
		stepall(work, threads, 1);
		cluster(&work[0]);
		waitall(work, threads);
		dtot = collect_dtot(work, threads);
		if (dtot == dlast) {
			break;
		}
		dlast = dtot;
	}
	debug_echo("Kmeans ends after %d loops. End = %f\n", i, dlast);
	stepall(work, threads, 3);
	waitall(work, threads);
	for (i = 0; i < threads; ++i) {
		safe_free(work[i].cls_tmp);
		safe_free(work[i].centers_tmp);
		pthread_mutex_destroy(&work[i].mutex);
		pthread_cond_destroy(&work[i].cond);
		pthread_join(work[i].thr, NULL);
	}
}

