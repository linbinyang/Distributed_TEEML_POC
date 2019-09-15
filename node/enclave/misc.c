#include <stdio.h>      /* vsnprintf */
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <sgx_trts.h>
#include <assert.h>
#include <setjmp.h>
#include "Enclave_t.h"  /* ocalls */
#include <stdarg.h>
#include <string.h>

#ifndef KMEANS_H
#include "kmeans.h"
#endif

#include "pthread.h"

void debug_echo(const char *fmt, ...)
{
	char buf[1024];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, 1024, fmt, ap);
	va_end(ap);
	oc_print_error(buf);
}

void handle_error(const char *file, int line, const char *fmt, ...)
{
	char buf[1024];
	int pos = 0;
	va_list ap;

	snprintf(buf, 1024, "%s:%d ", file, line);
	pos = strlen(buf);

	va_start(ap, fmt);
	vsnprintf(&buf[pos], 1024-pos, fmt, ap);
	va_end(ap);
	
	oc_print_error(buf);
	
	((void (*)())0)();/* Cause error */
}

#define CHECK_oc_ERROR(f)		do {			\
		int _sgx_ret = f;				\
		if (SGX_SUCCESS != _sgx_ret) {			\
			handle_error(__FILE__, __LINE__, 	\
				"Error %d at %s:%d\n", 		\
				_sgx_ret);			\
		}						\
	} while (0)

void *safe_zalloc(size_t sz)
{
	void *ret = malloc(sz);
	if (!ret) {
		fail("Cannot allocate memory size = %ld\n", sz);
	}
	if (!sgx_is_within_enclave(ret, sz)) {
		fail("Cannot allocate EPC memory size = %ld\n", sz);
	}
	memset(ret, 0, sz);
	return ret;
}

struct threadhelper {
	unsigned long magic[4];
	unsigned long long tid;
	int running;
	void *(*start_routine) (void *);
	void *arg;
};

#define N_THREAD_SLOTS		16
static struct threadhelper *thread_slots[N_THREAD_SLOTS];

void *ecall_newthread(int slot, unsigned long long tid)
{
	volatile struct threadhelper *ph;
	void *(*start_routine) (void *);
	void *arg;

	if (slot < 0 || slot >= N_THREAD_SLOTS) {
		return NULL;
	}
	
	ph = __atomic_exchange_n(&thread_slots[slot], NULL, __ATOMIC_SEQ_CST);
	if (!ph) {
		return NULL;
	}

	while (ph->tid != tid) {}
	
	start_routine = ph->start_routine;
	arg = ph->arg;
	
	/* Set running = 1 will release threadhelper on the other stack. */
	ph->running = 1;
	
	return start_routine(arg);
}

int pthread_create(pthread_t *t, const pthread_attr_t *attr,
                  void *(*start_routine) (void *), void *arg)
{
	volatile struct threadhelper helper;
	struct threadhelper *tmp;
	unsigned long long retid;
	int slot;

	helper.tid = 0;
	helper.running = 0;
	helper.start_routine = start_routine;
	helper.arg = arg;
	
	for (slot = 0;;) {
		tmp = NULL;
		if (__atomic_compare_exchange_n(&thread_slots[slot], &tmp, 
						&helper, 1, __ATOMIC_SEQ_CST,
						__ATOMIC_RELAXED)) {
		    	break;
		}
		++slot;
		if (slot >= N_THREAD_SLOTS) {
			slot = 0;
		}
	}
	
	CHECK_oc_ERROR(oc_new_thread(&retid, slot));
	helper.tid = retid;
	while (!helper.running) {}
	t->id = retid;
	return 0;
}

int pthread_join(pthread_t t, void **retval)
{
	int ret;
	unsigned long long rv;
	CHECK_oc_ERROR(oc_pthread_join(&ret, t.id, &rv));
	if (retval) {
		*retval = (void *)rv;
	}
	return ret;
}
