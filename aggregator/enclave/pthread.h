#ifndef SGX_PTHREAD_H
#define SGX_PTHREAD_H

#include <sgx_thread.h>

/* From SGX SDK */
#define pthread_mutex_t		sgx_thread_mutex_t
#define pthread_mutex_init	sgx_thread_mutex_init
#define pthread_mutex_destroy	sgx_thread_mutex_destroy
#define pthread_mutex_lock	sgx_thread_mutex_lock
#define pthread_mutex_unlock	sgx_thread_mutex_unlock

#define pthread_cond_t		sgx_thread_cond_t
#define pthread_cond_init	sgx_thread_cond_init
#define pthread_cond_destroy	sgx_thread_cond_destroy
#define pthread_cond_wait	sgx_thread_cond_wait
#define pthread_cond_signal	sgx_thread_cond_signal

/* Thread support */
typedef struct {
	unsigned long long id;
} pthread_t;
#define	pthread_attr_t		void	/* Not used */
int pthread_create(pthread_t *t, const pthread_attr_t *attr,
                  void *(*start_routine) (void *), void *arg);
int pthread_join(pthread_t t, void **retval);

#endif
