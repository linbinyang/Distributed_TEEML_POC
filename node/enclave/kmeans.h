#ifndef KMEANS_H
#define KMEANS_H

#include <stdio.h>
#include <stdlib.h>

#if defined(SGX)
#include "libcproxy.h"
#endif

#include "datatype.h"

#define fail(fmt, ...) handle_error(__FILE__, __LINE__, fmt, ##__VA_ARGS__)
void handle_error(const char *file, int line, const char *fmt, ...);
void debug_echo(const char *fmt, ...);

void *safe_zalloc(size_t sz);
#define safe_free(p)	do {if (p) free(p);} while(0)

void kmeans(DATATYPE *data, DATATYPE *centers, int *cls, int ndata, int ndim, int ncls, int maxiter, int threads);

#endif	/* KMEANS_H */
