#if !defined(READDATA_H)
#define READDATA_H

#include "datatype.h"

#ifdef __cplusplus
extern "C" {
#endif

int read_text(const char *path, DATATYPE **pout, int *dim, int *n);
int read_binary(const char *path, DATATYPE **pout, int *dim, int *n);

#ifdef __cplusplus
}
#endif

#endif
