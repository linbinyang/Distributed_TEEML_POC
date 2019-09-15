#ifndef __PYTHONCAPI_H
#define __PYTHONCAPI_H

#include <python3.5m/Python.h>

typedef struct {
    long size; //number of training samples
    double lambda;
    double* params;
    double* input_data;
    long *label;
    double *grads;
} ALGO_IO;

ALGO_IO Algor_interface(ALGO_IO *iters);

#endif
