#ifndef LOGISTIC_H
#define LOGISTIC_H

#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

double sigmoid(double x);
double inner_multiply(double *x, double *y, int start, int len);
double log_likelihood(int ndata, int dimension, double* para, double *dataset, long *label, double lambda);
void GradientDescent(double* dw, int ndata, int dimension, double* para, double *dataset, long *label, double lambda);
void LR(int ndata, int dimension, double* para, double *dataset, int max_iter, double learning_rate, double lambda);
void split_label_feature(int ndata, int dimension, int f_dimension, double* dataset, double *feature, long* label);

#endif