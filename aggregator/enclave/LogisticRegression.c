#include <float.h>
#include <pthread.h>
#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

#ifndef LOGISTIC_H
#include "LogisticRegression.h"
#endif

#define MAX_LINE 1024

// Sigmoid Function
double sigmoid(double x){
    double exp_value;
    double res;
    exp_value = exp((double)-x);
    res = 1 / (1 + exp_value);
    return res;
}

// Inner Product of two vector
double inner_multiply(double *x, double *y, int start, int len){
    double res = 0.0;
    x = x + start;
    for (int index = 0; index < len; index ++){
        double mult_res = (*x) * (*y);
        res = res + mult_res;
        x ++;
        y ++;
    }
    return res;
}

// Object Function
double log_likelihood(int ndata, int dimension, double* para, double *dataset, long *label, double lambda){
    double likelihood = 0.0;
    for (int i = 0; i < ndata; i ++){
        //loop through the one-dimension array
        double logits = inner_multiply(dataset, para, i*dimension, dimension);
        likelihood = likelihood - exp(1 + exp(-logits));
        if (label[i] == 0){
            // Case the correspoding label is 0, not 1
            likelihood = likelihood - logits;
        }
    }
    // Consider the regularization
    for (int k = 0; k < dimension; k ++){
        likelihood = likelihood - lambda*para[k]*para[k];
    }
    return -likelihood;
}

// Gradient Descent
void GradientDescent(double* dw, int ndata, int dimension, double* para, double *dataset, long *label, double lambda){
    memset(dw, 0.0, dimension);
    for (int i = 0; i < ndata; i ++){
        double logits = inner_multiply(dataset, para, i*dimension, dimension);
        for (int k = 0; k < dimension; k ++){
            dw[k] = dw[k] + dataset[i*dimension + k]*(1 - sigmoid(logits));
            if (label[i] == 0){
                dw[k] = dw[k] - dataset[i*dimension + k];
            }
        }
    }
    for (int h = 0; h < dimension; h ++){
        dw[h] = dw[h] - lambda * 2 * para[h];
        dw[h] = -dw[h];
    }
}

//training the model
void LR(int ndata, int dimension, double* para, double *dataset, int max_iter, double learning_rate, double lambda){
    double* dw = (double*)malloc(dimension*sizeof(double));
    double* feature = (double*)malloc(ndata*(dimension-1)*sizeof(double));
    long* label = (long*)malloc(ndata*sizeof(long));
    //begin split the data
    split_label_feature(ndata, dimension, dimension - 1, dataset, feature, label);
    for (int i = 0; i < max_iter; i ++){
        double temp_likelihood = log_likelihood(ndata, dimension, para, dataset, label, lambda);
        debug_echo("**********%d inter**********likelihood = %f\n", i, temp_likelihood);
        //update parameter
        GradientDescent(dw, ndata, dimension, para, dataset, label, lambda);
        for (int i = 0; i < dimension; i ++){
            para[i] = para[i] - learning_rate*dw[i];
        }
    }
    double temp_likelihood = log_likelihood(ndata, dimension, para, dataset, label, lambda);
    debug_echo("**********%d inter**********likelihood = %f\n", max_iter, temp_likelihood);
    free(dw);
    free(feature);
    free(label);
}

void split_label_feature(int ndata, int dimension, int f_dimension, double* dataset, double *feature, long* label){
    /*
        0 - dimension-2: feature
        dimension - 1: label
    */
    long index_for_label = 0;
    for (int i = 0; i < ndata; i ++){
        for (int j = 0; j < dimension; j ++){
            if (j == dimension - 1){
                //which means this is label
                label[index_for_label++] = (long)dataset[i*dimension + j];
            }else{
                //which means this is feature
                feature[i*f_dimension+j] = dataset[i*dimension + j];
            }
        }
    }//end for
}

int main (){
   // FILE *fp;
   // int dimension = 65;
   // int ndata = 800;
   // double *dataset = (double*)malloc(dimension*ndata*sizeof(double));
    // int *label = (int*)malloc(ndata*sizeof(int));
   // double *para = (double*)malloc(dimension*sizeof(double));
   // int max_iter = 10;
   // double learning_rate = 0.01;
   // double lambda = 0.5;
   // char linestr;
    // memset(dataset,1,dimension*ndata);
    // memset(label,0,ndata);
    // memset(para, 0, dimension);
    // LogitsticRegression(ndata, dimension, para, dataset, label, max_iter,learning_rate,lambda);
   // fp = fopen("/Users/linbinyang/Desktop/FL/kmeans/kmeans-data/data.txt","rb");
   // if (NULL == fp){
   //     printf("Cannot open the file");
   //     exit(0);
   // }
   // char buf[MAX_LINE];
   // int len;
   // int index = 0;
   // int index_label = 0;
   // int line = 0;
    //load dataset and label from disk into our memory
  //  while (fgets(buf, MAX_LINE, fp) != NULL){
  //      len = strlen(buf);
   //     for (int i = 0; i < len - 1; i ++){
   //         int reminder = i % 2;
   //         if (reminder == 0){
   //             dataset[index] = atof(&buf[i]);
   //             index = index + 1;
    //        }
    //    }
  //  }
    //After Loading the data into memory, we can start out LR Model
   // fclose(fp);
   // LogitsticRegression(ndata, dimension, para, dataset, max_iter, learning_rate, lambda);
   // free(dataset);
    // free(label);
    return 0;
}
