#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "python_c_api.h"

ALGO_IO Algor_interface(ALGO_IO *iters){
	/*
        Pass by List: Transform an C Array to Python List
    */
	Py_Initialize();
    PyRun_SimpleString("import sys");
    PyRun_SimpleString("import numpy as np");
    PyRun_SimpleString("sys.path.append('./')");
	PyObject *pModule = NULL;
	PyObject *pFunc = NULL;
	PyObject *pDict = NULL;
	PyObject *pReturn = NULL;
	pModule = PyImport_ImportModule("client");
    if (!pModule) {
        printf("Can't open python file!\n");
    }
	pDict = PyModule_GetDict(pModule); 
    if (!pDict) {
        printf("Can't find dictionary.\n");
    }
    pFunc = PyDict_GetItemString(pDict, "ComputeGradient");
    /*Prepare for the parameter */
    long len_of_para = sizeof(iters->params)/sizeof(double);
	PyObject *PyList1  = PyList_New(len_of_para);
    PyObject *PyList2  = PyList_New((iters->size)*len_of_para);
    PyObject *PyList3  = PyList_New(iters->size);
    PyObject *ArgList = PyTuple_New(5);
    for(int i = 0; i < PyList_Size(PyList1); i++){
        PyList_SetItem(PyList1, i, PyFloat_FromDouble(iters->params[i]));
    }
    for(int i = 0; i < PyList_Size(PyList2); i++){
        PyList_SetItem(PyList2, i, PyFloat_FromDouble(iters->input_data[i]));
    }
    for(int i = 0; i < PyList_Size(PyList3); i++){
        PyList_SetItem(PyList3, i, PyFloat_FromDouble(iters->label[i]));
    }
    PyTuple_SetItem(ArgList, 0, PyList1);
    PyTuple_SetItem(ArgList, 1, Py_BuildValue("i", iters->size));
    PyTuple_SetItem(ArgList, 2, PyList2);
    PyTuple_SetItem(ArgList, 3, PyList3);
    PyTuple_SetItem(ArgList, 4, Py_BuildValue("d", iters->lambda));

    pReturn =PyObject_CallObject(pFunc, ArgList);

	if(PyList_Check(pReturn)){
		int SizeOfList = PyList_Size(pReturn);
        for(int j = 0; j < SizeOfList; j++){
             PyObject *Item = PyList_GetItem(pReturn, j);
            double result;
			PyArg_Parse(Item, "d", &result);
            iters->grads[j] = result;
            Py_DECREF(Item);
        }
    return *iters;
	}
    else{
        printf("Error, not a List !\n");
        return *iters;
    }
    Py_Finalize();
}

// void main(){
    // Algor_io iters;
    // iters.size = 3;
    // iters.lamda = 1.0;
    // double params[10] = {1,2,3,4,5,6,7,8,9,10};
    // memcpy(&iters.params, params, sizeof(params));
    // double input_data[30] = {7,8,9,10,6,1,2,3,3,1,0,0,0,1,1,1,1,1,9,1,321,123,321,13,11,90,60,90,80,1};
    // memcpy(&iters.input_data, input_data, sizeof(input_data));
    // double label[3] = {1, 0, 1};
    // memcpy(&iters.label, label, sizeof(label));
    // for(int i = 0; i < 1; i++){
    //     iters = Algor_interface(&iters);
    //     for(int j= 0; j < 10; j++){
    //         printf("%.10f", iters.grads[j]);
    //     }
    //     printf("\n");
    // }
// }
