import numpy as np

def sigmoid(x):
    return 1/(1+np.exp(-x))
    
def inner_mutiply(x, y):
    return sum([x[i]*y[i] for i in range(len(x))])
    
def ComputeGradient(W, ndata, input_data, label, lam):
    dim = len(W)
    dw = [0]*dim
    for i in range(ndata):
        unit_feature = input_data[i*dim: i*dim+dim]
        logits = inner_mutiply(unit_feature, W)
        for k in range(len(W)):
            dw[k] += unit_feature[k]*(1-sigmoid(logits))
            if label[i] == 0:
                dw[k] -= unit_feature[k]
        for k in range(len(W)):
            dw[k] -= lam*2*W[k]
    return [-x for x in dw]