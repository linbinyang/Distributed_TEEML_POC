#include "config.h"
#include <stdlib.h>
#include <limits.h>
#include <stdio.h>
#include <sys/stat.h>
#include <string.h>
#include <sys/types.h>
#include <signal.h>
#include <getopt.h>
#include <unistd.h>
#include <sgx_key_exchange.h>
#include <sgx_report.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include "common.h"
#include "hexutil.h"
#include "protocol.h"
#include "zeromqio.h"
#include "readdata.h"
#include "readconfig.h"
#include <sgx_urts.h>
#include "Enclave_u.h"
#include <map>
#include <string>
#include <iostream>
#include <algorithm>
using namespace std;

#ifndef _APP_H
extern "C"{
	#include "app.h"
}
#endif

#ifndef LOGISTIC_H
extern "C"{
	#include "LogisticRegression.h"
}
#endif

#ifndef __PYTHONCAPI_H
extern "C"{
	#include "python_c_api.h"
}
#endif

char debug = 0;
char verbose = 0;

#define NNL <<endl<<endl<<
#define NL <<endl<<

enum tarining_state {
	FIRST_AROUND,
	WAIT_AVG_GRAD,
	END_TRAINING
};

zmqio_t *z;

typedef struct {
	char *data_file;
	char *port;
	char *server;
	char *opt_enclave_path;
	char *opt_statefile;
	char *opt_signature_file;
	char *opt_input_file;
	char *opt_public_key_file;
	char *opt_sealed_SKfile_path;
} config_file_t;

typedef struct request_struct {
	int n_clusters;
	int max_iters;
	int data_dims;
	int data_rows;
	double lambda;
	double learning_rate;
	char *model;
} request_t;

static void safe_copy_str(char *dest, int dsz, const char *src){
	if (!src || strlen(src) > dsz-1) {
		eprintf("Copy string: NULL or too long.\n");
		exit(1);
	}
	strcpy(dest, src);
}

#define SAFE_COPY(dst, src)	safe_copy_str(dst, sizeof(dst), src)
#define ENCLAVE_NAME "./enclave/enclave.signed.so"
#define SHARED_KEY "AABBCCDDEEFFGGHHIIJJKKLLMMNNOOQQ"

int parse_cmdline(int argc, char *argv[], config_t &config){
	printf("%s\n","parse_cmdline is called!");
	config_info_t info[] = {
		CONFIG_ENTRY(config_file_t, data_file, TYPE_STRING, 0),
		CONFIG_ENTRY(config_file_t, port, TYPE_STRING, 0),
		CONFIG_ENTRY(config_file_t, server, TYPE_STRING, 0),
		CONFIG_ENTRY(config_file_t, opt_enclave_path, TYPE_STRING, 0),
		CONFIG_ENTRY(config_file_t, opt_statefile, TYPE_STRING, 0),
		CONFIG_ENTRY(config_file_t, opt_signature_file, TYPE_STRING, 0),
		CONFIG_ENTRY(config_file_t, opt_input_file, TYPE_STRING, 0),
		CONFIG_ENTRY(config_file_t, opt_public_key_file, TYPE_STRING, 0),
		CONFIG_ENTRY(config_file_t, opt_sealed_SKfile_path, TYPE_STRING, 0),
	};
	const int info_len = sizeof(info) / sizeof(info[0]);
	config_file_t cf;
	memset(&config, 0, sizeof(config));
	memset(&cf, 0, sizeof(cf));
    if(parse_config(argv[1], &cf, info, info_len)) {
		eprintf("Cannot read config.\n");
		return 1;
	}
	printf("data_file:%s\n", cf.data_file);
	printf("port:%s\n", cf.port);
	printf("server:%s\n", cf.server);
	printf("opt_enclave_path:%s\n", cf.opt_enclave_path);
	printf("opt_statefile:%s\n", cf.opt_statefile);
	printf("opt_signature_file:%s\n", cf.opt_signature_file);
	printf("opt_input_file:%s\n", cf.opt_input_file);
	printf("opt_public_key_file:%s\n", cf.opt_public_key_file);
	printf("opt_sealed_SKfile_path:%s\n", cf.opt_sealed_SKfile_path);
    //load info include n_clusters and n_inerations into the config
	//data structure
	SAFE_COPY(config.data_file_path, cf.data_file);
	SAFE_COPY(config.server, cf.server);
	SAFE_COPY(config.port, cf.port);
	SAFE_COPY(config.opt_enclave_path, cf.opt_enclave_path);
	SAFE_COPY(config.opt_statefile, cf.opt_statefile);
	SAFE_COPY(config.opt_signature_file, cf.opt_signature_file);
	SAFE_COPY(config.opt_input_file, cf.opt_input_file);
	SAFE_COPY(config.opt_public_key_file, cf.opt_public_key_file);
	SAFE_COPY(config.opt_sealed_SKfile_path, cf.opt_sealed_SKfile_path);
	return 0;
}

static int around_num = 0; //record the training around of the model
int main(int argc, char *argv[]){
	config_t config;
	DATATYPE *data;
	int datasize;
	ALGO_IO iters;
	tarining_state t_stat = FIRST_AROUND;
	if(parse_cmdline(argc, argv, config)) {
		return 1;
	}
	if (read_text(config.data_file_path, &data, &config.data_dims, &config.data_rows)){
		eprintf("Cannot open data file.\n");
		return 1;
	}
	datasize = config.data_dims*config.data_rows*sizeof(DATATYPE);
	/* 1. Launch the enclave */
	if (!create_enclave(config.opt_enclave_path)){
		printf("[GatewayApp]: Failed to create the enclave for aggregator!\n");
		return -1;
	}
	/* 2. Allocate Buffer for Keys */
	bool success_status = false;
	success_status = enclave_get_buffer_sizes() && allocate_buffers();
	if (!success_status){
		printf("[GatewayApp]: Failed to allocate buffer for keys!\n");
		return -1;
	}
	/* 3. Generate public key and sealed private key */
	success_status = enclave_generate_key() && save_enclave_state(config.opt_statefile) && save_public_key(config.opt_public_key_file);
	if (!success_status){
		printf("[GatewayApp]: Failed to generate and save the sealed private key!\n");
		return -1;
	}
	/* 4. Start to transfer the public key to each node */
	sgx_status_t ret, retval;
	char incoming[1024*1024]; //1M should be enough for POC No.2
	size_t incoming_sz = sizeof(incoming);
	z = z_new_client(config.server);
	/* 4.1. Send HELLO_MSG to request public key from the Aggregator */
	z_send_many(z, 2, HELLO_MSG, PREFIX_LEN, config.port, PORT_LEN);
	int rc;
	rc = z_recv(z, incoming, &incoming_sz);
	if (rc){
		eprintf("[GatewayApp]: Error reading from ZMQ, not receiving public key info from !!!\n");
		return -1;
	}
	/* 4.2. Upon receiving public key then generate Symmetric Key */
	bool sucess_status = false;
	if (!memcmp(incoming, CLIENT_KEY_PREFIX, PREFIX_LEN)){
		edividerWithText("Receive Key and Signature from Aggregator");
		/* 4.2.1. Start to generate symmetric key(SK) and store it as binary file for the node side*/
		APP_GetPubKey((sgx_ec256_public_t *)&incoming[PREFIX_LEN]);
		success_status = enclave_generate_symmetric_key(config.opt_statefile) && save_sealed_SK(config.opt_sealed_SKfile_path);
		if (!success_status){
			eprintf("[GatewayApp]: Error in generating SK and save SK as bin file!!!\n");
		}
		/* 4.2.2. Upon generating SK, the node would send its public key to other side*/
		z_send_many(z, 3, REQUEST_PARAMETER, PREFIX_LEN, config.port, PORT_LEN, public_key_buffer, public_key_buffer_size);
	}
	incoming_sz = sizeof(incoming);
	rc = z_recv(z, incoming, &incoming_sz);
	if (rc){
		eprintf("[GatewayApp]: Error reading from ZMQ, not reveiving parameter info from aggregator!!!\n");
		return -1;
	}
	request_t request_info;
	/* 4.3. Start to initialized the enclave with the SK we just generate */
	success_status = enclave_init_with_SK(config.opt_sealed_SKfile_path);
	if (!success_status){
		eprintf("[GatewayApp]: Error in initializing the enclave!!!\n");
		return -1;
	}
	if (!memcmp(incoming, SEND_PARAMETER, PREFIX_LEN)){
		edividerWithText("Receive training parameter from Aggregator");
		uint8_t *outbuf1;
		size_t decrypt_sz = decryption((uint8_t*)&incoming[PREFIX_LEN], sizeof(incoming)-PREFIX_LEN, &outbuf1);
		memcpy (&request_info, outbuf1, sizeof(request_info));
		printf("Lambda:%f\n", request_info.lambda);
		printf("Learning rate:%f\n", request_info.learning_rate);
		printf("Max_iter:%d\n", request_info.max_iters);
		iters.lambda = request_info.lambda;
		iters.size = config.data_rows;
		//dynamic allocate memory for ALGO_IO
		iters.params = (double*)malloc(sizeof(double)*(config.data_dims-1));
		iters.input_data = (double*)malloc((sizeof(double))*(config.data_dims-1)*config.data_rows);
		iters.label = (long*)malloc(sizeof(long)*config.data_rows);
		iters.grads = (double*)malloc(sizeof(double)*(config.data_dims-1));
		//tell the aggregator that I have already received the the parameters
		z_send_many(z, 2, RECEIVE_PARAMETER, PREFIX_LEN, config.port, PORT_LEN);
		free(outbuf1);
	}
	/* 4.4. Start to training */
	edividerWithText("Start Training");
	//After receive the parameter, set an infinite loop to do training work
	//first we should prepare the parameter
	long label[config.data_rows];
	double feature[config.data_rows*(config.data_dims - 1)];
	double para[config.data_dims-1]; //W
	double grad[config.data_dims-1]; //dw
	memcpy(iters.grads, grad, sizeof(grad)); //intialized with 0.0
	memcpy(iters.params, para, sizeof(para)); //initialized with 0.0
	split_label_feature(config.data_rows, config.data_dims, config.data_dims - 1, data, feature, label); //get the data
	memcpy(iters.label, label, sizeof(label));
	memcpy(iters.input_data, feature, sizeof(feature));
	for(;;){
		incoming_sz = sizeof(incoming);
		rc = z_recv(z, incoming, &incoming_sz);
		if (rc){
			eprintf("Error reading from ZMQ!!!\n");
			return -1;	
		}
		if (!memcmp(incoming, START_TRAIN, PREFIX_LEN)){
			switch(t_stat){
				case FIRST_AROUND:
					if(around_num < request_info.max_iters){
						//encrypt the current gradient
						around_num ++;
						uint8_t *outbuf;
						//SingleLR(config.data_rows, config.data_dims - 1, feature, label, grad, para, request_info.lambda, request_info.learning_rate);
						Algor_interface(&iters);
						size_t encrypt_sz = encryption((uint8_t*)iters.grads, sizeof(grad), &outbuf);
						printf("Successfully encrypted one gradient!\n");
						printf("********************%d inter*******************\n", around_num);
						z_send_many(z, 5, GRADI_INFO, PREFIX_LEN, config.port, PORT_LEN, &around_num, sizeof(around_num), WITH_GRA, PREFIX_LEN, outbuf, encrypt_sz);
						free(outbuf);
					}
					t_stat = WAIT_AVG_GRAD;
					break;
				case WAIT_AVG_GRAD:
					if (!memcmp(&incoming[PREFIX_LEN], WITH_AVG, PREFIX_LEN)){
						uint8_t *outbuf1_sz;
						size_t decrypt_sz = decryption((uint8_t*)&incoming[PREFIX_LEN*2], sizeof(incoming)-PREFIX_LEN*2, &outbuf1_sz);
						memset(para, 0, sizeof(para));
						memcpy(para, outbuf1_sz, decrypt_sz);
						free(outbuf1_sz);
						// update the parameter of the current iters
						memcpy(iters.params, para, sizeof(para)); 
						// SingleLR(config.data_rows, config.data_dims - 1, feature, label, grad, para, request_info.lambda, request_info.learning_rate);
						if (around_num < request_info.max_iters){
							around_num ++;
							printf("********************%d inter*******************\n", around_num);
							uint8_t *outbuf_co;
							// then compute the gradient again
							Algor_interface(&iters);
							size_t encrypt_sz_co = encryption((uint8_t*)iters.grads, sizeof(grad), &outbuf_co);
							z_send_many(z, 5, GRADI_INFO, PREFIX_LEN, config.port, PORT_LEN, &around_num, sizeof(around_num), WITH_GRA, PREFIX_LEN, outbuf_co, encrypt_sz_co);
							free(outbuf_co);
						}
					}else if (!memcmp(&incoming[PREFIX_LEN], PLE_WAIT, PREFIX_LEN)){
						z_send_many(z, 4, GRADI_INFO, PREFIX_LEN, config.port, PORT_LEN, &around_num, sizeof(around_num), WITHOUT_GRA, PREFIX_LEN);
					}else if (!memcmp(&incoming[PREFIX_LEN], END_PREFIX, PREFIX_LEN)){
						uint8_t *outbuf1_sz_1;
						size_t decrypt_sz_1 = decryption((uint8_t*)&incoming[PREFIX_LEN*2], sizeof(incoming)-PREFIX_LEN*2, &outbuf1_sz_1);
						memset(para, 0, sizeof(para));
						memcpy(para, outbuf1_sz_1, decrypt_sz_1);
						free(outbuf1_sz_1);
						// SingleLR(config.data_rows, config.data_dims - 1, feature, label, grad, para, request_info.lambda, request_info.learning_rate);
						// Now we get the final model
						for (int i = 0; i < config.data_dims; i ++){
							printf("W[%d]=%f ", i, para[i]);
							if (i != 0 && i%8 == 0){
								printf("\n");
							}
						}
						//then we should release memory to avoid memeory leak
						free(iters.grads);
						free(iters.input_data);
						free(iters.params);
						free(iters.label);
						cleanup_buffers();
						destroy_enclave();
						z_close(z);
						return 0; //end the client
					}
				break;
				case END_TRAINING:
				break;
				default:
				break;
			}//end for switch
		}
	}//infinite loop
	return 0;
}

static void *newthreadproc(void *opaque){
	void *r;
	sgx_status_t ret;
	ret = ecall_newthread(enclave_id_test, &r, (int)(long long)opaque, (unsigned long long)pthread_self());
	if (ret != SGX_SUCCESS) {
		eprintf("Cannot invoke ecall_newthread\n");
		return NULL;
	}
	return r;
}

unsigned long long oc_new_thread(int slot){
	pthread_t p;
	pthread_create(&p, NULL, newthreadproc, (void *)(long long)slot);
	return (unsigned long long)p;
}

int oc_pthread_join(unsigned long long id, unsigned long long *rv){
	void *tmp;
	int r;
	r = pthread_join((pthread_t)id, &tmp);
	*rv = (unsigned long long)tmp;
	return r;
}

void oc_print_error(const char *buf){
	eprintf("%s", buf);
}
