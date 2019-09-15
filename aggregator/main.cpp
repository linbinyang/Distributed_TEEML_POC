using namespace std;

#include "config.h"
#include <stdlib.h>
#include <limits.h>
#include <stdio.h>
#include <time.h>
#include <sgx_urts.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <getopt.h>
#include <unistd.h>
#include <sgx_uae_service.h>
#include <sgx_ukey_exchange.h>
#include <string>
#include "common.h"
#include "protocol.h"
#include "hexutil.h"
#include "msgio.h"
#include "enclave_u.h"
#include "readdata.h"
#include "readconfig.h"
#include <unordered_map>
#include <iostream>

#ifndef _APP_H
extern "C"{
	#include "app.h"
}
#endif

typedef struct config_file_struct{
	char *opt_enclave_path;
	char *opt_statefile;
	char *opt_signature_file;
	char *opt_input_file;
	char *opt_public_key_file;
	char *opt_sealed_SKfile_path;
	char *data_file;
	char *nodelist;
	char *model;
	int node_num;
	int n_clusters;
	int n_iterations;
	double lambda;
	double learning_rate;
} config_file_t;

template <class _Tp>
struct my_equal_to : public binary_function<_Tp, _Tp, bool>{
    bool operator()(const _Tp& __x, const _Tp& __y) const
    { return strcmp( __x, __y ) == 0; }
};

struct Hash_Func{
    //BKDR hash algorithm
    int operator()(char * str)const{
        int seed = 131;
        int hash = 0;
        while(*str)
        {
            hash = (hash * seed) + (*str);
            str ++;
        }
        return hash & (0x7FFFFFFF);
    }
};

typedef unordered_map<char*, MSGIO*, Hash_Func,  my_equal_to<char*> > my_unordered_map;
typedef unordered_map<char*, int, Hash_Func, my_equal_to<char*> > my_state_record;

static void safe_copy_str(char *dest, int dsz, const char *src){
	if (!src || strlen(src) > dsz-1) {
		eprintf("Copy string: NULL or too long.\n");
		exit(1);
	}
	strcpy(dest, src);
}

void split(char **arr, char *str, const char *del) {
    char *s = strtok(str, del);
    while(s != NULL) {
        *arr++ = s;
        s = strtok(NULL, del);
    }
}

#define SAFE_COPY(dst, src)	safe_copy_str(dst, sizeof(dst), src)
#define MSG_SIZE 1024*1024 // 1M should be enough for the POC No.1

int parse_cmdline(int argc, char *argv[], config_t &config, reply_t &reply){
	config_info_t info[] = {
		CONFIG_ENTRY(config_file_t, opt_enclave_path, TYPE_STRING, 0),
		CONFIG_ENTRY(config_file_t, opt_statefile, TYPE_STRING, 0),
		CONFIG_ENTRY(config_file_t, opt_signature_file, TYPE_STRING, 0),
		CONFIG_ENTRY(config_file_t, opt_input_file, TYPE_STRING, 0),
		CONFIG_ENTRY(config_file_t, opt_public_key_file, TYPE_STRING, 0),
		CONFIG_ENTRY(config_file_t, opt_sealed_SKfile_path, TYPE_STRING, 0),
		CONFIG_ENTRY(config_file_t, data_file, TYPE_STRING, 0),
		CONFIG_ENTRY(config_file_t, nodelist, TYPE_STRING, 0),
		CONFIG_ENTRY(config_file_t, model, TYPE_STRING, 0),
		CONFIG_ENTRY(config_file_t, node_num, TYPE_INT, 0),
		CONFIG_ENTRY(config_file_t, n_clusters, TYPE_INT, 0),
		CONFIG_ENTRY(config_file_t, n_iterations, TYPE_INT, 0),
		CONFIG_ENTRY(config_file_t, lambda, TYPE_DOUBLE, 0),
		CONFIG_ENTRY(config_file_t, learning_rate, TYPE_DOUBLE, 0),
	};
	const int info_len = sizeof(info) / sizeof(info[0]);
	config_file_t cf;
	if (argc < 2) {
		eprintf("Usage: %s <config file>\n", argv[0]);
		return 1;
	}
	//initialized the cf variable
	memset(&cf, 0, sizeof(cf));
	memset(&config, 0, sizeof(config));
	memset(&reply, 0, sizeof(reply));
	if(parse_config(argv[1], &cf, info, info_len)) {
		eprintf("Cannot read config.\n");
		return 1;
	}
	if (!cf.nodelist || strlen(cf.nodelist) > sizeof(config.nodelist)-1) {
		eprintf("Invalid server url\n");
		exit(1);
	}
	config.mode = MODE_ATTEST;
	config.model = cf.model;
    SAFE_COPY(config.nodelist, cf.nodelist);
	SAFE_COPY(config.opt_enclave_path, cf.opt_enclave_path);
	SAFE_COPY(config.opt_statefile, cf.opt_statefile);
	SAFE_COPY(config.opt_signature_file, cf.opt_signature_file);
	SAFE_COPY(config.opt_input_file, cf.opt_input_file);
	SAFE_COPY(config.opt_public_key_file, cf.opt_public_key_file);
	SAFE_COPY(config.opt_sealed_SKfile_path, cf.opt_sealed_SKfile_path);
	config.n_clusters = cf.n_clusters;
	config.max_iters = cf.n_iterations;
	config.node_num = cf.node_num;
	config.lambda = cf.lambda;
	config.learning_rate = cf.learning_rate;
	/* Prepare the reply info which contains parameter */
	reply.n_clusters = cf.n_clusters;
	reply.lambda = cf.lambda;
	reply.learning_rate = cf.learning_rate;
	reply.max_iters = cf.n_iterations;
	reply.model = cf.model;
	printf("nodelist: %s\n", config.nodelist);
	printf("model: %s\n", config.model);
	printf("node_num: %d\n", config.node_num);
	printf("n_clusters: %d\n", config.n_clusters);
	printf("n_iterations: %d\n", config.max_iters);
	printf("lambda: %f\n", config.lambda);
	printf("learning_rate: %f\n", config.learning_rate);
	printf("opt_enclave_path: %s\n", config.opt_enclave_path);
	printf("opt_statefile: %s\n", config.opt_statefile);
	printf("opt_signature_file: %s\n", config.opt_signature_file);
	printf("opt_input_file: %s\n", config.opt_input_file);
	printf("opt_public_key_file: %s\n", config.opt_public_key_file);
	printf("opt_sealed_SKfile_path: %s\n", config.opt_sealed_SKfile_path);
	printf("data_file: %s\n", cf.data_file);
	/* For the POC, we do not need to load any data on the aggregator side */
	if (!cf.data_file || read_text(cf.data_file, (DATATYPE **)&config.local_db, &config.local_dims, &config.local_entries)){
		eprintf("Cannot read data file.\n");
		return 1;
	}
	eprintf("Local data (%d, %d)\n", config.local_entries, config.local_dims);
	cleanup_config();
	return 0;
}

static zmqio_t *z;
int main (int argc, char *argv[]){
	config_t config;
	reply_t reply;
	if(parse_cmdline(argc, argv, config, reply)) {
		return 1;
	}
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
	/* 3. Generate public key and sealed private key*/
	success_status = enclave_generate_key() && save_enclave_state(config.opt_statefile) && save_public_key(config.opt_public_key_file);
	if (!success_status){
		printf("[GatewayApp]: Failed to generate and save the sealed private key!\n");
		return -1;
	}
	/* 4. Start to transfer the public key to each node*/
	/* 4.1 Prepare the zmq server for multiple clients */
	const char *del = "!";
	char *arr[config.node_num+1]; // server_ip + number of port
	split(arr, config.nodelist, del);
	z = z_new_server(arr, config.node_num);
	my_unordered_map port_table;
	unordered_map<int, bool> round_is_full;
	unordered_map<int, int> round_sephomore;
	unordered_map<int, double*> round_value;
	/* 4.1.1 Initialized the hashmap */
	for (int i = 0; i < config.node_num; i ++){
		port_table.insert(my_unordered_map::value_type(arr[i+1], new MSGIO(z, &config, &reply, arr[i+1], enclave_id_test, (sgx_ec256_public_t*) public_key_buffer, public_key_buffer_size)));
	}
	for (int j = 1; j <= config.max_iters; j ++){
		round_is_full.insert(pair<int, bool>(j, false));
		round_sephomore.insert(pair<int, int>(j, 0));
		round_value.insert(pair<int, double*>(j, new double[64]));
	}
	char default_port[5] = "7777";
	/* By default the mode is MODE_ATTEST*/
	config.mode = MODE_ATTEST;
	if (config.mode == MODE_ATTEST) {
		cout << "Waiting for clients to connect......\n";
		char incomming[MSG_SIZE];
		int around_num = 0;
		for (;;){
			size_t incomming_sz = sizeof(incomming);
			int rc_stat = z_recv(z, incomming, &incomming_sz);
			if (rc_stat){
				eprintf("Error reading from zmq: %d\n", rc_stat);
				break;
			}
			//extract port from the msg, we can modify it to cookie later
			char port_info[PORT_LEN+1];
			memset(port_info, 0, sizeof(port_info));
			memcpy(port_info, &incomming[PREFIX_LEN], PORT_LEN);
			MSGIO* msgio = port_table[port_info];
			if (!memcmp(incomming, GRADI_INFO, PREFIX_LEN)){
				//first check which around
				//decrypt data
				memcpy(&around_num, &incomming[PREFIX_LEN+PORT_LEN], sizeof(around_num));
				printf("Around Number:%d\n", around_num);
				if (!memcmp(&incomming[PREFIX_LEN + PORT_LEN + sizeof(around_num)], WITH_GRA, PREFIX_LEN)){
					printf("WITH_GRA\n");
					uint8_t *outbuf;
					/* Before decrypt, we should load the corresponding SK for this port */
					if (!msgio->enclave_init_with_SK_port()){
						printf("Fails to init the enclave with SK of the port %s\n", port_info);
						return -1;
					}
					size_t decrypt_sz = msgio->decryption((uint8_t*)&incomming[PREFIX_LEN*2+PORT_LEN+sizeof(around_num)], sizeof(incomming)-PREFIX_LEN*2-PORT_LEN-sizeof(around_num), &outbuf);
					double *temp_arr = round_value[around_num];
					/*
						Will research about memory allocation in C++ later
					*/
					double temp_pool[64];
					memcpy(temp_pool, outbuf, decrypt_sz);
					free(outbuf);
					if (round_sephomore[around_num] < config.node_num){
						for (int i = 0; i < 64; i ++){
							temp_arr[i] = temp_arr[i] + (double)temp_pool[i]/(double)config.node_num;
						}// get the avg of gradient
						int temp = round_sephomore[around_num];
						round_sephomore.erase(around_num);
						round_sephomore.insert(pair<int, int>(around_num, temp+1));
						if (round_sephomore[around_num] == config.node_num){
							round_is_full[around_num] = true;
						}
					}
				}
				if (round_is_full[around_num]){
					/*
						which means we can sent the avg gradient
						1. encrypt the gradient data
						2. send the data
						3. check round_sephomore to decide whether or not we should free the space 
					*/
					double* fetch_arr = round_value[around_num];
					uint8_t* outbuf_en;
					if (!msgio->enclave_init_with_SK_port()){
						printf("Fails to init the enclave with SK of the port %s\n", port_info);
						return -1;
					}
					size_t encrypt_sz = msgio->encryption((uint8_t*)fetch_arr, sizeof(fetch_arr), &outbuf_en);
					int temp = round_sephomore[around_num];
					round_sephomore.erase(around_num);
					round_sephomore.insert(pair<int, int>(around_num, temp - 1));
					if (around_num == config.max_iters){
						z_send_many(z, 3, START_TRAIN, PREFIX_LEN, END_PREFIX, PREFIX_LEN, outbuf_en, encrypt_sz);
					}else{
						z_send_many(z, 3, START_TRAIN, PREFIX_LEN, WITH_AVG, PREFIX_LEN, outbuf_en, encrypt_sz);
					}
					free(outbuf_en);
				}else{
					//the node must wait
					z_send_many(z, 2, START_TRAIN, PREFIX_LEN, PLE_WAIT, PREFIX_LEN);
				}
			}else{
				printf("Start to communication and generate Symmetric Key for port: %s\n", port_info);
				// we have not got the key, so continue the RA process
				msgio->do_attestation_by_port(incomming);
			}
		}
		//close zmq & enclave and the dynamic allocated memory for each port
		destroy_enclave();
		for(int i = 0; i < config.node_num; i ++){
			MSGIO *msgio = port_table[arr[i+1]];
			msgio->cleanup_buffers_port();
		}
		z_close(z);
	}else{
		printf("New Mode, we have not develop yet!!!\n");
		destroy_enclave();
		z_close(z);
		return -1;
	}
}

static void *newthreadproc(void *opaque){
	void *r;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	// ret = ecall_newthread(eid, &r, (int)(long long)opaque, (unsigned long long)pthread_self());
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