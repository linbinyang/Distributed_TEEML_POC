/*

Copyright 2018 Intel Corporation

This software and the related documents are Intel copyrighted materials,
and your use of them is governed by the express license under which they
were provided to you (License). Unless the License provides otherwise,
you may not use, modify, copy, publish, distribute, disclose or transmit
this software or the related documents without Intel's prior written
permission.

This software and the related documents are provided as is, with no
express or implied warranties, other than those that are expressly stated
in the License.

*/

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <exception>
#include <stdexcept>
#include <string>
#include "hexutil.h"
#include "msgio.h"
#include "common.h"
#include "protocol.h"
#include "enclave_u.h"

using namespace std;

#ifndef _MSGIO_H
#include "msgio.h"
#endif

MSGIO::MSGIO(zmqio_t *z, config_t *config, reply_t *reply, const char* port_msg, sgx_enclave_id_t o_eid, sgx_ec256_public_t* pub_key, long o_key_len){
	//initialize the parameter of this class
	zmq = z;
	key_len = o_key_len;
	aggregator_pub_key = pub_key;
	port_state.eid = o_eid;
	port_state.state_step = NOT_START_YET;
    /* Construct the unique filename of the SK */
    memset(sk_file_path, 0, sizeof(sk_file_path));
    strcat(sk_file_path, config->opt_sealed_SKfile_path);
    strcat(sk_file_path, port_msg);
    strcat(sk_file_path, file_type);
    memset(port, 0, sizeof(port));
	memcpy(port, port_msg, PORT_LEN);
	memcpy(&port_state.config, config, sizeof(port_state.config));
    memcpy(&port_state.reply, reply, sizeof(port_state.reply));
}

MSGIO::~MSGIO(){}

void MSGIO::do_attestation_by_port(const char* incomming){
	if (!memcmp(incomming, HELLO_MSG, PREFIX_LEN)){
        // Start to initialize the key variables
        if (port_state.state_step != NOT_START_YET){
			z_send_str(zmq, ERR_PREFIX, PREFIX_LEN, "Another RA session for this port is activate.");
			return;
		}
		port_state.state_step = RECEIVE_HELLO;
        printf("Receive Hello MSG from port %s\n", port);
        bool success_status = enclave_get_buffer_sizes_port() && allocate_buffers_port();
        if (!success_status){
            printf("Fail to allocate key buffers for this port\n");
            return;
        }
		z_send_many(zmq, 2, CLIENT_KEY_PREFIX, PREFIX_LEN, aggregator_pub_key, key_len);
	}else if (!memcmp(incomming, REQUEST_PARAMETER, PREFIX_LEN)){
		printf("Receive Parameter request from port %s with public key\n", port);
        /* Just for Test */
        printf("[GatewayAppPort]: sealed_sk_buffer_size_p: %lu\n", sealed_sk_buffer_size_p);
        /* Fetch the public key and generate the SK for this port*/
        memset(outer_public_key_buffer_p, 0, outer_public_key_buffer_size_p);
        memcpy(outer_public_key_buffer_p, &incomming[PREFIX_LEN + PORT_LEN], outer_public_key_buffer_size_p);
		bool generate_SK_flag = enclave_generate_symmetric_key_port(port_state.config.opt_statefile) && save_sealed_SK_port();
        if (!generate_SK_flag){
            printf("Successfully generate SK and save the SK as bin file for the port %s\n", port);
            return;
        }
        /* Start to initialized the enclave with this key */
        if (!enclave_init_with_SK_port()){
            printf("Fails to init the enclave with SK of the port %s\n", port);
            return;
        }
        /* Start to encrypt the data */
		uint8_t *outbuf;
		size_t encrypt_sz = encryption((uint8_t*)&port_state.reply, sizeof(port_state.reply), &outbuf);
		printf("We must note the code on line 380 in main.cpp\n");
		z_send_many(zmq, 2, SEND_PARAMETER, PREFIX_LEN, outbuf, encrypt_sz);
		free(outbuf);
	}else if (!memcmp(incomming, RECEIVE_PARAMETER, PREFIX_LEN)){
		z_send_str(zmq, START_TRAIN, PREFIX_LEN, "Ok, I get it!!!!");
	}else if (!memcmp(incomming, END_PREFIX, PREFIX_LEN)){
		z_send_str(zmq, OK_PREFIX, PREFIX_LEN, "Thanks a lot!!!!");
	}else{
		z_send_str(zmq, ERR_PREFIX, PREFIX_LEN, "Unknown header.");
	}
	return;
}

bool MSGIO::enclave_get_buffer_sizes_port(){
    sgx_status_t ecall_retval = SGX_SUCCESS;
    printf("[GatewayAppPort]: enclave_id_test:%lu\n", port_state.eid);
    sgx_lasterr_port = ecall_calc_buffer_sizes_port(port_state.eid,
                                                        &ecall_retval,
                                                        &outer_public_key_buffer_size_p,
                                                        &sealed_data_buffer_size_p,
                                                        &sealed_sk_buffer_size_p);
    printf("[GatewayAppPort]: outer_public_key_buffer_size_p: %lu\n", outer_public_key_buffer_size_p);
    printf("[GatewayAppPort]: sealed_data_buffer_size_p: %lu\n", sealed_data_buffer_size_p);
    printf("[GatewayAppPort]: sealed_sk_buffer_size_p: %lu\n", sealed_sk_buffer_size_p);
    if (sgx_lasterr_port == SGX_SUCCESS && (ecall_retval != 0)){
        fprintf(stderr, "[GatewayAppPort]: ERROR: ecall_calc_buffer_sizes returned %d\n", ecall_retval);
        sgx_lasterr_port = SGX_ERROR_UNEXPECTED;
    }
    return (sgx_lasterr_port == SGX_SUCCESS);
}

bool MSGIO::allocate_buffers_port(){
    printf("[GatewayAppPort]: Allocating buffers\n");
    outer_public_key_buffer_p = calloc(outer_public_key_buffer_size_p, 1);
    sealed_data_buffer_p = calloc(sealed_data_buffer_size_p, 1);
    sealed_sk_buffer_p = calloc(sealed_sk_buffer_size_p, 1);
    if (outer_public_key_buffer_p == NULL || sealed_data_buffer_p == NULL || sealed_sk_buffer_p == NULL){
        fprintf(stderr, "[GatewayAppPort]: allocate_buffer_port() memory allocation failure\n");
        sgx_lasterr_port = SGX_ERROR_UNEXPECTED;
    }//end if
    return (sgx_lasterr_port == SGX_SUCCESS);
}

bool MSGIO::cleanup_buffers_port(){
    printf("[GatewayAppPort]: Deallocating buffers\n");
    if (sealed_data_buffer_p != NULL){
        free(sealed_data_buffer_p);
        sealed_data_buffer_p = NULL;
    }
    if (outer_public_key_buffer_p != NULL){
        free(outer_public_key_buffer_p);
        outer_public_key_buffer_p = NULL;
    }
    if (sealed_sk_buffer_p != NULL){
        free(sealed_sk_buffer_p);
        sealed_sk_buffer_p = NULL;
    }
    return true;
}

/* Dynamic Load sealed private key into memory */
bool MSGIO::load_enclave_state_port(const char *const statefile){
    void* new_buffer;
    size_t new_buffer_size;
    printf("[GatewayAppPort]: Loading enclave state\n");
    bool ret_status = read_file_into_memory(statefile, &new_buffer, &new_buffer_size);
    if (sealed_data_buffer_p != NULL){
        free(sealed_data_buffer_p);
        sealed_data_buffer_p = NULL;
    }
    /* Put new buffer into context */
    sealed_data_buffer_p = new_buffer;
    sealed_data_buffer_size_p = new_buffer_size;
    return ret_status;
}

/* Dynamic Load sealed SK into memory */
bool MSGIO::load_sealed_sk_port(){
    void* new_buffer;
    size_t new_buffer_size;
    printf("[GatewayAppPort]: Load sealed SK into memory");
    bool ret_status = read_file_into_memory(sk_file_path, &new_buffer, &new_buffer_size);
    /* If we previously allocated a buffer, free it before putting new one in its place */
    // free memory to avoid memory leak
    if (sealed_sk_buffer_p != NULL){
        free(sealed_sk_buffer_p);
        sealed_sk_buffer_p = NULL;
    }
    /* Put new buffer into context */
    sealed_sk_buffer_p = new_buffer;
    sealed_sk_buffer_size_p = new_buffer_size;
    return ret_status;
}

/* Generate Symmetric Key(SK) for this port */
bool MSGIO::enclave_generate_symmetric_key_port(const char *const statefile){
    bool ret_status = true;
    sgx_status_t ecall_retval = SGX_ERROR_UNEXPECTED;
    printf("[GatewayAppPort]: Call enclave to generate symmetric key\n");
    
    /* Step1: ensure that the sealed private key has been already loaded into memory */
    printf("[GatewayAppPort]: Get Sealed Private Key\n");
    if (!(ret_status = load_enclave_state_port(statefile))){
        fprintf(stderr, "[GatewayAppPort]: Failed to load the sealed private.\n");
        sgx_lasterr_port = SGX_ERROR_UNEXPECTED;
        return false;
    }

    /* Step2: Invoke ECALL, 'ecall_unseal_and_generate_SK', to generate one symmetric key (SK) for aggregator and clients */
    sgx_lasterr_port = ecall_unseal_and_generate_SK(port_state.eid,
                                                    &ecall_retval,
                                                    (char *)outer_public_key_buffer_p,
                                                    outer_public_key_buffer_size_p,
                                                    (char *)sealed_data_buffer_p,
                                                    sealed_data_buffer_size_p,
                                                    (char *)sealed_sk_buffer_p,
                                                    sealed_sk_buffer_size_p);
    if (sgx_lasterr_port == SGX_SUCCESS && (ecall_retval != SGX_SUCCESS)){
        fprintf(stderr, "[GatewayAppPort]: ERROR: ecall_unseal_and_generate_SK returned %d\n", ecall_retval);
        sgx_lasterr_port = SGX_ERROR_UNEXPECTED;
    }
    return (sgx_lasterr_port == SGX_SUCCESS);   
}

/* Save the sealed SK onto disk out of enclave */
bool MSGIO::save_sealed_SK_port(){
    bool ret_status = true;
    printf("[GatewayAppPort]: Saving SK state\n");
    FILE *file = open_file(sk_file_path, "wb");
    if (file == NULL){
        fprintf(stderr, "[GatewayAppPort]: save_sealed_SK() fopen failed\n");
        sgx_lasterr_port = SGX_ERROR_UNEXPECTED;
        return false;
    }//end if
    if (fwrite(sealed_sk_buffer_p, sealed_sk_buffer_size_p, 1, file) != 1){
        fprintf(stderr, "[GatewayAppPort]: Enclave state only partially written.\n");
        sgx_lasterr_port = SGX_ERROR_UNEXPECTED;
        ret_status = false;
    }
    fclose(file);
    return ret_status;
}

/* Init the enclave with the specific SK */
bool MSGIO::enclave_init_with_SK_port(){
    bool ret_status = true;
    sgx_status_t ecall_retval = SGX_ERROR_UNEXPECTED;
    /* Step1: ensure that the sealed SK has been already loaded into memory */
    printf("[GatewayAppPort]: Get Sealed Private Key\n");
    if (!(ret_status = load_sealed_sk_port())){
        fprintf(stderr, "[GatewayApp]: Failed to load the sealed SK.\n");
        sgx_lasterr_port = SGX_ERROR_UNEXPECTED;
        return false;
    }
    /* Step2: Invoke ecall new_enclave_init to initialized the enclave */
    printf("[GatewayApp]: Call enclave_init_with_SK_port to initialized the state of the enclave\n");
    sgx_lasterr_port = new_enclave_init(port_state.eid,
                                   &ecall_retval,
                                   (char *) sealed_sk_buffer_p,
                                   sealed_sk_buffer_size_p);
    return sgx_lasterr_port == SGX_SUCCESS;
}

/* Encrypt data use SK */

size_t MSGIO::encryption(uint8_t *inbuf, size_t inbuf_sz, uint8_t **outbuf){
    sgx_status_t retval = SGX_ERROR_UNEXPECTED;
	size_t outbuf_size;
	/* -------------------------get encrypted data size ---------------------------*/
	sgx_lasterr_port = enclave_get_sealed_data_size(port_state.eid, &retval, inbuf_sz, &outbuf_size);
	if (sgx_lasterr_port != SGX_SUCCESS || retval != SGX_SUCCESS) {
		printf("failed to call enclave_get_sealed_data_size(), ret is 0x%x\n", sgx_lasterr_port);
		goto out;
	}
	*outbuf = (uint8_t *)malloc(outbuf_size);
	if (!outbuf)
		goto out;
	memset(*outbuf, 0, outbuf_size);
    /* ----------------------------encrypte data ------------------------------------*/
	sgx_lasterr_port = enclave_seal_data(port_state.eid, &retval, inbuf, inbuf_sz, *outbuf, outbuf_size);
	if (sgx_lasterr_port != SGX_SUCCESS || retval != SGX_SUCCESS) {
		printf("failed to call enclave_seal_data(), ret is 0x%x\n", sgx_lasterr_port);
		goto out;
	}
    printf("enclave 1 sealed datasize if %lu bytes.\n", outbuf_size);	
	return outbuf_size;
out:
	return 0;
}

/* Decrypt data use SK */

size_t MSGIO::decryption(uint8_t* encrypte_inbuf, size_t encrypte_inbuf_size, uint8_t **outbuf){
    sgx_status_t retval = SGX_ERROR_UNEXPECTED;
	size_t outbuf_size;
	/* -------------------------get decrypted data size ---------------------------*/
	sgx_lasterr_port = enclave_get_unsealed_data_size(port_state.eid, &retval, encrypte_inbuf, &outbuf_size);
	if (sgx_lasterr_port != SGX_SUCCESS || retval != SGX_SUCCESS) {
		printf("failed to call enclave_get_sealed_data_size(), ret is 0x%x\n", sgx_lasterr_port);
		goto out;
	}
	*outbuf = (uint8_t*)malloc(outbuf_size);
	if (!outbuf)
		goto out;
	memset(*outbuf, 0, outbuf_size);
	/* ----------------------------decrypt data ------------------------------------*/
	sgx_lasterr_port = enclave_unseal_data(port_state.eid, &retval, *&encrypte_inbuf, encrypte_inbuf_size, *outbuf, outbuf_size);
	if (sgx_lasterr_port != SGX_SUCCESS || retval != SGX_SUCCESS) {
		printf("failed to call enclave_unseal_data(), ret is 0x%x, retval is 0x%x\n", sgx_lasterr_port, retval);
		goto out;
	}
    printf("enclave unsealed data if %lu bytes.\n", outbuf_size);	
	return outbuf_size;
out:
	return 0;
}

