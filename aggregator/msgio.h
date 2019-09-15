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

#ifndef __MSGIO_H
#define __MSGIO_H

#include <sys/types.h>
#include <sgx_urts.h>
#include <stdio.h>
#include <string>
#include <sgx_urts.h>
#include <sgx_uae_service.h>
#include <sgx_ukey_exchange.h>
#include "base64.h"
#include "config.h"
#include "zeromqio.h"

#ifndef _FILELOADER_H
extern "C" {
    #include "fileload.h"
}
#endif


using namespace std;

/* A 1MB buffer should be sufficient for demo purposes */
#define MSGIO_BUFFER_SZ	1024*1024
#define DEFAULT_PORT "7777"		// A C string for getaddrinfo()
#define SID_LENGTH	8

enum port_state_step {
	NOT_START_YET,
	RECEIVE_HELLO,
	WAIT_REQUEST,
	WAIT_GRADIENT,
	WORK_DONE
};

typedef struct {
	config_t config;
    reply_t reply;
	port_state_step state_step;
	sgx_enclave_id_t eid;
	sgx_ra_context_t ra_ctx;
} port_state_t;

class MSGIO{
private:
	zmqio_t *zmq;
	char port[10];
    char sk_file_path[256];
    char file_type[5] = ".bin"; //store the key as binary file
	port_state_t port_state;
    sgx_status_t sgx_lasterr_port;
	sgx_ec256_public_t* aggregator_pub_key;
    long key_len;
    void *outer_public_key_buffer_p;
    size_t outer_public_key_buffer_size_p;
    void *sealed_data_buffer_p;
    size_t sealed_data_buffer_size_p;
    void *sealed_sk_buffer_p;
    size_t sealed_sk_buffer_size_p;
public:
	MSGIO(zmqio_t *z, config_t *config, reply_t *reply, const char* port, sgx_enclave_id_t eid, sgx_ec256_public_t* aggregator_pub_key, long key_len);
	~MSGIO();
    bool allocate_buffers_port();
    bool enclave_get_buffer_sizes_port();
    bool cleanup_buffers_port();
    bool load_enclave_state_port(const char *const statefile);
    bool load_sealed_sk_port();
    bool enclave_generate_symmetric_key_port(const char *const statefile);
    bool save_sealed_SK_port();
    bool enclave_init_with_SK_port();
    size_t decryption(uint8_t* encrypte_inbuf, size_t encrypte_inbuf_size, uint8_t **outbuf);
    size_t encryption(uint8_t *inbuf, size_t inbuf_sz, uint8_t **outbuf);
	void do_attestation_by_port(const char *rev_info);
};

#endif