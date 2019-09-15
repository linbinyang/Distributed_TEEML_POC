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

#ifndef __PROTOCOL_H
#define __PROTOCOL_H

#include <inttypes.h>
#include <sgx_quote.h>
#include <sgx_key_exchange.h>

/*
 * Define a structure to be used to transfer the Attestation Status 
 * from Server to client and include the Platform Info Blob in base16 
 * format as Message 4.
 *
 * The structure of Message 4 is not defined by SGX: it is up to the
 * service provider, and can include more than just the attestation
 * status and platform info blob.
 */

/*
 * This doesn't have to be binary. 
 */

typedef enum {
	NotTrusted = 0,
	NotTrusted_ItsComplicated,
	Trusted_ItsComplicated,
	Trusted
} attestation_status_t;

/* BGI demo: this is only for debug purpose, all useful information has
   already been exchanged in msg 0~3. */
typedef struct _ra_msg4_struct {
	attestation_status_t status;
	sgx_platform_info_t platformInfoBlob;
} ra_msg4_t;

#define PREFIX_LEN		4
#define PORT_LEN		4
#define CLIENT_KEY_PREFIX	"ID__"
#define RA_PREFIX		"RA__"
#define ERR_PREFIX		"ERR_"
#define OK_PREFIX		"OK__"
#define DATA_WRITE_PREFIX	"DW__"
#define HELLO_MSG		"HEY_"
#define REQUEST_PARAMETER		"REQ_"
#define SEND_PARAMETER  "SEN_"
#define RECEIVE_PARAMETER		"REC_"

// from aggregator
#define START_TRAIN		"STA_"
#define WITH_AVG		"WTA_" //flag1
#define PLE_WAIT		"WAI_" //flag2
#define END_PREFIX		"END_" //flag3

// from node
#define GRADI_INFO		"GRAD"
#define WITH_GRA		"WGA_" //flag2
#define WITHOUT_GRA		"NOG_" //flag3

#pragma pack(push, 1) 

/*
	ECALL pass parameters to the enclave
 */
struct request_record {	/* Can be recorded on the blockchain */
	char algorithm_name[16];
	int nr_clusters; // for kmeans
	int data_dims;
	int max_iters;
	int data_rows;
	double lambda;
	double learning_rate;
	sgx_sha256_hash_t data_hash;
	/* Add anything on-chain here */
};

typedef struct {
	struct {
		struct request_record rec;
		sgx_ec256_signature_t record_sig;	/* Signed by client_pubkey */
		sgx_ec256_public_t client_pubkey;
		sgx_ec256_signature_t client_sig_from_root;	/* Offline acquired from root */
		/* Add anything off-chain here */
	} cmd;
	sgx_cmac_128bit_tag_t command_sig;	/* Signed by shared key */
} compute_request_t;

typedef struct {
	struct {	/* Can be recorded on the blockchain */
		struct request_record rec; /* Same as in compute_request_t */
		int local_data_rows;
		sgx_sha256_hash_t local_data_hash;
		sgx_sha256_hash_t result_hash;
		/* Add anything on-chain here */
	} res;
	sgx_cmac_128bit_tag_t res_sig;	/* Signed by shared key */
	/* TODO: cmac128 is only for online validation. To write to blockchain,
	   implement Tx signing and generate signing key inside Enclave. */
} compute_result_t;

#pragma pack(pop)

#endif

