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

#ifndef __ENCLAVE_QUOTE_H
extern "C" {
	#include "enclave.h"
}
#endif

#ifndef ENCLAVE_T_H__
extern "C" {
	#include "enclave_t.h"
}
#endif

#ifndef __PROTOCOL_H
extern "C" {
	#include "protocol.h"
}
#endif

#ifndef LOGISTIC_H
extern "C"{
	#include "LogisticRegression.h"
}
#endif

#ifndef KMEANS_H
extern "C"{
	#include "kmeans.h"
}
#endif

#include <stdlib.h>
#include <sgx_utils.h>
#include <sgx_tae_service.h>
#include <sgx_tkey_exchange.h>
#include <sgx_tcrypto.h>
#include <ecp_interface.h>
#include <cstdio>
#include "sgx.h"
#include "sgx_trts.h"
#include "sgx_tseal.h"
#include "sgx_error.h"
#include "string.h"

struct secure_message_t {
	sgx_aes_gcm_data_t message_aes_gcm_data;
};

struct session {
	sgx_key_128bit_t shared_key;
};

struct session g_session;

static const sgx_ec256_public_t def_root_key = {
    {
        0xad, 0xa3, 0xa8, 0xa2, 0x02, 0xd7, 0x2e, 0x14,
        0xde, 0x81, 0xec, 0xf8, 0x3a, 0xdb, 0xd6, 0x12,
        0xe9, 0xf6, 0x90, 0xfb, 0x53, 0x1c, 0x2d, 0x27,
        0x49, 0x48, 0x25, 0xdd, 0xe8, 0xbd, 0xe1, 0x19,
    },
    {
        0x37, 0x40, 0x07, 0x60, 0x74, 0x60, 0x47, 0x10,
        0xf0, 0x7f, 0xbb, 0x56, 0x4d, 0xdd, 0x16, 0x44,
        0xa3, 0xaa, 0x34, 0x0c, 0x51, 0xbe, 0xf7, 0x58,
        0x37, 0x7d, 0xc0, 0xb5, 0x57, 0xf2, 0x65, 0x0a,
    }
};

#define PSE_RETRIES	5	/* Arbitrary. Not too long, not too short. */

/*----------------------------------------------------------------------
 * WARNING
 *----------------------------------------------------------------------
 *
 * End developers should not normally be calling these functions
 * directly when doing remote attestation:
 *
 *    sgx_get_ps_sec_prop()
 *    sgx_get_quote()
 *    sgx_get_quote_size()
 *    sgx_get_report()
 *    sgx_init_quote()
 *
 * These functions short-circuits the RA process in order
 * to generate an enclave quote directly!
 *
 * The high-level functions provided for remote attestation take
 * care of the low-level details of quote generation for you:
 *
 *   sgx_ra_init()
 *   sgx_ra_get_msg1
 *   sgx_ra_proc_msg2
 *
 *----------------------------------------------------------------------
 */

extern "C" sgx_status_t get_report(sgx_report_t *report, sgx_target_info_t *target_info){
#ifdef SGX_HW_SIM
	return sgx_create_report(NULL, NULL, report);
#else
	return sgx_create_report(target_info, NULL, report);
#endif
}

extern "C" size_t get_pse_manifest_size (){
	return sizeof(sgx_ps_sec_prop_desc_t);
}

extern "C" sgx_status_t get_pse_manifest(char *buf, size_t sz){
	sgx_ps_sec_prop_desc_t ps_sec_prop_desc;
	sgx_status_t status= SGX_ERROR_SERVICE_UNAVAILABLE;
	int retries= PSE_RETRIES;
	do {
		status= sgx_create_pse_session();
		if ( status != SGX_SUCCESS ) return status;
	} while (status == SGX_ERROR_BUSY && retries--);
	if ( status != SGX_SUCCESS ) return status;

	status= sgx_get_ps_sec_prop(&ps_sec_prop_desc);
	if ( status != SGX_SUCCESS ) return status;
	memcpy(buf, &ps_sec_prop_desc, sizeof(ps_sec_prop_desc));
	sgx_close_pse_session();
	return status;
}

extern "C" int ecdsa_verify(void *buf, size_t bufsz, const sgx_ec256_public_t *pubkey, sgx_ec256_signature_t *sig){
	sgx_status_t s;
	uint8_t r = SGX_EC_INVALID_SIGNATURE;
	sgx_ecc_state_handle_t h = NULL;
	if (sgx_ecc256_open_context(&h) != SGX_SUCCESS) {
		return -1;
	}
	s = sgx_ecdsa_verify((const uint8_t*)buf, bufsz, pubkey, sig, &r, h);
	sgx_ecc256_close_context(h);
	return (s != SGX_SUCCESS) || (r == SGX_EC_INVALID_SIGNATURE);
}

extern "C" int verify_sig(sgx_ec256_public_t *key, sgx_ec256_signature_t *sig, const sgx_ec256_public_t *root_key){
	int i;
	unsigned char buf[PREFIX_LEN + SGX_ECP256_KEY_SIZE * 2];
	memcpy(buf, CLIENT_KEY_PREFIX, PREFIX_LEN);
	for (i = 0; i < SGX_ECP256_KEY_SIZE; ++i) {
		buf[4+i] = key->gx[SGX_ECP256_KEY_SIZE - i - 1];
	}
	for (i = 0; i < SGX_ECP256_KEY_SIZE; ++i) {
		buf[4+SGX_ECP256_KEY_SIZE+i] = key->gy[SGX_ECP256_KEY_SIZE - i - 1];
	}
	return ecdsa_verify(buf, sizeof(buf), root_key, sig);
}

extern "C" sgx_status_t enclave_ra_init(sgx_ec256_public_t key, sgx_ec256_signature_t sig, int b_pse, sgx_ra_context_t *ctx, sgx_status_t *pse_status){
	sgx_status_t ra_status;
    if (verify_sig(&key, &sig, &def_root_key)) {
        return SGX_ERROR_UNEXPECTED;
    }
	/*
	 * If we want platform services, we must create a PSE session 
	 * before calling sgx_ra_init()
	 */

	if ( b_pse ) {
		int retries= PSE_RETRIES;
		do {
			*pse_status= sgx_create_pse_session();
			if ( *pse_status != SGX_SUCCESS ) return SGX_ERROR_UNEXPECTED;
		} while (*pse_status == SGX_ERROR_BUSY && retries--);
		if ( *pse_status != SGX_SUCCESS ) return SGX_ERROR_UNEXPECTED;
	}
	
/*
   The function sgx_ra_init() accepts the service provider's public key as an argument 
   and returns an opaque context for the DHKE that will occur during Remote Attestation. 
   Using a context that is opaque to the client provides replay protection.
*/

	ra_status= sgx_ra_init(&key, b_pse, ctx);

	if ( b_pse ) {
		int retries= PSE_RETRIES;
		do {
			*pse_status= sgx_create_pse_session();
			if ( *pse_status != SGX_SUCCESS ) return SGX_ERROR_UNEXPECTED;
		} while (*pse_status == SGX_ERROR_BUSY && retries--);
		if ( *pse_status != SGX_SUCCESS ) return SGX_ERROR_UNEXPECTED;
	}

	return ra_status;
}

extern "C" sgx_status_t enclave_ra_close(sgx_ra_context_t ctx){
        sgx_status_t ret;
        ret = sgx_ra_close(ctx);
        return ret;
}

/*
 * Return a SHA256 hash of the requested key. KEYS SHOULD NEVER BE
 * SENT OUTSIDE THE ENCLAVE IN PLAIN TEXT. This function let's us
 * get proof of possession of the key without exposing it to untrusted
 * memory.
 */

extern "C" sgx_status_t enclave_ra_get_key_hash(sgx_ra_context_t ctx, sgx_sha256_hash_t *mkhash, sgx_sha256_hash_t *skhash){
	sgx_status_t ret;
	sgx_ra_key_128_t k;
	// First get the requested key which is one of:
	//  * SGX_RA_KEY_MK 
	//  * SGX_RA_KEY_SK
	// per sgx_ra_get_keys().

	ret = sgx_ra_get_keys(ctx, SGX_RA_KEY_SK, &k);
	if ( ret != SGX_SUCCESS ) goto out;

	/* Now generate a SHA hash */

	ret = sgx_sha256_msg((const uint8_t *) &k, sizeof(k), 
		(sgx_sha256_hash_t *) skhash);
	if ( ret != SGX_SUCCESS ) goto out;

	ret = sgx_ra_get_keys(ctx, SGX_RA_KEY_MK, &k);
	if ( ret != SGX_SUCCESS ) goto out;

	ret = sgx_sha256_msg((const uint8_t *) &k, sizeof(k), 
		(sgx_sha256_hash_t *) mkhash);
	if ( ret != SGX_SUCCESS ) goto out;

	/* Let's be thorough */
out:
	memset(k, 0, sizeof(k));

	return ret;
}

extern "C" void dumphex(void *buf, int len) {
	for (int i = 0; i < len; ++i) {
		debug_echo("%02x", ((unsigned char *)buf)[i]);
	}
	debug_echo("\n");
}

extern "C" sgx_status_t enclave_do_calculation(sgx_ra_context_t ctx, compute_request_t *req, void *encrypted_data, size_t encrypted_bytes,
	void *local_data, size_t local_bytes, 
	int local_entries, int local_dim, int nthreads,
	compute_result_t *result,
	void *out_data, size_t out_bytes)
{
	sgx_ra_key_128_t k;
	sgx_status_t status = SGX_ERROR_UNEXPECTED;
	int *cls = NULL;
	DATATYPE *plain = NULL;
	sgx_sha256_hash_t hash;

	if (local_bytes != local_entries * local_dim * sizeof(DATATYPE)) {
		debug_echo("local_bytes check failed.\n");
		return SGX_ERROR_INVALID_PARAMETER;
	}
        //string model_name = req->cmd.rec.algorithm_name;
	if (!strcmp(req->cmd.rec.algorithm_name, "KM")){
		if (out_bytes < sizeof(DATATYPE) * req->cmd.rec.data_dims * req->cmd.rec.nr_clusters) {
			debug_echo("out_bytes check failed.\n");
			return SGX_ERROR_INVALID_PARAMETER;
		}
	}else if (!strcmp(req->cmd.rec.algorithm_name, "LR")){
		if (out_bytes != sizeof(DATATYPE) * req->cmd.rec.data_dims){
			debug_echo("out_bytes check failed.\n");
			return SGX_ERROR_INVALID_PARAMETER;
		}
	}
	/* Check compute_request_t: 1) CMAC, 2) ECDSA, 3) parameters */
	status = sgx_ra_get_keys(ctx, SGX_RA_KEY_MK, &k);
	if (status != SGX_SUCCESS) {
		debug_echo("sgx_ra_get_keys SGX_RA_KEY_MK failed.\n");
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_cmac_128bit_tag_t mac;
	status = sgx_rijndael128_cmac_msg(&k, (uint8_t*)&req->cmd, sizeof(req->cmd), &mac);
	memset(k, 0, sizeof(k));
	if (status != SGX_SUCCESS) {
		debug_echo("sgx_rijndael128_cmac_msg failed.\n");
		return SGX_ERROR_UNEXPECTED;
	}
	if (memcmp(&mac, &req->command_sig, sizeof(mac))) {
		debug_echo("command_sig check failed.\n");
		return SGX_ERROR_UNEXPECTED;
	}
    if (verify_sig(&req->cmd.client_pubkey, &req->cmd.client_sig_from_root, &def_root_key)) {
		debug_echo("client_sig_from_root check failed.\n");
        return SGX_ERROR_UNEXPECTED;
    }
    if (ecdsa_verify(&req->cmd.rec, sizeof(req->cmd.rec), &req->cmd.client_pubkey, &req->cmd.record_sig)) {
		debug_echo("record_sig check failed.\n");
        return SGX_ERROR_UNEXPECTED;
    }
	if (encrypted_bytes != 16 + req->cmd.rec.data_rows * req->cmd.rec.data_dims * sizeof(DATATYPE)) {
		debug_echo("encrypted_bytes check failed.\n");
		return SGX_ERROR_INVALID_PARAMETER;
	}
	if (req->cmd.rec.data_dims != local_dim) {
		//the dimension of encrypted data and local data should be the same
		debug_echo("data_dims check failed.\n");
		return SGX_ERROR_INVALID_PARAMETER;
	}
	/* All check passed, allocate memory */
	int ndata = req->cmd.rec.data_rows + local_entries;
	// Combine data from the client and service
	// This is a new ndata
	if (!strcmp(req->cmd.rec.algorithm_name, "KM")){
		cls = (int *)safe_zalloc(sizeof(int) * ndata);
		if (!cls) {
		debug_echo("cls allocation failed.\n");
		return SGX_ERROR_OUT_OF_MEMORY;
		}
	}
	plain = (DATATYPE *)safe_zalloc(encrypted_bytes-16+local_bytes);
	if (!plain) {
		debug_echo("plain allocation failed.\n");
		status = SGX_ERROR_OUT_OF_MEMORY;
		if (cls) free(cls);
		if (plain) free(plain);
		return status;
	}

	/* Decrypt client data */
	status = sgx_ra_get_keys(ctx, SGX_RA_KEY_SK, &k);
	if (status != SGX_SUCCESS) {
		debug_echo("sgx_ra_get_keys SGX_RA_KEY_SK failed.\n");
		if (cls) free(cls);
		if (plain) free(plain);
		return status;
	}
/*
	sgx_sha256_msg((uint8_t *)encrypted_data, encrypted_bytes, &hash);
	debug_echo("encrypted data hash %d\n", encrypted_bytes);
	dumphex(&hash, sizeof(hash));
	sgx_sha256_msg((uint8_t *)&k, sizeof(k), &hash);
	debug_echo("SK hash %d\n", sizeof(k));
	dumphex(&hash, sizeof(hash));
*/
	sgx_status_t status_1 = sgx_aes_ctr_decrypt(&k, &((uint8_t*)encrypted_data)[16], encrypted_bytes-16, (uint8_t *)encrypted_data, 128, (uint8_t*)plain);
	memset(k, 0, sizeof(k));
	if (status_1 != SGX_SUCCESS) {
		debug_echo("sgx_aes_ctr_decrypt failed.\n");
		if (cls) free(cls);
		if (plain) free(plain);
		return status;
	}
	status = sgx_sha256_msg((uint8_t *)plain, encrypted_bytes-16, &hash);
	if (status != SGX_SUCCESS) {
		debug_echo("sgx_sha256_msg plain failed.\n");
		if (cls) free(cls);
		if (plain) free(plain);
		return status;
	}
	if (memcmp(&hash, &req->cmd.rec.data_hash, sizeof(hash))) {
		debug_echo("data hash mismatch.\n");
		dumphex(&hash, sizeof(hash));
		dumphex(&req->cmd.rec.data_hash, sizeof(req->cmd.rec.data_hash));
		status = SGX_ERROR_UNEXPECTED;
		if (cls) free(cls);
		if (plain) free(plain);
		return status;
	}

	void *local_data_start = &((char *)plain)[encrypted_bytes-16];
	//conbine data from the local and remote
	memcpy(local_data_start, local_data, local_bytes);
	/* Save local data hash before calculating */
	status = sgx_sha256_msg((const uint8_t*)local_data_start, local_bytes, &hash);
	if (status != SGX_SUCCESS) {
		debug_echo("sgx_sha256_msg local_data failed.\n");
		goto out;
	}
	if (!strcmp(req->cmd.rec.algorithm_name, "KM")){
    	debug_echo("kmeans(ndata = %d, dim = %d, cls = %d, iter = %d, numberOfthreads = %d).\n", ndata, req->cmd.rec.data_dims, req->cmd.rec.nr_clusters, req->cmd.rec.max_iters, nthreads);
		kmeans(plain, (double *)out_data, cls, ndata, req->cmd.rec.data_dims, req->cmd.rec.nr_clusters, req->cmd.rec.max_iters, nthreads);
	}else if (!strcmp(req->cmd.rec.algorithm_name, "LR")){
		debug_echo("Logistic Regression(ndata = %d, dim = %d, iter = %d, numberOfthreads = %d, lambda=%f, learning_rate=%f).\n", ndata, req->cmd.rec.data_dims, req->cmd.rec.max_iters, nthreads, req->cmd.rec.lambda, req->cmd.rec.learning_rate);
		LR(ndata, req->cmd.rec.data_dims, (double *)out_data, plain, req->cmd.rec.max_iters, req->cmd.rec.learning_rate, req->cmd.rec.lambda);
	}
	memset(result, 0, sizeof(*result));
	memcpy(&result->res.rec, &req->cmd.rec, sizeof(req->cmd.rec));
	result->res.local_data_rows = local_entries;
	memcpy(&result->res.local_data_hash, hash, sizeof(hash));
	status = sgx_sha256_msg((uint8_t *)out_data, out_bytes, &result->res.result_hash);
	if (status != SGX_SUCCESS) {
		debug_echo("sgx_sha256_msg tmpout failed.\n");
		goto out;
	}
	status = sgx_ra_get_keys(ctx, SGX_RA_KEY_MK, &k);
	if (status != SGX_SUCCESS) {
		debug_echo("sgx_ra_get_keys SGX_RA_KEY_MK failed.\n");
		return SGX_ERROR_UNEXPECTED;
	}
	status = sgx_rijndael128_cmac_msg(&k, (uint8_t*)&result->res, sizeof(result->res), &result->res_sig);
	memset(k, 0, sizeof(k));
	if (status != SGX_SUCCESS) {
		debug_echo("sgx_rijndael128_cmac_msg result failed.\n");
		goto out;
	}
	status = SGX_SUCCESS;
out:
	if (cls) free(cls);
	if (plain) free(plain);
	return status;
}

/*
	What we can do here is to get the return results of the Enclave function
*/

/*
	Start from here, what we do is to seal and unseal data in the SGX environment
*/

extern "C" sgx_status_t enclave_init(uint8_t* key, size_t len)
{
	int i, val;
	uint8_t * buf = (uint8_t *)&g_session.shared_key;

	if (len < sizeof(sgx_key_128bit_t) * 2)
		return SGX_ERROR_INVALID_PARAMETER;

	for (i = 0; i < (int)len / 2; i++) {
		val = ((*(key+i) & 0xf) * 16) + (*(key + i + 1) & 0xf);
	        buf[i] = (uint8_t)val;	
	}

	return SGX_SUCCESS;
}

extern "C" sgx_status_t enclave_get_sealed_data_size(size_t message_size, size_t *sealed_message_size)
{
	*sealed_message_size = sizeof(sgx_aes_gcm_data_t) + message_size;
	return SGX_SUCCESS;
}

extern "C" sgx_status_t enclave_get_unsealed_data_size(uint8_t* encrypted_data, size_t *plaintext_size)
{
    sgx_aes_gcm_data_t * sec_msg = (sgx_aes_gcm_data_t *)encrypted_data;

    if (!encrypted_data || !plaintext_size){
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
    *plaintext_size = sec_msg->payload_size;
    return SGX_SUCCESS;
}

extern "C" sgx_status_t enclave_seal_data(uint8_t* message, size_t message_size, uint8_t* outbuf, size_t outbuf_size)
{
	const uint8_t* plaintext;
	uint32_t plaintext_length;
	// outbuf_size = sizeof(outbuf);
	uint8_t *encrypted_data;

	// outbuf_size = sizeof(sgx_aes_gcm_data_t) + message_size;
	encrypted_data = (uint8_t *)malloc(outbuf_size);
    if (!encrypted_data)
        return SGX_ERROR_OUT_OF_MEMORY;
	memset(encrypted_data, 0, outbuf_size);

	sgx_status_t status;
	secure_message_t * sec_msg = (struct secure_message_t *)encrypted_data;
	plaintext = (const uint8_t*)"abc";
    plaintext_length = (uint32_t)strlen((char*)plaintext);

	sec_msg->message_aes_gcm_data.payload_size = (uint32_t)message_size;

	status = sgx_rijndael128GCM_encrypt(&g_session.shared_key, message, message_size,
                reinterpret_cast<uint8_t *>(sec_msg->message_aes_gcm_data.payload),
                reinterpret_cast<uint8_t *>(sec_msg->message_aes_gcm_data.reserved),
                sizeof(sec_msg->message_aes_gcm_data.reserved), plaintext, plaintext_length,
                &(sec_msg->message_aes_gcm_data.payload_tag));

	memcpy(outbuf, encrypted_data, outbuf_size);
    free(encrypted_data);
	return status;

}

extern "C" sgx_status_t enclave_unseal_data(uint8_t* message, size_t message_size, uint8_t *outbuf, size_t outbuf_size)
{
	const uint8_t* plaintext;
    uint32_t plaintext_length;
	size_t decrypted_data_length;
	uint8_t *decrypted_data;
	sgx_status_t status = SGX_SUCCESS;
	secure_message_t * sec_msg = (struct secure_message_t *)message;
	plaintext = (const uint8_t*)"abc";
    plaintext_length = (uint32_t)strlen((char*)plaintext);

	if (message_size < sizeof(sgx_aes_gcm_data_t))
		return SGX_ERROR_INVALID_PARAMETER;

	decrypted_data_length = (size_t)sec_msg->message_aes_gcm_data.payload_size;
    decrypted_data = (uint8_t*)malloc(decrypted_data_length);
    if (!decrypted_data)
        return SGX_ERROR_OUT_OF_MEMORY;
	memset(decrypted_data, 0, decrypted_data_length);

	//Decrypt the response message payload
	status = sgx_rijndael128GCM_decrypt(&g_session.shared_key, sec_msg->message_aes_gcm_data.payload,
        	        decrypted_data_length, decrypted_data,
                	reinterpret_cast<uint8_t *>(sec_msg->message_aes_gcm_data.reserved),
                	sizeof(sec_msg->message_aes_gcm_data.reserved), plaintext, plaintext_length,
                	&sec_msg->message_aes_gcm_data.payload_tag);
    	if(SGX_SUCCESS != status)
    	{
    	}

	memcpy(outbuf, decrypted_data, decrypted_data_length < outbuf_size ? decrypted_data_length : outbuf_size);
	
	// memcpy(outbuf, decrypted_data, decrypted_data_length);
	// outbuf_size = decrypted_data_length;

    free(decrypted_data);
	return status;
}

extern "C" sgx_status_t enclave_test(){
    const uint8_t* plaintext;
    uint32_t plaintext_length;
    uint32_t decrypted_data_length;
    uint8_t *decrypted_data;
    sgx_status_t status = SGX_SUCCESS;
	plaintext = (const uint8_t*)"abc";
    plaintext_length = (uint32_t)strlen((char*)plaintext);
	uint8_t data[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
	uint32_t message_size = sizeof(data);
	sgx_aes_gcm_data_t * sec_msg = (sgx_aes_gcm_data_t *)malloc(sizeof(sgx_aes_gcm_data_t) + message_size);
	memset(sec_msg, 0, sizeof(sgx_aes_gcm_data_t) + message_size);
	sec_msg->payload_size = message_size;
	status = sgx_rijndael128GCM_encrypt(&g_session.shared_key, data, message_size,
                reinterpret_cast<uint8_t *>(&(sec_msg->payload)),
                reinterpret_cast<uint8_t *>(&(sec_msg->reserved)),
                sizeof(sec_msg->reserved), plaintext, plaintext_length,
                &(sec_msg->payload_tag));

	if (status != SGX_SUCCESS)
		return status;

	decrypted_data_length = sec_msg->payload_size;
    	decrypted_data = (uint8_t*)malloc(decrypted_data_length);
    	if (!decrypted_data)
        	return SGX_ERROR_OUT_OF_MEMORY;
	memset(decrypted_data, 0, decrypted_data_length);

	//Decrypt the response message payload
	status = sgx_rijndael128GCM_decrypt(&g_session.shared_key, sec_msg->payload,
        	        decrypted_data_length, decrypted_data,
                	reinterpret_cast<uint8_t *>(&(sec_msg->reserved)),
                	sizeof(sec_msg->reserved), plaintext, plaintext_length,
                	&sec_msg->payload_tag);

	if (memcmp(decrypted_data, data, sizeof(data)) != 0)
		return SGX_ERROR_UNEXPECTED;

        free(decrypted_data);
	return status;		
}

extern "C" sgx_status_t ecall_calc_buffer_sizes(size_t* epubkey_size, size_t* esealedprivkey_size, size_t* esignature_size){
  *epubkey_size = sizeof(sgx_ec256_public_t);
  *esealedprivkey_size = sgx_calc_sealed_data_size(0U, sizeof(sgx_ec256_private_t));
  *esignature_size = sizeof(sgx_ec256_signature_t);
  print("\nTrustedApp: Sizes for public key, sealed private key and signature calculated successfully.\n");
  return SGX_SUCCESS;
}

extern "C" sgx_status_t ecall_calc_buffer_sizes_port(size_t* epubkey_size, size_t* esealedprivkey_size, size_t* sealed_SK_size){
  *epubkey_size = sizeof(sgx_ec256_public_t);
  *esealedprivkey_size = sgx_calc_sealed_data_size(0U, sizeof(sgx_ec256_private_t));
  *sealed_SK_size = sgx_calc_sealed_data_size(0U, sizeof(sgx_ec_key_128bit_t));
  print("\nTrustedApp: Sizes for public key, sealed private key and signature calculated successfully.\n");
  return SGX_SUCCESS;
}

/**
 * This function generates a key pair and then seals the private key.
 *
 * @param pubkey                 Output parameter for public key.
 * @param pubkey_size            Input parameter for size of public key.
 * @param sealedprivkey          Output parameter for sealed private key.
 * @param sealedprivkey_size     Input parameter for size of sealed private key.
 *
 * @return                       SGX_SUCCESS (Error code = 0x0000) on success, some
 *                               sgx_status_t value upon failure.
 */

extern "C" sgx_status_t ecall_key_gen_and_seal(char *pubkey, size_t pubkey_size, char *sealedprivkey, size_t sealedprivkey_size){
  // Step 1: Open Context.
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  sgx_ecc_state_handle_t p_ecc_handle = NULL;

  if ((ret = sgx_ecc256_open_context(&p_ecc_handle)) != SGX_SUCCESS){
    print("\nTrustedApp: sgx_ecc256_open_context() failed !\n");
    goto cleanup;
  }

  // Step 2: Create Key Pair.
  sgx_ec256_private_t p_private;
  if ((ret = sgx_ecc256_create_key_pair(&p_private, (sgx_ec256_public_t *)pubkey, p_ecc_handle)) != SGX_SUCCESS){
    print("\nTrustedApp: sgx_ecc256_create_key_pair() failed !\n");
    goto cleanup;
  }

  // Step 3: Calculate sealed data size.
  if (sealedprivkey_size >= sgx_calc_sealed_data_size(0U, sizeof(p_private))){
    if ((ret = sgx_seal_data(0U, NULL, sizeof(p_private), (uint8_t *)&p_private, (uint32_t) sealedprivkey_size, (sgx_sealed_data_t *)sealedprivkey)) != SGX_SUCCESS){
      print("\nTrustedApp: sgx_seal_data() failed !\n");
      goto cleanup;
    }
  }else{
    print("\nTrustedApp: Size allocated for sealedprivkey by untrusted app is less than the required size !\n");
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }
  print("\nTrustedApp: Key pair generated and private key was sealed. Sent the public key and sealed private key back.\n");
  ret = SGX_SUCCESS;

cleanup:
  // Step 4: Close Context.
  if (p_ecc_handle != NULL){
    sgx_ecc256_close_context(p_ecc_handle);
  }
  return ret;
}

/**
 * This function unseals the sealed data from app and then performs ECDSA signing on
 * this unsealed data.
 *
 * @param msg                Input parameter for message to be signed. Message may
 *                           be some sensor data.
 * @param msg_size           Input parameter for size of message.
 * @param sealed             Input parameter for sealed data.
 * @param sealed_size        Input parameter for size of sealed data.
 * @param signature          Output parameter for signature/signed data.
 * @param signature_size     Input parameter for size of signature/signed data.
 *
 * @return                   SGX_SUCCESS (Error code = 0x0000) on success, some
 *                           other appropriate sgx_status_t value upon failure.
 */

extern "C" sgx_status_t ecall_unseal_and_sign(uint8_t *msg, uint32_t msg_size, char *sealed, size_t sealed_size, char *signature, size_t signature_size){
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  sgx_ecc_state_handle_t p_ecc_handle = NULL;

  print("\nTrustedApp: Received sensor data and the sealed private key.\n");

  // Step 1: Calculate sealed/encrypted data length.
  uint32_t unsealed_data_size = sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)sealed);
  uint8_t * const unsealed_data = (uint8_t *)malloc(unsealed_data_size); // Check malloc return;
  if (unsealed_data == NULL)
  {
    print("\nTrustedApp: malloc(unsealed_data_size) failed !\n");
    goto cleanup;
  }

  // Step 2: Unseal data.
  if ((ret = sgx_unseal_data((sgx_sealed_data_t *)sealed, NULL, NULL, unsealed_data, &unsealed_data_size)) != SGX_SUCCESS)
  {
    print("\nTrustedApp: sgx_unseal_data() failed !\n");
    goto cleanup;
  }

  // Step 3: Open Context.
  if ((ret = sgx_ecc256_open_context(&p_ecc_handle)) != SGX_SUCCESS){
    print("\nTrustedApp: sgx_ecc256_open_context() failed !\n");
    goto cleanup;
  }

  // Step 4: Perform ECDSA Signing.
  if ((ret = sgx_ecdsa_sign(msg, msg_size, (sgx_ec256_private_t *)unsealed_data, (sgx_ec256_signature_t *)signature, p_ecc_handle)) != SGX_SUCCESS){
    print("\nTrustedApp: sgx_ecdsa_sign() failed !\n");
    goto cleanup;
  }
  print("\nTrustedApp: Unsealed the sealed private key, signed sensor data with this private key and then, sent the signature back.\n");
  ret = SGX_SUCCESS;

cleanup:
  // Step 5: Close Context, release memory
  if (p_ecc_handle != NULL){
    sgx_ecc256_close_context(p_ecc_handle);
  }
  if (unsealed_data != NULL){
    memset_s(unsealed_data, unsealed_data_size, 0, unsealed_data_size);
    free(unsealed_data);
  }
  return ret;
}

extern "C" sgx_status_t ecall_unseal_and_generate_SK(char *pubkey, size_t pubkey_size, char *sealed, size_t sealed_size, char *Sk_sealed, size_t Sk_sealed_size){
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    sgx_ecc_state_handle_t p_ecc_handle = NULL;
	print("\nTrustedApp: Received public key and generate SK for encryption\n");
	/*Step1: Unsealed the private.bin as the private key */
	uint32_t unsealed_data_size = sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)sealed);
	uint8_t * const unsealed_data = (uint8_t *)malloc(unsealed_data_size); // Check malloc return;
	sgx_ec256_dh_shared_t dh_key;
	memset(&dh_key, 0, sizeof(dh_key));
	sgx_ec_key_128bit_t smkey = {0};
    sgx_ec_key_128bit_t skey = {0};
    sgx_ec_key_128bit_t mkey = {0};
    sgx_ec_key_128bit_t vkey = {0};
	if (unsealed_data == NULL){
    	print("\nTrustedApp: malloc(unsealed_data_size) failed !\n");
    	goto cleanup;
  	}
	if ((ret = sgx_unseal_data((sgx_sealed_data_t *)sealed, NULL, NULL, unsealed_data, &unsealed_data_size)) != SGX_SUCCESS){
    	print("\nTrustedApp: sgx_unseal_data() failed !\n");
    	goto cleanup;
  	}
	/*Step2: Open Context*/
	if ((ret = sgx_ecc256_open_context(&p_ecc_handle)) != SGX_SUCCESS){
    	print("\nTrustedApp: sgx_ecc256_open_context() failed !\n");
    	goto cleanup;
  	}
	/*Step3: Create dh_key */
	if ((ret = sgx_ecc256_compute_shared_dhkey((sgx_ec256_private_t *)unsealed_data, (sgx_ec256_public_t*) pubkey, &dh_key, p_ecc_handle)) != SGX_SUCCESS){
		print("\nTrustedApp: sgx_ecc256_compute_shared_dhkey() failed !\n");
		goto cleanup;
	}
	/*Step4: Generate SMK, SK, MK, VK */
	if ((ret = derive_key(&dh_key, "SMK", (uint32_t)(sizeof("SMK") - 1), &smkey)) != SGX_SUCCESS){
		print("\nTruestedApp: derive SMK failed !\n");
		goto cleanup;
	}
	if ((ret = derive_key(&dh_key, "SK", (uint32_t)(sizeof("SK") - 1), &skey)) != SGX_SUCCESS){
		print("\nTruestedApp: derive SK failed !\n");
		goto cleanup;
	}
	if ((ret = derive_key(&dh_key, "MK", (uint32_t)(sizeof("MK") - 1), &mkey)) != SGX_SUCCESS){
		print("\nTruestedApp: derive MK failed !\n");
		goto cleanup;
	}
	if ((ret = derive_key(&dh_key, "VK", (uint32_t)(sizeof("VK") - 1), &vkey)) != SGX_SUCCESS){
		print("\nTrustedApp: derive VK failed !\n");
		goto cleanup;
	}
	/*Step5: Sealed SK */
	if (Sk_sealed_size >= sgx_calc_sealed_data_size(0U, sizeof(skey))){
    	if ((ret = sgx_seal_data(0U, NULL, sizeof(skey), (uint8_t *)&skey, (uint32_t) Sk_sealed_size, (sgx_sealed_data_t *)Sk_sealed)) != SGX_SUCCESS)
    	{
      		print("\nTrustedApp: sgx_seal_data() failed !\n");
      		goto cleanup;
    	}
  	}else{
    	print("\nTrustedApp: Size allocated for sealedprivkey by untrusted app is less than the required size !\n");
    	ret = SGX_ERROR_INVALID_PARAMETER;
    	goto cleanup;
  	}
	print("\nTrustedApp: dnkey was computed and SK was sealed.\n");
  	ret = SGX_SUCCESS;

cleanup:
	/*Step6: Close handle and release the memory */
	if (p_ecc_handle != NULL){
    	sgx_ecc256_close_context(p_ecc_handle);
  	}
	if (unsealed_data != NULL){
    	memset_s(unsealed_data, unsealed_data_size, 0, unsealed_data_size);
    	free(unsealed_data);
  	}
  	return ret;
}

extern "C" sgx_status_t ecall_unseal_SK(char *SK_key, uint32_t SK_key_size, char *sealed, size_t sealed_size){
	/*Step1: Unsealed the SK */
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	uint32_t unsealed_data_size = sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)sealed);
	if (SK_key_size != unsealed_data_size){
		print("\nTrustedApp: wrong unsealed size!\n");
		goto cleanup;
	}
	if ((ret = sgx_unseal_data((sgx_sealed_data_t *)sealed, NULL, NULL, (uint8_t*) SK_key, &SK_key_size)) != SGX_SUCCESS){
    	print("\nTrustedApp: sgx_unseal_data() failed !\n");
    	goto cleanup;
  	}
	print("\nTrustedApp: Unsealed SK Successfully! \n");
	ret = SGX_SUCCESS;
cleanup:
	return ret;
}

extern "C" sgx_status_t new_enclave_init(char *sealed, size_t sealed_size){
	/*Step1: Unsealed the SK */
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	uint32_t unsealed_data_size = sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)sealed);
	uint8_t * const unsealed_data = (uint8_t *)malloc(unsealed_data_size); // Check malloc return;
	if (unsealed_data_size != sizeof(sgx_ec_key_128bit_t)){
		print("\nTrustedApp: wrong unsealed size!\n");
		goto cleanup;
	}
	if ((ret = sgx_unseal_data((sgx_sealed_data_t *)sealed, NULL, NULL, (uint8_t*) unsealed_data, &unsealed_data_size)) != SGX_SUCCESS){
    	print("\nTrustedApp: sgx_unseal_data() failed !\n");
    	goto cleanup;
  	}
	memcpy((uint8_t *)&g_session.shared_key, unsealed_data, unsealed_data_size);
	/*Copy the key into global varibale */
	ret = SGX_SUCCESS;
cleanup:
	if (unsealed_data != NULL){
    	memset_s(unsealed_data, unsealed_data_size, 0, unsealed_data_size);
    	free(unsealed_data);
  	}
	return ret;
}