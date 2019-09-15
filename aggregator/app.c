#include <stdio.h>
#include <stdlib.h>

#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include "app.h"

/**
 * Macros for little to big endian conversion.
 * One example for its use is for byte endianness conversion for an
 * OpenSSL-based application which uses big endian format, whereas,
 * Intel(r) SGX uses little endian format.
 */

#if !defined(SWAP_ENDIAN_DW)
#define SWAP_ENDIAN_DW(dw) ((((dw)&0x000000ff) << 24) | (((dw)&0x0000ff00) << 8) | (((dw)&0x00ff0000) >> 8) | (((dw)&0xff000000) >> 24))
#endif

#if !defined(SWAP_ENDIAN_32B)
#define SWAP_ENDIAN_8X32B(ptr)                                           \
    {                                                                    \
        uint32_t temp = 0;                                               \
        temp = SWAP_ENDIAN_DW(((uint32_t *)(ptr))[0]);                   \
        ((uint32_t *)(ptr))[0] = SWAP_ENDIAN_DW(((uint32_t *)(ptr))[7]); \
        ((uint32_t *)(ptr))[7] = temp;                                   \
        temp = SWAP_ENDIAN_DW(((uint32_t *)(ptr))[1]);                   \
        ((uint32_t *)(ptr))[1] = SWAP_ENDIAN_DW(((uint32_t *)(ptr))[6]); \
        ((uint32_t *)(ptr))[6] = temp;                                   \
        temp = SWAP_ENDIAN_DW(((uint32_t *)(ptr))[2]);                   \
        ((uint32_t *)(ptr))[2] = SWAP_ENDIAN_DW(((uint32_t *)(ptr))[5]); \
        ((uint32_t *)(ptr))[5] = temp;                                   \
        temp = SWAP_ENDIAN_DW(((uint32_t *)(ptr))[3]);                   \
        ((uint32_t *)(ptr))[3] = SWAP_ENDIAN_DW(((uint32_t *)(ptr))[4]); \
        ((uint32_t *)(ptr))[4] = temp;                                   \
    }
#endif

BIGNUM* bignum_from_little_endian_bytes_32(const uint8_t * const bytes){
    /* Create BIGNUM from raw (little endian) bytes
       without using memcpy (static scanner requirement) */
    uint8_t copied_bytes[32];
    for (size_t i = 0 ; i < sizeof(copied_bytes) ; ++i){
        copied_bytes[i] = bytes[i];
    }
    SWAP_ENDIAN_8X32B(copied_bytes);
    BIGNUM * bn = BN_bin2bn(copied_bytes, sizeof(copied_bytes), NULL);
    return bn;
}

bool allocate_buffers(){
    printf("[GatewayApp]: Allocating buffers\n");
    sealed_data_buffer = calloc(sealed_data_buffer_size, 1);
    public_key_buffer = calloc(public_key_buffer_size, 1);
    signature_buffer = calloc(signature_buffer_size, 1);
    if (sealed_data_buffer == NULL || public_key_buffer == NULL || signature_buffer == NULL){
        fprintf(stderr, "[GatewayApp]: allocate_buffers() memory allocation failure\n");
        sgx_lasterr = SGX_ERROR_UNEXPECTED;
    }
    return (sgx_lasterr == SGX_SUCCESS);
}

void cleanup_buffers(){
    printf("[GatewayApp]: Deallocating buffers\n");
    if (sealed_data_buffer != NULL)
    {
        free(sealed_data_buffer);
        sealed_data_buffer = NULL;
    }
    if (public_key_buffer != NULL)
    {
        free(public_key_buffer);
        public_key_buffer = NULL;
    }
    if (signature_buffer != NULL)
    {
        free(signature_buffer);
        signature_buffer = NULL;
    }
    if (input_buffer != NULL){
        free(input_buffer);
        input_buffer = NULL;
    }
}

const char* decode_sgx_status(sgx_status_t status){
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];
    for (size_t idx = 0; idx < ttl; idx++) {
        if(status == sgx_errlist[idx].err) {
            return sgx_errlist[idx].msg;
        }
    }
    return "Unexpected error parsing SGX return status";
}

bool enclave_get_buffer_sizes(){
    sgx_status_t ecall_retval = SGX_SUCCESS;
    printf("[GatewayApp]: Querying enclave for buffer sizes\n");
    /*
    * Invoke ECALL, 'ecall_calc_buffer_sizes()', to calculate the sizes of buffers needed for the untrusted app to store
    * data (public key, sealed private key and signature) from the enclave.
    */
    printf("[GatewayApp]: enclave_id_test:%lu\n", enclave_id_test);
    sgx_lasterr = ecall_calc_buffer_sizes(enclave_id_test,
                                                   &ecall_retval,
                                                   &public_key_buffer_size,
                                                   &sealed_data_buffer_size,
                                                   &signature_buffer_size);
    printf("[GatewayApp]: public_key_buffer_size: %lu\n", public_key_buffer_size);
    printf("[GatewayApp]: sealed_data_buffer_size: %lu\n", sealed_data_buffer_size);
    printf("[GatewayApp]: signature_buffer_size: %lu\n", signature_buffer_size);
    if (sgx_lasterr == SGX_SUCCESS && (ecall_retval != 0)){
        fprintf(stderr, "[GatewayApp]: ERROR: ecall_calc_buffer_sizes returned %d\n", ecall_retval);
        sgx_lasterr = SGX_ERROR_UNEXPECTED;
    }
    return (sgx_lasterr == SGX_SUCCESS);
}

bool load_enclave_state(const char *const statefile){
    void* new_buffer;
    size_t new_buffer_size;
    printf("[GatewayApp]: Loading enclave state\n");
    bool ret_status = read_file_into_memory(statefile, &new_buffer, &new_buffer_size);
    /* If we previously allocated a buffer, free it before putting new one in its place */
    // free memory to avoid memory leak
    if (sealed_data_buffer != NULL){
        free(sealed_data_buffer);
        sealed_data_buffer = NULL;
    }
    /* Put new buffer into context */
    sealed_data_buffer = new_buffer;
    sealed_data_buffer_size = new_buffer_size;
    return ret_status;
}

bool save_enclave_state(const char *const statefile){
    bool ret_status = true;
    printf("[GatewayApp]: Saving enclave state\n");
    FILE *file = open_file(statefile, "wb");
    if (file == NULL){
        fprintf(stderr, "[GatewayApp]: save_enclave_state() fopen failed\n");
        sgx_lasterr = SGX_ERROR_UNEXPECTED;
        return false;
    }
    if (fwrite(sealed_data_buffer, sealed_data_buffer_size, 1, file) != 1){
        fprintf(stderr, "[GatewayApp]: Enclave state only partially written.\n");
        sgx_lasterr = SGX_ERROR_UNEXPECTED;
        ret_status = false;
    }
    fclose(file);
    return ret_status;
}

bool create_enclave(const char *const enclave_binary){
    printf("[GatewayApp]: Creating enclave\n");

    /* 
       SGX_DEBUG_FLAG is a macro set in sgx_urts.h to enable debugging when
       building in debug and pre-release mode.  In common/common.mk
       this mode is controlled by SGX_DEBUG and SGX_PRERELEASE.
       Setting either to 1 will set SGX_DEBUG_FLAG to 1 (true).
    */

    sgx_lasterr = sgx_create_enclave(enclave_binary,
                                              SGX_DEBUG_FLAG,
                                              &launch_token,
                                              &launch_token_updated,
                                              &enclave_id_test,
                                              NULL);
    printf("[GatewayApp]: enclave_id_test:%lu\n", enclave_id_test);
    return (sgx_lasterr == SGX_SUCCESS);
}

void destroy_enclave(){
    printf("[GatewayApp]: Destroying enclave\n");
    sgx_status_t err = sgx_destroy_enclave(enclave_id_test);
    if (err != SGX_SUCCESS){
        fprintf(stderr, "[GatewayApp]: ERROR: %s\n", decode_sgx_status(err));
        return;
    }
    enclave_id_test = 0;
}

bool enclave_generate_key(){
    sgx_status_t ecall_retval = SGX_ERROR_UNEXPECTED;
    printf("[GatewayApp]: Calling enclave to generate key material\n");
    /*
    * Invoke ECALL, 'ecall_key_gen_and_seal()', to generate a keypair and seal it to the enclave.
    */
    printf("current sealed_data_buffer: %lu\n", sealed_data_buffer_size);
    sgx_lasterr = ecall_key_gen_and_seal(enclave_id_test,
                                         &ecall_retval,
                                         (char *)public_key_buffer,
                                         public_key_buffer_size,
                                         (char *)sealed_data_buffer,
                                         sealed_data_buffer_size);
    if (sgx_lasterr == SGX_SUCCESS && (ecall_retval != SGX_SUCCESS)){
        fprintf(stderr, "[GatewayApp]: ERROR: ecall_key_gen_and_seal returned %d\n", ecall_retval);
        sgx_lasterr = SGX_ERROR_UNEXPECTED;
    }
    return (sgx_lasterr == SGX_SUCCESS);
}

static bool convert_sgx_key_to_openssl_key(EC_KEY *key, const uint8_t *key_buffer, size_t key_buffer_size){
    bool ret_status = true;
    if (key_buffer_size != 64)
    {
        fprintf(stderr, "[GatewayApp]: assertion failed: key_buffer_size == 64\n");
        return false;
    }
    BIGNUM *bn_x = bignum_from_little_endian_bytes_32(key_buffer);
    BIGNUM *bn_y = bignum_from_little_endian_bytes_32(key_buffer + 32);
    if (1 != EC_KEY_set_public_key_affine_coordinates(key, bn_x, bn_y))
    {
        fprintf(stderr, "[GatewayApp]: Failed to convert public key to OpenSSL format\n");
        ret_status = false;
    }
    BN_free(bn_x);
    BN_free(bn_y);
    return ret_status;
}

bool save_public_key(const char *const public_key_file){
    bool ret_status = true;
    printf("[GatewayApp]: Saving public key\n");
    FILE *file = open_file(public_key_file, "wt");
    if (file == NULL){
        fprintf(stderr, "[GatewayApp]: save_public_key() fopen failed\n");
        sgx_lasterr = SGX_ERROR_UNEXPECTED;
        return false;
    }
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_set_asn1_flag(key, OPENSSL_EC_NAMED_CURVE);
    /*
        Convert the sgx public key in openssh format
    */
    if (convert_sgx_key_to_openssl_key(key, (uint8_t *)public_key_buffer, public_key_buffer_size)){
        PEM_write_EC_PUBKEY(file, key);
    }else{
        fprintf(stderr, "[GatewayApp]: Failed export public key\n");
        ret_status = false;
    }
    EC_KEY_free(key);
    key = NULL;
    fclose(file);
    return ret_status;
}

void ocall_print_string(const char *str){
  /* Proxy/Bridge will check the length and null-terminate
   * the input string to prevent buffer overflow.
   */
  printf("%s", str);
}

bool load_input_file(const char *const input_file){
    printf("[GatewayApp]: Loading input file\n");
    printf("%s\n", input_file);
    return read_file_into_memory(input_file, &input_buffer, &input_buffer_size);
}

bool enclave_sign_data(){
    sgx_status_t ecall_retval = SGX_ERROR_UNEXPECTED;
    printf("[GatewayApp]: Calling enclave to generate key material\n");
    /*
    * Invoke ECALL, 'ecall_unseal_and_sign()', to sign some data with the sealed key
    */
    sgx_lasterr = ecall_unseal_and_sign(enclave_id_test,
                                        &ecall_retval,
                                        (uint8_t *)input_buffer,
                                        (uint32_t)input_buffer_size,
                                        (char *)sealed_data_buffer,
                                        sealed_data_buffer_size,
                                        (char *)signature_buffer,
                                        signature_buffer_size);
    if (sgx_lasterr == SGX_SUCCESS && (ecall_retval != 0)){
        fprintf(stderr, "[GatewayApp]: ERROR: ecall_unseal_and_sign returned %d\n", ecall_retval);
        sgx_lasterr = SGX_ERROR_UNEXPECTED;
    }
    return (sgx_lasterr == SGX_SUCCESS);
}

bool save_signature(const char *const signature_file){
    bool ret_status = true;
    ECDSA_SIG *ecdsa_sig = NULL;
    FILE *file = NULL;
    unsigned char *sig_buffer = NULL;
    int sig_len = 0;
    int sig_len2 = 0;

    if (signature_buffer_size != 64)
    {
        fprintf(stderr, "[GatewayApp]: assertion failed: signature_buffer_size == 64\n");
        ret_status = false;
        goto cleanup;
    }

    ecdsa_sig = ECDSA_SIG_new();
    if (ecdsa_sig == NULL)
    {
        fprintf(stderr, "[GatewayApp]: memory alloction failure ecdsa_sig\n");
        ret_status = false;
        goto cleanup;
    }
    ecdsa_sig->r = bignum_from_little_endian_bytes_32((unsigned char *)signature_buffer);
    ecdsa_sig->s = bignum_from_little_endian_bytes_32((unsigned char *)signature_buffer + 32);

    sig_len = i2d_ECDSA_SIG(ecdsa_sig, NULL);
    if (sig_len <= 0)
    {
        ret_status = false;
        goto cleanup;
    }

    sig_len2 = i2d_ECDSA_SIG(ecdsa_sig, &sig_buffer);
    if (sig_len != sig_len2)
    {
        ret_status = false;
        goto cleanup;
    }

    file = open_file(signature_file, "wb");
    if (file == NULL){
        fprintf(stderr, "[GatewayApp]: save_signature() fopen failed\n");
        sgx_lasterr = SGX_ERROR_UNEXPECTED;
        ret_status = false;
        goto cleanup;
    }

    if (fwrite(sig_buffer, (size_t)sig_len, 1, file) != 1){
        fprintf(stderr, "GatewayApp]: ERROR: Could not write signature\n");
        sgx_lasterr = SGX_ERROR_UNEXPECTED;
        ret_status = false;
        goto cleanup;
    }

cleanup:
    if (file != NULL)
    {
        fclose(file);
    }
    if (ecdsa_sig)
    {
        ECDSA_SIG_free(ecdsa_sig); /* Above will also free r and s */
    }
    if (sig_buffer)
    {
        free(sig_buffer);
    }

    return ret_status;
}