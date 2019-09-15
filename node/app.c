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

BIGNUM* bignum_from_little_endian_bytes_32(const uint8_t * const bytes)
{
    /* Create BIGNUM from raw (little endian) bytes
       without using memcpy (static scanner requirement) */
    uint8_t copied_bytes[32];
    for (size_t i = 0 ; i < sizeof(copied_bytes) ; ++i)
    {
        copied_bytes[i] = bytes[i];
    }

    SWAP_ENDIAN_8X32B(copied_bytes);
    BIGNUM * bn = BN_bin2bn(copied_bytes, sizeof(copied_bytes), NULL);
    return bn;
}

bool APP_GetPubKey(sgx_ec256_public_t* pub_key){
    /*Copy the public key received*/
    if (outer_public_key_buffer == NULL){
        fprintf(stderr, "You should first allocate size and memory!\n");
        return false;
    }
    memset(outer_public_key_buffer, 0, outer_public_key_buffer_size);
    memcpy(outer_public_key_buffer, pub_key, outer_public_key_buffer_size);
    printf("Successed in copy the contents of pubKey\n");
    return true;
}

bool allocate_buffers(){
    printf("[GatewayApp]: Allocating buffers\n");
    outer_public_key_buffer = calloc(outer_public_key_buffer_size, 1);
    sealed_sk_buffer = calloc(sealed_sk_buffer_size, 1);
    sealed_data_buffer = calloc(sealed_data_buffer_size, 1);
    public_key_buffer = calloc(public_key_buffer_size, 1);
    signature_buffer = calloc(signature_buffer_size, 1);
    if (sealed_data_buffer == NULL || public_key_buffer == NULL || signature_buffer == NULL || sealed_sk_buffer == NULL || outer_public_key_buffer == NULL){
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
    if (sealed_sk_buffer != NULL){
        free(sealed_sk_buffer);
        sealed_sk_buffer = NULL;
    }
    if (outer_public_key_buffer != NULL){
        free(outer_public_key_buffer);
        outer_public_key_buffer = NULL;
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

    printf("enclave_id_test:%lu\n", enclave_id_test);
    sgx_lasterr = ecall_calc_buffer_sizes(enclave_id_test,
                                                   &ecall_retval,
                                                   &public_key_buffer_size,
                                                   &sealed_data_buffer_size,
                                                   &signature_buffer_size,
                                                   &sealed_sk_buffer_size,
                                                   &outer_public_key_buffer_size);
    printf("public_key_buffer_size: %lu\n",public_key_buffer_size);
    printf("sealed_data_buffer_size: %lu\n",sealed_data_buffer_size);
    printf("signature_buffer_size: %lu\n",signature_buffer_size);
    printf("sealed_sk_buffer_size: %lu\n", sealed_sk_buffer_size);
    printf("outer_public_key_buffer_size: %lu\n", outer_public_key_buffer_size);
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

bool load_sealed_sk(const char *const sealedSK_file){
    void* new_buffer;
    size_t new_buffer_size;
    printf("[GatewayApp]: Load sealed SK into memory\n");
    bool ret_status = read_file_into_memory(sealedSK_file, &new_buffer, &new_buffer_size);
    /* If we previously allocated a buffer, free it before putting new one in its place */
    // free memory to avoid memory leak
    if (sealed_sk_buffer != NULL){
        free(sealed_sk_buffer);
        sealed_sk_buffer = NULL;
    }
    /* Put new buffer into context */
    sealed_sk_buffer = new_buffer;
    sealed_sk_buffer_size = new_buffer_size;
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

bool save_sealed_SK(const char *const sealedSK_file){
    bool ret_status = true;
    printf("[GatewayApp]: Saving SK state\n");
    FILE *file = open_file(sealedSK_file, "wb");
    if (file == NULL){
        fprintf(stderr, "[GatewayApp]: save_sealed_SK() fopen failed\n");
        sgx_lasterr = SGX_ERROR_UNEXPECTED;
        return false;
    }//end if
    if (fwrite(sealed_sk_buffer, sealed_sk_buffer_size, 1, file) != 1){
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
    printf("enclave_id_test:%d\n", enclave_id_test);
    if (sgx_lasterr == SGX_ERROR_ENCLAVE_FILE_ACCESS){
        printf("Do you forget to set the LD_LIBRARY_PATH?\n");
    }
    return (sgx_lasterr == SGX_SUCCESS);
}

void destroy_enclave(){
    printf("[GatewayApp]: Destroying enclave\n");
    sgx_status_t err = sgx_destroy_enclave(enclave_id_test);
    if (err != SGX_SUCCESS)
    {
        fprintf(stderr, "[GatewayApp]: ERROR: %s\n", decode_sgx_status(err));
        return;
    }
    enclave_id_test = 0;
}

bool enclave_generate_symmetric_key(const char *const statefile){
    bool ret_status = true;
    sgx_status_t ecall_retval = SGX_ERROR_UNEXPECTED;
    printf("[GatewayApp]: Call enclave to generate symmetric key\n");
    /* Step1: ensure that the sealed private key has been already loaded into memory */
    printf("[GatewayApp]: Get Sealed Private Key\n");
    if (!(ret_status = load_enclave_state(statefile))){
        fprintf(stderr, "[GatewayApp]: Failed to load the sealed private.\n");
        sgx_lasterr = SGX_ERROR_UNEXPECTED;
        return false;
    }
    /* Step2: Invoke ECALL, 'ecall_unseal_and_generate_SK', to generate one symmetric key (SK) for aggregator and clients */
    sgx_lasterr = ecall_unseal_and_generate_SK(enclave_id_test,
                                               &ecall_retval,
                                               (char *)outer_public_key_buffer,
                                               outer_public_key_buffer_size,
                                               (char *)sealed_data_buffer,
                                               sealed_data_buffer_size,
                                               (char *)sealed_sk_buffer,
                                               sealed_sk_buffer_size);
    if (sgx_lasterr == SGX_SUCCESS && (ecall_retval != SGX_SUCCESS)){
        fprintf(stderr, "[GatewayApp]: ERROR: ecall_unseal_and_generate_SK returned %d\n", ecall_retval);
        sgx_lasterr = SGX_ERROR_UNEXPECTED;
    }
    return (sgx_lasterr == SGX_SUCCESS);   
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

    if (key_buffer_size != 64){
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
    }
    else
    {
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

FILE* open_file(const char* const filename, const char* const mode){
    return fopen(filename, mode);
}

bool read_file_into_memory(const char *const filename, void **buffer, size_t *buffer_size){
    bool ret_status = true;
    FILE *file = NULL;
    long file_len = 0L;

    if (buffer == NULL || buffer_size == NULL){
        fprintf(stderr, "[GatewayApp]: read_file_into_memory() invalid parameter\n");
        ret_status = false;
        goto cleanup;
    }

    /* Read sensor data from file */
    file = open_file(filename, "rb");
    if (file == NULL){
        fprintf(stderr, "[GatewayApp]: read_file_into_memory() fopen failed\n");
        ret_status = false;
        goto cleanup;
    }

    fseek(file, 0, SEEK_END);
    file_len = ftell(file);
    if (file_len < 0 || file_len > INT_MAX){
        fprintf(stderr, "[GatewayApp]: Invalid input file size\n");
        ret_status = false;
        goto cleanup;
    }

    *buffer_size = (size_t)file_len;
    *buffer = malloc(*buffer_size);
    if (*buffer == NULL)
    {
        fprintf(stderr, "[GatewayApp]: read_file_into_memory() memory allocation failed\n");
        ret_status = false;
        goto cleanup;
    }
    fseek(file, 0, SEEK_SET);
    if (fread(*buffer, *buffer_size, 1, file) != 1){
        fprintf(stderr, "[GatewayApp]: Input file only partially read.\n");
        ret_status = false;
        goto cleanup;
    }

cleanup:
    if (file != NULL)
    {
        fclose(file);
    }

    return ret_status;
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

bool enclave_init_with_SK(const char *const sealedSK_file){
    bool ret_status = true;
    sgx_status_t ecall_retval = SGX_ERROR_UNEXPECTED;
    /* Step1: ensure that the sealed SK has been already loaded into memory */
    printf("[GatewayApp]: Get Sealed Private Key\n");
    if (!(ret_status = load_sealed_sk(sealedSK_file))){
        fprintf(stderr, "[GatewayApp]: Failed to load the sealed SK.\n");
        sgx_lasterr = SGX_ERROR_UNEXPECTED;
        return false;
    }
    /* Step2: Invoke ecall new_enclave_init to initialized the enclave */
    printf("[GatewayApp]: Call enclave_init_with_SK to initialized the state of the enclave\n");
    sgx_lasterr = new_enclave_init(enclave_id_test,
                                   &ecall_retval,
                                   (char *) sealed_sk_buffer,
                                   sealed_sk_buffer_size);
    return sgx_lasterr == SGX_SUCCESS;
}

bool save_signature(const char *const signature_file){
    bool ret_status = true;
    ECDSA_SIG *ecdsa_sig = NULL;
    FILE *file = NULL;
    unsigned char *sig_buffer = NULL;
    int sig_len = 0;
    int sig_len2 = 0;

    if (signature_buffer_size != 64){
        fprintf(stderr, "[GatewayApp]: assertion failed: signature_buffer_size == 64\n");
        ret_status = false;
        goto cleanup;
    }

    ecdsa_sig = ECDSA_SIG_new();
    if (ecdsa_sig == NULL){
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
    if (file != NULL){
        fclose(file);
    }
    if (ecdsa_sig){
        ECDSA_SIG_free(ecdsa_sig); /* Above will also free r and s */
    }
    if (sig_buffer){
        free(sig_buffer);
    }
    return ret_status;
}

/*
    Modify the interface for encryption and decryption
*/

size_t encryption(uint8_t *inbuf, size_t inbuf_sz, uint8_t **outbuf){
    sgx_status_t retval = SGX_ERROR_UNEXPECTED;
	size_t outbuf_size;
	/* -------------------------get encrypted data size ---------------------------*/
	sgx_lasterr = enclave_get_sealed_data_size(enclave_id_test, &retval, inbuf_sz, &outbuf_size);
	if (sgx_lasterr != SGX_SUCCESS || retval != SGX_SUCCESS) {
		printf("failed to call enclave_get_sealed_data_size(), ret is 0x%x\n", sgx_lasterr);
		goto out;
	}
	*outbuf = (uint8_t *)malloc(outbuf_size);
	if (!outbuf)
		goto out;
	memset(*outbuf, 0, outbuf_size);
    /* ----------------------------encrypte data ------------------------------------*/
	sgx_lasterr = enclave_seal_data(enclave_id_test, &retval, inbuf, inbuf_sz, *outbuf, outbuf_size);
	if (sgx_lasterr != SGX_SUCCESS || retval != SGX_SUCCESS) {
		printf("failed to call enclave_seal_data(), ret is 0x%x\n", sgx_lasterr);
		goto out;
	}
    printf("enclave 1 sealed datasize if %lu bytes.\n", outbuf_size);	
	return outbuf_size;
out:
	return 0;
}

size_t decryption(uint8_t* encrypte_inbuf, size_t encrypte_inbuf_size, uint8_t **outbuf){
    sgx_status_t retval = SGX_ERROR_UNEXPECTED;
	size_t outbuf_size;
	/* -------------------------get decrypted data size ---------------------------*/
	sgx_lasterr = enclave_get_unsealed_data_size(enclave_id_test, &retval, encrypte_inbuf, &outbuf_size);
	if (sgx_lasterr != SGX_SUCCESS || retval != SGX_SUCCESS) {
		printf("failed to call enclave_get_sealed_data_size(), ret is 0x%x\n", sgx_lasterr);
		goto out;
	}
	*outbuf = (uint8_t*)malloc(outbuf_size);
	if (!outbuf)
		goto out;
	memset(*outbuf, 0, outbuf_size);
	/* ----------------------------decrypt data ------------------------------------*/
	sgx_lasterr = enclave_unseal_data(enclave_id_test, &retval, *&encrypte_inbuf, encrypte_inbuf_size, *outbuf, outbuf_size);
	if (sgx_lasterr != SGX_SUCCESS || retval != SGX_SUCCESS) {
		printf("failed to call enclave_unseal_data(), ret is 0x%x, retval is 0x%x\n", sgx_lasterr, retval);
		goto out;
	}
    printf("enclave unsealed data if %lu bytes.\n", outbuf_size);	
	return outbuf_size;
out:
	return 0;
}