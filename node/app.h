#ifndef _APP_H
#define _APP_H

#include <sys/types.h>
#include <stdbool.h>
#include <sgx_error.h>
#include <sgx_urts.h>
#include "Enclave_u.h"
#include <openssl/bn.h>
#include <limits.h>
#include <string.h>

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char * msg;
} sgx_errlist_t;

static sgx_errlist_t sgx_errlist[] = {
    {SGX_ERROR_UNEXPECTED,               "Unexpected error occurred."},
    {SGX_ERROR_INVALID_PARAMETER,        "Invalid parameter."},
    {SGX_ERROR_OUT_OF_MEMORY,            "Out of memory."},
    {SGX_ERROR_ENCLAVE_LOST,             "Power transition occurred."},
    {SGX_ERROR_INVALID_ENCLAVE,          "Invalid enclave image."},
    {SGX_ERROR_INVALID_ENCLAVE_ID,       "Invalid enclave identification."},
    {SGX_ERROR_INVALID_SIGNATURE,        "Invalid enclave signature."},
    {SGX_ERROR_OUT_OF_EPC,               "Out of EPC memory."},
    {SGX_ERROR_NO_DEVICE,                "Invalid SGX device."},
    {SGX_ERROR_MEMORY_MAP_CONFLICT,      "Memory map conflicted."},
    {SGX_ERROR_INVALID_METADATA,         "Invalid encalve metadata."},
    {SGX_ERROR_DEVICE_BUSY,              "SGX device is busy."},
    {SGX_ERROR_INVALID_VERSION,          "Enclave metadata version is invalid."},
    {SGX_ERROR_ENCLAVE_FILE_ACCESS,      "Can't open enclave file."},

    {SGX_ERROR_INVALID_FUNCTION,         "Invalid function name."},
    {SGX_ERROR_OUT_OF_TCS,               "Out of TCS."},
    {SGX_ERROR_ENCLAVE_CRASHED,          "The enclave is crashed."},

    {SGX_ERROR_MAC_MISMATCH,             "Report varification error occurred."},
    {SGX_ERROR_INVALID_ATTRIBUTE,        "The enclave is not authorized."},
    {SGX_ERROR_INVALID_CPUSVN,           "Invalid CPUSVN."},
    {SGX_ERROR_INVALID_ISVSVN,           "Invalid ISVSVN."},
    {SGX_ERROR_INVALID_KEYNAME,          "The requested key name is invalid."},

    {SGX_ERROR_SERVICE_UNAVAILABLE,          "AESM service is not responsive."},
    {SGX_ERROR_SERVICE_TIMEOUT,              "Request to AESM is time out."},
    {SGX_ERROR_SERVICE_INVALID_PRIVILEGE,    "Error occurred while getting launch token."},

    /* NRI Added: */
    {SGX_ERROR_AE_INVALID_EPIDBLOB,    "Indicates an Intel(R) EPID blob verification error."}
};

// [down] generate dynamic public key and private key
sgx_enclave_id_t enclave_id_test;
sgx_launch_token_t launch_token;
int launch_token_updated;
sgx_status_t sgx_lasterr;
void *outer_public_key_buffer; /* Used for receive public key from the opposite side */
size_t outer_public_key_buffer_size; /* Used for receive public key from the opposite side */
void *public_key_buffer;       /* unused for signing */
size_t public_key_buffer_size; /* unused for signing */
void *sealed_data_buffer; /* Used for sealed private key */
size_t sealed_data_buffer_size; /* Used for sealed private key */
void *sealed_sk_buffer; /* Used for sealed SK */
size_t sealed_sk_buffer_size; /* Used for sealed SK*/
void *signature_buffer;
size_t signature_buffer_size;
void *input_buffer;
size_t input_buffer_size;

const char* decode_sgx_status(sgx_status_t status);
FILE* open_file(const char* const filename, const char* const mode);
bool create_enclave(const char *const enclave_binary);
bool enclave_get_buffer_sizes(void);
bool allocate_buffers(void);
bool APP_GetPubKey(sgx_ec256_public_t* pub_key);
bool read_file_into_memory(const char *const filename, void **buffer, size_t *buffer_size);
bool load_enclave_state(const char *const statefile);
bool load_sealed_sk(const char *const sealedSK_file);
bool save_sealed_SK(const char *const sealedSK_file);
bool load_input_file(const char *const input_file);
bool enclave_generate_symmetric_key(const char *const statefile);
bool enclave_sign_data(void);
bool enclave_generate_key(void);
bool enclave_init_with_SK(const char *const sealedSK_file);
bool save_enclave_state(const char *const statefile);
size_t decryption(uint8_t* encrypte_inbuf, size_t encrypte_inbuf_size, uint8_t **outbuf);
size_t encryption(uint8_t *inbuf, size_t inbuf_sz, uint8_t **outbuf);
BIGNUM* bignum_from_little_endian_bytes_32(const unsigned char * const bytes);
bool save_signature(const char *const signature_file);
bool save_public_key(const char *const public_key_file);
void destroy_enclave(void);
void cleanup_buffers(void);
// [up] generate dynamic public and private key

#endif