#if !defined(CONFIG_H)
#define CONFIG_H

#include <sgx_key_exchange.h>
#include <sgx_report.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#define SET_OPT(x,y)	x|=y
#define CLEAR_OPT(x,y)	x=x&~y
#define OPT_ISSET(x,y)	x&y

#define OPT_IAS_PROD	0x01
#define OPT_NO_PROXY	0x02

typedef struct config_struct {
	int data_dims;
	int data_rows;
	char data_file_path[1024];
	char opt_enclave_path[256];
	char opt_statefile[256];
	char opt_signature_file[256];
	char opt_input_file[256];
	char opt_public_key_file[256];
	char opt_sealed_SKfile_path[256];
	char server[256];
	char port[50];
} config_t;

#endif
