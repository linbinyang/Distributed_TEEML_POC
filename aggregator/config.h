#if !defined(CONFIG_H)
#define CONFIG_H

#include <sgx_uae_service.h>
#include <sgx_ukey_exchange.h>

#define MODE_ATTEST 0x0
#define MODE_EPID 	0x1
#define MODE_QUOTE	0x2

#define OPT_PSE		0x01
#define OPT_NONCE	0x02
#define OPT_LINK	0x04

/* Macros to set, clear, and get the mode and options */

#define SET_OPT(x,y)	x|=y
#define CLEAR_OPT(x,y)	x=x&~y
#define OPT_ISSET(x,y)	x&y

typedef struct config_struct {
	char mode;
	void *local_db;
	int local_entries;
	int local_dims;
	char opt_enclave_path[256];
	char opt_statefile[256];
	char opt_signature_file[256];
	char opt_input_file[256];
	char opt_public_key_file[256];
	char opt_sealed_SKfile_path[256];
	char nodelist[256];
	int node_num;
	int n_clusters; //for kmeans
	int max_iters;
	int data_dims;
	int data_rows;
	double lambda;
	double learning_rate;
	char *model;
} config_t;

typedef struct reply_struct {
	int n_clusters;
	int max_iters;
	int data_dims;
	int data_rows;
	double lambda;
	double learning_rate;
	char *model;
} reply_t;

#endif
