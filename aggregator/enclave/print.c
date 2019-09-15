#include "enclave.h"
#include "enclave_t.h"

void print(const char * const str){
  ocall_print_string(str);
}