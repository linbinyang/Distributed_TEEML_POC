#include "Enclave.h"
#include "Enclave_t.h"

void print(const char * const str){
  ocall_print_string(str);
}