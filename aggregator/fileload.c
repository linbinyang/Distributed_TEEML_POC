#include "fileload.h"

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
    if (*buffer == NULL){
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
    if (file != NULL){
        fclose(file);
    }

    return ret_status;
}
