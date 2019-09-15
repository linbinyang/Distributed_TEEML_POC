#ifndef FILELOAD_H
#define FILELOAD_H

#include <stdbool.h>
#include <string.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

FILE* open_file(const char* const filename, const char* const mode);
bool read_file_into_memory(const char *const filename, void **buffer, size_t *buffer_size);

#endif