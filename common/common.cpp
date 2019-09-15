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

using namespace std;


#include <time.h>
#include <stdio.h>
#include <stdarg.h>
#include <cstdio>
#include <string.h>
#include <string>
#include "common.h"

#define LINE_TYPE '-'
#define LINE_SHORT_LEN 4
#define LINE_MAX_LEN   76
#define LINE_TRAILING_LEN(header) ((LINE_MAX_LEN - string(header).size()) - LINE_SHORT_LEN -2)

#define LINE_COMPLETE (string( LINE_MAX_LEN, LINE_TYPE).c_str())

#define LINE_HEADER(header) (string(string( LINE_SHORT_LEN, LINE_TYPE) + ' ' + string(header) + ' ' + string(LINE_TRAILING_LEN(header), LINE_TYPE)).c_str())

#define INDENT(level) (string( level, ' ' ))

#define WARNING_INDENT(level) (string(level, '*'))

#define TIMESTR_SIZE	64

static void dividerWithText (FILE *fd, const char *text)
{
	fprintf(fd, "\n%s\n", LINE_HEADER(text));
}

void edividerWithText (const char *text)
{
	dividerWithText(stderr, text);
//	if ( fplog != NULL ) dividerWithText(fplog, text);
}

static void divider (FILE * fd)
{
	fprintf(fd, "%s\n", LINE_COMPLETE);
}

void edivider ()
{
	divider(stderr);
//	if ( fplog != NULL ) divider(fplog);
}

int eprintf (const char *format, ...)
{
	va_list va;
	int rv;

	va_start(va, format);
	rv= vfprintf(stderr, format, va);
	va_end(va);
#if 0
	if ( fplog != NULL ) {
		time_t ts;
		struct tm timetm;
		char timestr[TIMESTR_SIZE];	

		/* Don't timestamp a single "\n" */
		if ( !(strlen(format) == 1 && format[0] == '\n') ) {
			time(&ts);
			timetm= *localtime(&ts);

			/* If you change this format, you _may_ need to change TIMESTR_SIZE */
			if ( strftime(timestr, TIMESTR_SIZE, "%b %e %Y %T", &timetm) == 0 ) {
				/* oops */
				timestr[0]= 0;
			}
			fprintf(fplog, "%s ", timestr);
		}
		va_start(va, format);
		rv= vfprintf(fplog, format, va);
		va_end(va);
	}
#endif
	return rv;
}

int eputs (const char *s)
{
//	if ( fplog != NULL ) fputs(s, fplog);
	return fputs(s, stderr);
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
