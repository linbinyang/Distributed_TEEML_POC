#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include "datatype.h"

#define fail(fmt, ...) 	do {				\
	fprintf(stderr, "%s:%d ", __FILE__, __LINE__);	\
	fprintf(stderr, fmt, ##__VA_ARGS__);		\
	assert(0);					\
	exit(1);					\
} while (0)

#define debug_echo(fmt, ...)	fprintf(stderr, fmt, ##__VA_ARGS__)

#define safe_free(p)		do {if(p) free(p);} while (0)

struct buffer {
	char buf[1024];
	char *cur;
	int buflen;
};

struct output {
	DATATYPE *out;
	int n;
	int sz;
};

/* Read the file continuously. Add \n at EOF. */
static int fill_buffer(struct buffer *pbuf, FILE *fp)
{
	int szin = 0;
	int used = pbuf->cur - pbuf->buf;

	if (pbuf->buflen > used) {
		memmove(pbuf->buf, pbuf->cur, pbuf->buflen - used);
	}
	pbuf->buflen -= used;
	pbuf->cur = pbuf->buf;

	int toread = sizeof(pbuf->buf) - pbuf->buflen - 1;	/* 1 is for tailing \0 */

	if (toread <= 0 || toread >= sizeof(pbuf->buf)) {
		fail("fill_buffer: invalid arguments.\n");
	}

	szin = fread(pbuf->buf + pbuf->buflen, 1, toread, fp);
	if (szin > 0) {
		pbuf->buflen += szin;
		pbuf->buf[pbuf->buflen] = 0;	/* Ensure the string is ended. */
	} else if (pbuf->buflen > 0) {
		/* Still something in the buffer. Add a fake \n. */
		pbuf->cur[pbuf->buflen] = '\n';
		++pbuf->buflen;
		pbuf->cur[pbuf->buflen] = 0;
	}
	return pbuf->buflen > 0;
}

static void append_out(DATATYPE f, struct output *out)
{
	if (out->n >= out->sz) {
		if (out->sz > 1024) {
			out->sz += 1024;
		}else if (out->sz > 0) {
			out->sz *= 2;
		} else {
			out->sz = 100;
		}
		out->out = realloc(out->out, out->sz * sizeof(DATATYPE));
		if (!out->out) {
			fail("Out of memory.\n");
		}
	}
	out->out[out->n++] = f;
}

int read_text(const char *path, DATATYPE **pout, int *dim, int *n)
{
	FILE *fp;
	struct buffer buf;
	struct output out;
	char *p, *q, *eol;
	int d;
	DATATYPE f;

	*n = 0;
	*dim = 0;
	buf.cur = buf.buf;
	buf.buflen = 0;
	out.out = NULL;
	out.n = 0;
	out.sz = 0;

	fp = fopen(path, "r");
	if (!fp) {
		return -1;
	}

	while (fill_buffer(&buf, fp)) {
		for (;;) {
			for (; *buf.cur == '\n' || *buf.cur == '\r'; ++buf.cur) {}
			/* start of a line */
			d = 0;
			for (eol = buf.cur; *eol != '\n' && *eol != '\r' && *eol != 0; ++eol) {}
			if (*eol == 0) {
				/* Incomplete line. Read more. */
				break;
			}
			for (p = buf.cur; p < eol; ) {
				for (; *p == ' ' || *p == '\t'; ++p) {}
				f = (DATATYPE)strtod(p, &q);
				if (p == q) {
					debug_echo("garbage byte: %02x\n", *p);
					++p;
					continue;
				}
				append_out(f, &out);
				++d;
				p = q;
			}
			if (*dim == 0) {
				*dim = d;
			} else if (*dim != d) {
				fclose(fp);
				safe_free(out.out);
				fail("Different dimension: %d %d\n", *dim, d);
			}
			++*n;
			buf.cur = eol;
		}
	}

	fclose(fp);

	*pout = realloc(out.out, out.n * sizeof(DATATYPE));
	if (!*pout) {
		fail("Cannot allocate memory.\n");
	}

	return 0;
}

int read_binary(const char *path, DATATYPE **pout, int *dim, int *n)
{
	FILE *fp;
	size_t sz;
	char header[4];

	fp = fopen(path, "rb");
	if (!fp) {
		fail("Cannot open file %s\n", path);
	}

	if (1 != fread(header, sizeof(header), 1, fp)) {
		fail("Cannot read from file %s\n", path);
	}

	if (!memcmp(header, "DATF", 4) && sizeof(DATATYPE) == sizeof(float)) {
		debug_echo("Reading float.\n");
	} else if (!memcmp(header, "DATD", 4) && sizeof(DATATYPE) == sizeof(double)) {
		debug_echo("Reading double.\n");
	} else {
		fail("Invalid data file.\n");
	}

	if (1 != fread(n, sizeof(*n), 1, fp) || 
	    1 != fread(dim, sizeof(*dim), 1, fp)) {
	    	fail("Cannot read from file %s\n", path);
	}

	sz = (*dim)*(*n)*sizeof(DATATYPE);
	*pout = (DATATYPE *)malloc(sz);
	if (1 != fread(*pout, sz, 1, fp)) {
	    	fail("Cannot read from file %s\n", path);
	}
		
	fclose(fp);
	return 0;
}
