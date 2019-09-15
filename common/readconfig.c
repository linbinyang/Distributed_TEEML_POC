#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include "readconfig.h"

static void *config_text = NULL;

static void handle_error(const char *file, int line, const char *fmt, ...)
{
	va_list ap;

	fprintf(stderr, "%s:%d ", file, line);

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

static void debug_echo(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

#define fail(fmt, ...) do {					\
	handle_error(__FILE__, __LINE__, fmt, ##__VA_ARGS__);	\
	return 1;						\
}while(0)

#define safe_free	free
static void *safe_zalloc(size_t sz)
{
	void *ret = malloc(sz);
	if (!ret) {
		debug_echo("Cannot allocate memory size = %ld\n", sz);
		exit(1);
	}
	memset(ret, 0, sz);
	return ret;
}

static char *trim(char *start, char *end)
{
	if (*end) {
		debug_echo("Invalid string\n");
		exit(1);
	}
	
	while (isspace(*start)) {
		++start;
	}
	
	for (--end; end > start && isspace(*end); --end) {*end = 0;}
	return start;
}

static int setconfig(void *config, config_info_t *info, int ninfo, const char *k, const char *v)
{
	int i;
	char *end;
	long val;
	double val_d;
	//debug_echo("Key: '%s'\nValue: [%s]\n", k, v);
	for (i = 0; i < ninfo; ++i) {
		if (!strcmp(info[i].name, k)) {
			//strcmp denotes that the two strings are equal
			void *member = &((char *)config)[info[i].offset];
			++info[i].optional;
			switch(info[i].type) {
			case TYPE_BOOL:
				break;
			case TYPE_INT:
				val = strtol(v, &end, 10);
				if (end == v || *end) {
					fail("Garbage char.\n");
				}
				if (info[i].type == TYPE_BOOL && val != 0 && val != 1) {
					fail("Value is not bool.\n");
				}
				*(int*)member = val;
				break;
			case TYPE_STRING:
				*(char **)member = (char *)v;
				break;
			case TYPE_DOUBLE:
				val_d = strtod(v, &end);
				//get the floating point number from the string
				if (*end){
					fail("Garbage char.\n");
				}
				*(double*)member = val_d;
				break;
			default:
				fail("Unknown config type %s.\n", k);
			}
		//	printf("%s\n",info[i].name);
			return 0;
		}
	}
	fail("Unknonw config %s\n", k);
}

int parse_config(const char *path, void *config, config_info_t *info, int ninfo)
{
	FILE *fp = fopen(path, "rb");
	char *text, *p, *sol, *eq, *k, *v, *ms, *me;
	int len, i;
	if (!fp) {
		fail("Cannot open config file: %s\n", path);
	}
	/*
		calculate the size of the config file
	*/
	fseek(fp, 0, SEEK_END);
	len = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	if (len > 1024*1024) {
		fail("Config file too big: %s\n", path);
	}
	text = (char *)safe_zalloc(len+1);
	cleanup_config();
	config_text = text;
	if (1 != fread(text, len, 1, fp)) {
		fail("Cannot read config file: %s\n", path);
	}
	fclose(fp);
	p = text;
	sol = p;
	while (p - text < len) {
		while (*p && *p != '\n') {++p;}
		for (eq = sol; eq < p && *eq != '#'; ++eq) {
			if (!isspace(*eq)) {
				break;
			}
		}
		if (*eq != '#') {
			for (eq = sol; eq < p && *eq != '='; ++eq) {}
			if (*eq == '=') {
				*eq = 0;
				k = trim(sol, eq);
				for (v = eq+1; isspace(*v); ++v) {}
				if (v[0] == '\'' && v[1] == '\'' && v[2] == '\'') {
					/* Multiline */
					ms = &v[3];
					v = ms;
					me = NULL;
					while (*v) {
						if (v[0] == '\'' && v[1] == '\'' && v[2] == '\'') {
							me = v;
							break;
						} else {
							++v;
						}
					}
					if (!me) {
						fail("Multiline quote has no end.\n");
					}
					p = me + 3;
					while (*p && *p != '\n') {
						if (isspace(*p)) {
							++p;
						} else {
							fail("Garbage char.\n");
						}
					}
					v = ms;
					*me = 0;
				} else {
					*p = 0;
					v = trim(eq+1, p);
				}
				printf("Key=%s\tvalue=%s\n",k, v);
				if (setconfig(config, info, ninfo, k, v)) {
					return 1;
				}
	//			if (!strcmp(k, "verbose")){
	//				printf("%d\n",config.verbose);
	//			}
			} else {
				*p = 0;
				if (strlen(trim(sol, p)) > 0) {
					fail("Cannot parse line: %s\n", sol);
				}
			}
		}
		++p;
		sol = p;
	}
	for (i = 0; i < ninfo; ++i) {
		if (0 == info[i].optional) {
			fail("Config %s not set.\n", info[i].name);
		}
	}
	return 0;
}

void cleanup_config()
{
	if (config_text) {
		free(config_text);
		config_text = NULL;
	}
}
