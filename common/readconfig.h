#if !defined(READCONFIG_H)
#define READCONFIG_H

#define OFFSET_OF(t, m)	((int)(long)(&((t*)0)->m))

enum field_type {
	TYPE_BOOL,
	TYPE_INT,
	TYPE_STRING,
	TYPE_DOUBLE
};

typedef struct {
	const char *name;
	enum field_type type;
	int offset;
	int optional;
} config_info_t;

#define CONFIG_ENTRY(ctype, name, type, optional)	{#name, type, OFFSET_OF(ctype, name), optional}


#ifdef __cplusplus
extern "C" {
#endif

int parse_config(const char *path, void *config, config_info_t *info, int ninfo);
void cleanup_config();

#ifdef __cplusplus
}
#endif

#endif
