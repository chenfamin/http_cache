#ifndef HTTP_MEM_H
#define HTTP_MEM_H

#include "list.h"

#if MEM_POOL
#define http_malloc mem_malloc
#define http_realloc mem_realloc
#define http_free mem_free
#else 
#define http_malloc malloc
#define http_realloc realloc
#define http_free free
#endif

struct string_t {
	size_t size;
	size_t len;
	char *buf;
};

struct buffer_t {
	size_t size;
	size_t len;
	int ref;
	void *buf;
};

struct buffer_node_t {
	struct list_head_t node;
	void *buffer;
};

struct buffer_node_pool_t {
	size_t size;
	struct list_head_t list;
};

struct buffer_list_t {
	struct list_head_t list;
};

void mem_pools_init();
void mem_pools_destroy();
void mem_pools_report(char *buf, size_t size);

void* mem_malloc(size_t size);
void* mem_realloc(void *ptr, size_t size);
void mem_free(void *ptr);

char *http_strdup(const char *s);

void string_init_size(struct string_t *string, size_t size);
void string_init_str(struct string_t *string, const char *s);
void string_clean(struct string_t *string);
void string_strcat(struct string_t *string, const char *s);
void string_strncat(struct string_t *string, const char *s, size_t len);
void string_strcat_printf(struct string_t *string, const char *format, ...);
size_t string_strlen(const struct string_t *string);
size_t string_strsize(const struct string_t *string);
char* string_buf(const struct string_t *string);

struct buffer_t* buffer_alloc(size_t size);
struct buffer_t* buffer_ref(struct buffer_t *buffer);
void buffer_unref(struct buffer_t *buffer);
int buffer_full(struct buffer_t *buffer);
int buffer_empty(struct buffer_t *buffer);

void buffer_node_pool_init(struct buffer_node_pool_t *buffer_node_pool, size_t size);
size_t buffer_node_pool_size(struct buffer_node_pool_t *buffer_node_pool);
int buffer_node_pool_empty(struct buffer_node_pool_t *buffer_node_pool);
struct buffer_node_t* buffer_node_pool_head(struct buffer_node_pool_t *buffer_node_pool);
struct buffer_node_t* buffer_node_pool_tail(struct buffer_node_pool_t *buffer_node_pool);
void buffer_node_pool_push(struct buffer_node_pool_t *buffer_node_pool, struct buffer_node_t *buffer_node);
void buffer_node_pool_pop(struct buffer_node_pool_t *buffer_node_pool, struct buffer_node_t **buffer_node);
void buffer_node_pool_clean(struct buffer_node_pool_t *buffer_node_pool);
#endif
