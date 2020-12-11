#ifndef HTTP_MEM_H
#define HTTP_MEM_H

#include "list.h"

#define http_malloc malloc
#define http_realloc realloc
//#define http_strdup strdup
#define http_free free

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

struct buffer_list_t {
	struct list_head_t use_list;
	struct list_head_t free_list;
};

struct buffer_t* buffer_alloc(size_t size);
struct buffer_t* buffer_ref(struct buffer_t *buffer);
void buffer_unref(struct buffer_t *buffer);
int buffer_full(struct buffer_t *buffer);
int buffer_empty(struct buffer_t *buffer);

void buffer_list_init(struct buffer_list_t *buffer_list, size_t size);
int buffer_list_empty(struct buffer_list_t *buffer_list);
int buffer_list_full(struct buffer_list_t *buffer_list);
void* buffer_list_head(struct buffer_list_t *buffer_list);
void* buffer_list_tail(struct buffer_list_t *buffer_list);
void buffer_list_push(struct buffer_list_t *buffer_list, void *buffer);
void buffer_list_pop(struct buffer_list_t *buffer_list, void **buffer);
void buffer_list_clean(struct buffer_list_t *buffer_list);

#endif
