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

struct buffer_node_pool_t {
	size_t size;
	struct list_head_t list;
};

struct buffer_list_t {
	struct list_head_t list;
};

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
