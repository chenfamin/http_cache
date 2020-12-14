#include <stdlib.h>
#include <assert.h>
#include "http_mem.h"
struct buffer_t* buffer_alloc(size_t size)
{
	struct buffer_t *buffer = NULL;
	buffer = http_malloc(sizeof(struct buffer_t) + size);
	buffer->ref = 1;
	buffer->size = size;
	buffer->len = 0;
	buffer->buf = (void *)buffer + sizeof(struct buffer_t);
	return buffer;
}

struct buffer_t* buffer_ref(struct buffer_t *buffer)
{
	buffer->ref++;
	return buffer;
}

void buffer_unref(struct buffer_t *buffer)
{
	buffer->ref--;
	if (buffer->ref == 0) {
		http_free(buffer);
	}
}

int buffer_full(struct buffer_t *buffer)
{
	return buffer->len == buffer->size;
}

int buffer_empty(struct buffer_t *buffer)
{
	return buffer->len == 0;
}

void buffer_node_pool_init(struct buffer_node_pool_t *buffer_node_pool, size_t alloc_size)
{
	size_t i = 0;
	struct buffer_node_t *buffer_node = NULL;
	INIT_LIST_HEAD(&buffer_node_pool->list);
	for (i = 0; i < alloc_size; i++) {
		buffer_node = http_malloc(sizeof(struct buffer_node_t));
		list_add_tail(&buffer_node->node, &buffer_node_pool->list);
	}
}

int buffer_node_pool_empty(struct buffer_node_pool_t *buffer_node_pool)
{
	if (list_empty(&buffer_node_pool->list)) {
		return 1;
	} else {
		return 0;
	}
}

struct buffer_node_t* buffer_node_pool_head(struct buffer_node_pool_t *buffer_node_pool)
{
	if (list_empty(&buffer_node_pool->list)) {
		return NULL;
	} else {
		return d_list_head(&buffer_node_pool->list, struct buffer_node_t, node);
	}
}

struct buffer_node_t* buffer_node_pool_tail(struct buffer_node_pool_t *buffer_node_pool)
{
	if (list_empty(&buffer_node_pool->list)) {
		return NULL;
	} else {
		return d_list_tail(&buffer_node_pool->list, struct buffer_node_t, node);
	}
}

void buffer_node_pool_push(struct buffer_node_pool_t *buffer_node_pool, struct buffer_node_t *buffer_node)
{
	list_add_tail(&buffer_node->node, &buffer_node_pool->list);
}

void buffer_node_pool_pop(struct buffer_node_pool_t *buffer_node_pool, struct buffer_node_t **buffer_node)
{
	assert(!list_empty(&buffer_node_pool->list));
	if (list_empty(&buffer_node_pool->list)) {
		*buffer_node = NULL;
	} else {
		*buffer_node = d_list_head(&buffer_node_pool->list, struct buffer_node_t, node);
		list_del(&(*buffer_node)->node);
	}
}

void buffer_node_pool_clean(struct buffer_node_pool_t *buffer_node_pool)
{
	struct buffer_node_t *buffer_node = NULL;
	while (!list_empty(&buffer_node_pool->list)) {
		buffer_node = d_list_head(&buffer_node_pool->list, struct buffer_node_t, node);
		list_del(&buffer_node->node);
		http_free(buffer_node);
	}
}
