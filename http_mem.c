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


void buffer_list_init(struct buffer_list_t *buffer_list, size_t size)
{
	size_t i = 0;
	struct buffer_node_t *buffer_node = NULL;
	for (i = 0; i < size; i++) {
		buffer_node = http_malloc(sizeof(struct buffer_node_t));
		buffer_node->buffer = NULL;
		list_add_tail(&buffer_node->node, &buffer_list->free_list);
	}
}

int buffer_list_empty(struct buffer_list_t *buffer_list)
{
	return list_empty(&buffer_list->use_list);
}

int buffer_list_full(struct buffer_list_t *buffer_list)
{
	return list_empty(&buffer_list->free_list);
}

void* buffer_list_head(struct buffer_list_t *buffer_list)
{
	struct buffer_node_t *buffer_node = NULL;
	if (list_empty(&buffer_list->use_list)) {
		return NULL;
	}
	buffer_node = d_list_head(&buffer_list->use_list, struct buffer_node_t, node);
	return buffer_node->buffer;
}

void* buffer_list_tail(struct buffer_list_t *buffer_list)
{
	struct buffer_node_t *buffer_node = NULL;
	if (list_empty(&buffer_list->use_list)) {
		return NULL;
	}
	buffer_node = d_list_head(&buffer_list->use_list, struct buffer_node_t, node);
	return buffer_node->buffer;
}

void buffer_list_push(struct buffer_list_t *buffer_list, void *buffer)
{
	struct buffer_node_t *buffer_node = NULL;
	assert(!list_empty(&buffer_list->free_list));
	buffer_node = d_list_head(&buffer_list->free_list, struct buffer_node_t, node);
	list_del(&buffer_node->node);
	buffer_node->buffer = buffer;
	list_add_tail(&buffer_node->node, &buffer_list->use_list);
}

void buffer_list_pop(struct buffer_list_t *buffer_list, void **buffer)
{
	struct buffer_node_t *buffer_node = NULL;
	assert(!list_empty(&buffer_list->use_list));
	buffer_node = d_list_head(&buffer_list->use_list, struct buffer_node_t, node);
	list_del(&buffer_node->node);
	*buffer = buffer_node->buffer;
	buffer_node->buffer = NULL;
	list_add_tail(&buffer_node->node, &buffer_list->free_list);
}

void buffer_list_clean(struct buffer_list_t *buffer_list)
{
	struct buffer_node_t *buffer_node = NULL;
	assert(list_empty(&buffer_list->use_list));
	while (!list_empty(&buffer_list->free_list)) {
		buffer_node = d_list_head(&buffer_list->free_list, struct buffer_node_t, node);
		list_del(&buffer_node->node);
		http_free(buffer_node);
	}
}
