#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct buffer_t {
	size_t size;
	size_t len;
	size_t ref;
	char *buf;
};

#define is_power_of_2(x)	((x) != 0 && (((x) & ((x) - 1)) == 0))
struct fifo_t {
	void **data;
	unsigned int size;
	unsigned int in;
	unsigned int out;
};

void fifo_init(struct fifo_t *fifo, unsigned int size)
{
	assert(is_power_of_2(size));
	fifo->data = http_malloc(sizeof(void*) * size);
	memset(fifo->data, 0, sizeof(void*) * size);
	fifo->size = size;
	fifo->in = 0;
	fifo->out = 0;
}

unsigned int fifo_length(struct fifo_t *fifo)
{
	return fifo->in - fifo->out;
}

void fifo_push(struct fifo_t *fifo, void *buf)
{
	assert(fifo->size > fifo->in - fifo->out);
	fifo->data[(fifo->in & (fifo->size - 1))] = buf;
	fifo->in++;
}

void fifo_pop(struct fifo_t *fifo)
{
	assert(fifo->in > fifo->out);
	fifo->data[(fifo->out & (fifo->size - 1))] = NULL;
	fifo->out++;
}
