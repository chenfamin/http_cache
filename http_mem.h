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

#define is_power_of_2(x)	((x) != 0 && (((x) & ((x) - 1)) == 0))
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

struct fifo_t {
	void **data;
	unsigned int size;
	unsigned int in;
	unsigned int out;
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

void fifo_init(struct fifo_t *fifo, unsigned int size);
unsigned int fifo_size(struct fifo_t *fifo);
unsigned int fifo_len(struct fifo_t *fifo);
void fifo_push_tail(struct fifo_t *fifo, void *buffer);
void fifo_pop_head(struct fifo_t *fifo, void **buffer);
void *fifo_head(struct fifo_t *fifo);
void *fifo_tail(struct fifo_t *fifo);
void fifo_clean(struct fifo_t *fifo);

//const char* sockaddr_to_string(struct sockaddr *addr, char *str, int size);
int socket_listen(const char *host, unsigned short port, int family);
int socket_non_block(int fd);
#endif
