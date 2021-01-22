#ifndef HTTP_UTIL_H
#define HTTP_UTIL_H

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <unistd.h>
#include <stdint.h>
#include <ctype.h>
#include <inttypes.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <fcntl.h>

#include <time.h>

#include <assert.h>
#include <signal.h>
#include <sys/epoll.h>
#include <pthread.h>

#include "list.h"
#include "rbtree.h"

#define PAGE_SIZE  (1024 * 4)
#define BLOCK_SIZE (1024 * 16)
#define MAX_READ   (PAGE_SIZE * MAX_LOOP)
#define MAX_WRITE  (PAGE_SIZE * MAX_LOOP)
#define PAGE_MAX_COUNT 32
#define DEFAULT_STRING_SIZE 1024
#define MAX_EPOLL_FD 1024

#define MIN(a,b) (((a)<(b)) ? (a) : (b))
#define MAX(a,b) (((a)>(b)) ? (a) : (b))

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

enum {
	CONTINUATION_NONE,
	CONTINUATION_CACHE,
	CONTINUATION_REPLY,
	CONTINUATION_SERVER,
};

struct continuation_t {
	struct list_head_t node;
	void (*callback)(void *callback_data);
	void *callback_data;
	int wait;
	int type;
	void *buf;
};

struct epoll_thread_t {
	pthread_t tid;
	char name[64];
	int64_t current_time;
	int epoll_fd;
	void *pipe_read_connection;
	int pipe_write_fd;
	int signal;

	int64_t epoll_add_num;
	int64_t epoll_mod_num;
	int64_t epoll_del_num;
	int64_t epoll_wait_num;

	struct list_head_t listen_session_list;
	struct list_head_t http_session_list;
	struct list_head_t ready_list;
	struct list_head_t free_list;
	struct list_head_t done_list;
	pthread_mutex_t done_mutex;
	void *dns_session;
};

struct aio_thread_t {
	pthread_t tid;
	char name[64];
	void *aio_list;
};
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

const char* sockaddr_to_string(struct sockaddr *addr, char *str, int size);
int socket_listen(const char *host, unsigned short port, int family);
int socket_non_block(int fd);

struct epoll_thread_t* epoll_thread_select(struct epoll_thread_t *epoll_thread);
void epoll_thread_pipe_signal(struct epoll_thread_t *epoll_thread);

#endif
