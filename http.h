#ifndef HTTP_H
#define HTTP_H

#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>

#include <stdio.h>
#include <inttypes.h>

#include <netdb.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <net/if.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

#include <assert.h>
#include <pthread.h>

#include <sys/epoll.h>


#include "list.h"
#include "rbtree.h"

#define http_malloc malloc
#define http_realloc realloc
//#define http_strdup strdup
#define http_free free

#define MIN(a,b) (((a)<(b)) ? (a) : (b))
#define MAX(a,b) (((a)>(b)) ? (a) : (b))

#define CONNECTION_FREE_NOW 0
#define CONNECTION_FREE_DELAY 1

#define MAX_LOOP 4

#define MAX_IOVEC 4
#define PAGE_SIZE (1024 * 4)
#define PAGE_LIST_MAX_SIZE (1024 * 128)
#define DEFAULT_STRING_SIZE 1024
#define MAX_EPOLL_FD 1024

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

struct mem_node_t {
	struct list_head_t node;
	size_t size;
	size_t len;
	char *buf;
};

struct mem_list_t {
	int64_t low;
	int64_t hight;
	struct list_head_t list;
};

struct string_t {
	size_t size;
	size_t len;
	char *buf;
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

	struct list_head_t listen_list;
	struct list_head_t ready_list;
	struct list_head_t free_list;
	struct list_head_t http_session_list;
	struct list_head_t done_list;
	pthread_mutex_t done_mutex;
	void *dns_session;
};

struct aio_thread_t {
	pthread_t tid;
	char name[64];
};

struct aio_t {
	struct list_head_t node;
	int fd;
	struct iovec iovecs[MAX_IOVEC];
	int count;
	void (*aio_exec)(struct aio_t *aio);
	void (*aio_done)(struct aio_t *aio);
	struct epoll_thread_t *epoll_thread;
};

struct aio_list_t {
	struct list_head_t list;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
};


ssize_t http_recv(int s, void *buf, size_t len, int flags);
ssize_t http_send(int s, const void *buf, size_t len, int flags);

void string_init_size(struct string_t *string, size_t size);
void string_init_str(struct string_t *string, const char *s);
void string_strcat(struct string_t *string, const char *s);
void string_strncat(struct string_t *string, const char *s, size_t len);
void string_strcat_printf(struct string_t *string, const char *format, ...);
size_t string_strlen(const struct string_t *string);
char* string_buf(const struct string_t *string);
void string_clean(struct string_t *string);

struct mem_node_t *mem_node_alloc(size_t size);
struct mem_node_t* mem_node_realloc(struct mem_node_t *mem_node, size_t size);
char* mem_node_buf(struct mem_node_t *mem_node);
size_t mem_node_size(struct mem_node_t *mem_node);
size_t mem_node_len(struct mem_node_t *mem_node);
int mem_node_is_full(struct mem_node_t *mem_node);
void mem_node_add_len(struct mem_node_t *mem_node, size_t len);
void mem_node_append(struct mem_node_t *mem_node, const char *buf, size_t len);
void mem_node_free(struct mem_node_t *mem_node);

void mem_list_init(struct mem_list_t *mem_list);
void mem_list_resize_first_node(struct mem_list_t *mem_list, size_t size);
int64_t mem_list_size(struct mem_list_t *mem_list);
void mem_list_set_low(struct mem_list_t *mem_list, int64_t low);
size_t mem_list_read_buf(struct mem_list_t *mem_list, char **buf, int64_t offset);
size_t mem_list_write_buf(struct mem_list_t *mem_list, char **buf);
void mem_list_append(struct mem_list_t *mem_list, const char *buf, size_t len);
void mem_list_free_to(struct mem_list_t *mem_list, int64_t offset);
void mem_list_clean(struct mem_list_t *mem_list);

int socket_non_block(int fd);
char *http_strdup(const char *s);
void strlow(uint8_t *dst, uint8_t *src, size_t n);
const char* sockaddr_to_string(struct sockaddr *addr, char *str, int size);

struct epoll_thread_t* epoll_thread_select();
void epoll_thread_pipe_signal(struct epoll_thread_t *epoll_thread);

#endif
