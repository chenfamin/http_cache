#ifndef HTTP_H
#define HTTP_H


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <strings.h>
#include <ctype.h>
#include <inttypes.h>

#include <unistd.h>

#include <netdb.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <net/if.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <signal.h>

#include <assert.h>
#include <pthread.h>

#include <sys/epoll.h>


#include "list.h"
#include "rbtree.h"

#define MIN(a,b) (((a)<(b)) ? (a) : (b))
#define MAX(a,b) (((a)>(b)) ? (a) : (b))

#define CONNECTION_FREE_NOW 0
#define CONNECTION_FREE_DELAY 1

#define MAX_LOOP 4

#define PAGE_SIZE (1024 * 4)
#define PAGE_MAX_COUNT 32
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
	void *aio_list;
};

ssize_t http_recv(int s, void *buf, size_t len, int flags);
ssize_t http_send(int s, const void *buf, size_t len, int flags);


int socket_non_block(int fd);
void strlow(uint8_t *dst, uint8_t *src, size_t n);
const char* sockaddr_to_string(struct sockaddr *addr, char *str, int size);

struct epoll_thread_t* epoll_thread_select();
void epoll_thread_pipe_signal(struct epoll_thread_t *epoll_thread);

#endif
