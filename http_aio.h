#ifndef HTTP_AIO_H
#define HTTP_AIO_H

#include "http.h"

struct aio_t {
	struct list_head_t node;
	int fd;
	void *buf;
	size_t buf_len;
	int64_t offset;
	void (*aio_exec)(struct aio_t *aio);
	void (*aio_done)(struct aio_t *aio);
	void *callback_data;
	struct epoll_thread_t *epoll_thread;
};

struct aio_list_t {
	struct list_head_t list;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
};

void aio_list_create();
void aio_list_free();
struct aio_list_t* aio_list_get();

void aio_summit(struct aio_t *aio);
void aio_create_cache_file(struct aio_t *aio);
void aio_open(struct aio_t *aio);
void aio_pread(struct aio_t *aio);
void aio_pwrite(struct aio_t *aio);
void aio_close(struct aio_t *aio);

#endif
