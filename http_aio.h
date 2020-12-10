#ifndef HTTP_AIO_H
#define HTTP_AIO_H

#include "http.h"

enum aio_status_t {
	AIO_STATUS_DONE,
	AIO_STATUS_SUMMIT,
};

struct aio_t {
	struct list_head_t node;
	enum aio_status_t status;
	int fd;
	int flags;
	mode_t mode;
	void *buf;
	size_t buf_len;
	int64_t offset;
	int return_ret;
	int return_errno;
	void (*exec)(struct aio_t *aio);
	void (*done)(struct aio_t *aio);
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
void aio_list_broadcast();

void aio_summit_exec(struct aio_t *aio);
void aio_exec(struct aio_t *aio);
void aio_done(struct aio_t *aio);
void aio_summit_done(struct aio_t *aio);
int aio_busy(struct aio_t *aio);

void aio_open(struct aio_t *aio);
void aio_pwrite(struct aio_t *aio);
void aio_close(struct aio_t *aio);

#endif
