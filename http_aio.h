#ifndef HTTP_AIO_H
#define HTTP_AIO_H

#include "http_util.h"


#define MAX_LOOP 4

enum aio_status_t {
	AIO_STATUS_DONE,
	AIO_STATUS_SUMMIT,
};

struct aio_iovec_t {
	void *buffer;
	void *buf;
	size_t buf_size;
	size_t buf_len;
};

struct aio_t {
	struct list_head_t node;
	enum aio_status_t status;
	int fd;
	int flags;
	struct aio_iovec_t iovec[MAX_LOOP + 1];
	int iovec_len;
	int64_t offset;
	int error;
	char *error_str;
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

void aio_summit(struct aio_t *aio, void (*exec)(struct aio_t *aio), void (*done)(struct aio_t *aio));
void aio_exec(struct aio_t *aio);
void aio_done(struct aio_t *aio);
int aio_busy(struct aio_t *aio);

void aio_open(struct aio_t *aio, const char *pathname, int flags, mode_t mode);
void aio_readv(struct aio_t *aio);
void aio_writev(struct aio_t *aio);
void aio_close(struct aio_t *aio);
void aio_unlink(struct aio_t *aio, const char *pathname);

#endif
