#define _XOPEN_SOURCE 500
#include "http_aio.h"

static struct aio_list_t aio_list;

void aio_list_create()
{
	memset(&aio_list, 0, sizeof(struct aio_list_t));
	INIT_LIST_HEAD(&aio_list.list);
	pthread_mutex_init(&aio_list.mutex, NULL);
	pthread_cond_init(&aio_list.cond, NULL);
}

void aio_list_free()
{
	assert(list_empty(&aio_list.list));
	pthread_mutex_destroy(&aio_list.mutex);
	pthread_cond_destroy(&aio_list.cond);
	memset(&aio_list, 0, sizeof(struct aio_list_t));
}

struct aio_list_t* aio_list_get()
{
	return &aio_list;
}

void aio_list_broadcast()
{
	pthread_mutex_lock(&aio_list.mutex);
	pthread_cond_broadcast(&aio_list.cond);
	pthread_mutex_unlock(&aio_list.mutex);
}

static void aio_exec_list_add(struct aio_t *aio)
{
	pthread_mutex_lock(&aio_list.mutex);
	list_add_tail(&aio->node, &aio_list.list);
	pthread_cond_signal(&aio_list.cond);
	pthread_mutex_unlock(&aio_list.mutex);
}

static void aio_done_list_add(struct aio_t *aio)
{
	struct epoll_thread_t *epoll_thread = aio->epoll_thread;
	pthread_mutex_lock(&epoll_thread->done_mutex);
	list_add_tail(&aio->node, &epoll_thread->done_list);
	pthread_mutex_unlock(&epoll_thread->done_mutex);
	epoll_thread_pipe_signal(epoll_thread);
}

void aio_summit(struct aio_t *aio, void (*exec)(struct aio_t *aio), void (*done)(struct aio_t *aio))
{
	assert(aio->epoll_thread != NULL);
	assert(aio->status == AIO_STATUS_DONE);
	aio->status = AIO_STATUS_SUMMIT;
	aio->error = 0;
	aio->error_str = "";
	aio->exec = exec;
	aio->done = done;
	if (exec) {
		aio_exec_list_add(aio);
	} else {
		aio_done_list_add(aio);
	}
}

void aio_exec(struct aio_t *aio)
{
	aio->exec(aio);
	aio_done_list_add(aio);
}

void aio_done(struct aio_t *aio)
{
	aio->status = AIO_STATUS_DONE;
	aio->done(aio);
}

int aio_busy(struct aio_t *aio)
{
	return aio->status > AIO_STATUS_DONE;
}

void aio_open(struct aio_t *aio, const char *pathname, int flags, mode_t mode)
{
	aio->fd = open(pathname, flags, mode);
	if (aio->fd < 0) {
		aio->error = -1;
		aio->error_str = strerror(errno);
	}
}

void aio_readv(struct aio_t *aio)
{
	ssize_t nread = 0;
	int i = 0;
	for (i = 0; i < aio->iovec_len; i++) {
		nread = pread(aio->fd, aio->iovec[i].buf, aio->iovec[i].buf_size, aio->offset);
		if (nread > 0) {
			aio->iovec[i].buf_len = nread;
			aio->offset += nread;
		} else {
			aio->error = -1;
		}
		if (nread < aio->iovec[i].buf_size) {
			aio->error_str = strerror(errno);
			break;
		}
	}
}

void aio_writev(struct aio_t *aio)
{
	ssize_t nwrite = 0;
	int i = 0;
	for (i = 0; i < aio->iovec_len; i++) {
		nwrite = pwrite(aio->fd, aio->iovec[i].buf, aio->iovec[i].buf_size, aio->offset);
		if (nwrite > 0) {
			aio->iovec[i].buf_len = nwrite;
			aio->offset += nwrite;
		} else {
			aio->error = -1;
		}
		if (nwrite < aio->iovec[i].buf_size) {
			aio->error_str = strerror(errno);
			break;
		}
	}
}

void aio_close(struct aio_t *aio)
{
	if (close(aio->fd)) {
		aio->error = -1;
		aio->error_str = strerror(errno);
	}
}

void aio_unlink(struct aio_t *aio, const char *pathname)
{
	if (unlink(pathname)) {
		aio->error = -1;
		aio->error_str = strerror(errno);
	}
}
