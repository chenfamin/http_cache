#define _XOPEN_SOURCE 500
#include <unistd.h>
#include <sys/uio.h>
#include "http_mem.h"
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

void aio_summit_exec(struct aio_t *aio)
{
	assert(aio->status == AIO_STATUS_DONE);
	assert(aio->epoll_thread != NULL);
	aio->status = AIO_STATUS_SUMMIT;
	pthread_mutex_lock(&aio_list.mutex);
	list_add_tail(&aio->node, &aio_list.list);
	pthread_cond_signal(&aio_list.cond);
	pthread_mutex_unlock(&aio_list.mutex);
}

void aio_exec(struct aio_t *aio)
{
	aio->exec(aio);
	aio_summit_done(aio);
}

void aio_done(struct aio_t *aio)
{
	assert(aio->status == AIO_STATUS_SUMMIT);
	aio->status = AIO_STATUS_DONE;
	aio->done(aio);
}

void aio_summit_done(struct aio_t *aio)
{
	struct epoll_thread_t *epoll_thread = aio->epoll_thread;
	pthread_mutex_lock(&epoll_thread->done_mutex);
	list_add_tail(&aio->node, &epoll_thread->done_list);
	pthread_mutex_unlock(&epoll_thread->done_mutex);
	epoll_thread_pipe_signal(epoll_thread);
}

int aio_busy(struct aio_t *aio)
{
	return aio->status > AIO_STATUS_DONE;
}

void aio_open(struct aio_t *aio)
{
	aio->return_ret = open(aio->path, aio->flags, aio->mode);
	aio->return_errno = errno;
}

void aio_pwritev(struct aio_t *aio)
{
	int64_t offset = aio->offset;
	ssize_t nwrite = 0;
	ssize_t n;
	int i = 0;
	for (i = 0; i < aio->iovec_count; i++) {
		n = 0;
		while (n < aio->iovec[i].iov_len) {
			nwrite = pwrite(aio->fd, aio->iovec[i].iov_base + n, aio->iovec[i].iov_len - n, aio->offset);
			if (nwrite > 0) {
				n += nwrite;
				aio->offset += nwrite;
			} else {
				aio->return_ret = (int)(aio->offset - offset);
				aio->return_errno = errno;
				return;
			}
		}
	}
	aio->return_ret = (int)(aio->offset - offset);
	aio->return_errno = errno;
}

void aio_close(struct aio_t *aio)
{
	aio->return_ret = close(aio->fd);
	aio->return_errno = errno;
}
