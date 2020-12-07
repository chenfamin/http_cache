#include "http_aio.h"

static struct aio_list_t *aio_list = NULL;

void aio_list_create()
{
	aio_list = http_malloc(sizeof(struct aio_list_t));
	memset(aio_list, 0, sizeof(struct aio_list_t));
	INIT_LIST_HEAD(&aio_list->list);
	pthread_mutex_init(&aio_list->mutex, NULL);
	pthread_cond_init(&aio_list->cond, NULL);
}

void aio_list_free()
{
	assert(list_empty(&aio_list->list));
	pthread_mutex_destroy(&aio_list->mutex);
	pthread_cond_destroy(&aio_list->cond);
	http_free(aio_list);
	aio_list = NULL;
}

struct aio_list_t* aio_list_get()
{
	return aio_list;
}

void aio_summit(struct aio_t *aio)
{
}

void aio_create_cache_file(struct aio_t *aio)
{
}

void aio_open(struct aio_t *aio)
{
}

void aio_pread(struct aio_t *aio)
{
}
void aio_pwrite(struct aio_t *aio)
{
}
void aio_close(struct aio_t *aio)
{
}
