#include "http.h"
#include "http_dns.h"
#include "http_session.h"

static struct epoll_thread_t *epoll_threads = NULL;
static struct aio_thread_t *aio_threads = NULL;
static int epoll_threads_num = 2;
static int aio_threads_num = 4;
int want_exit = 0;

static void sig_int(int sig);
static void sig_pipe(int sig);

static void sig_int(int sig)
{
	want_exit = 1;
}

static void sig_pipe(int sig)
{
}

void epoll_thread_init(struct epoll_thread_t *epoll_thread)
{
	//int event_pipe[2];
	INIT_LIST_HEAD(&epoll_thread->listen_list);
	INIT_LIST_HEAD(&epoll_thread->ready_list);
	INIT_LIST_HEAD(&epoll_thread->free_list);
	epoll_thread->epoll_fd = epoll_create(MAX_EPOLL_FD);
	if (epoll_thread->epoll_fd < 0) {
		LOG(LOG_ERROR, "%s epoll_create error:%s\n", epoll_thread->name, strerror(errno));
		assert(0);
	}
	/*
	   if (pipe(event_pipe)) {
	   LOG("%s pipe error:%s\n", epoll_thread->name, strerror(errno));
	   assert(0);
	   } 
	   socket_non_block(event_pipe[0]);
	   socket_non_block(event_pipe[1]);
	 */
	epoll_thread_dns_connection_init(epoll_thread);
}

void* epoll_thread_loop(void *arg)
{
	struct epoll_thread_t *epoll_thread = arg;
	struct connection_t *connection;
	struct list_head_t ready_list;
	struct epoll_event event_result[MAX_EPOLL_FD];
	int nfds = 0;
	int i = 0;
	while (!want_exit) {
		INIT_LIST_HEAD(&ready_list);
		list_splice_init(&epoll_thread->ready_list, &ready_list);
		nfds = epoll_wait(epoll_thread->epoll_fd, event_result, MAX_EPOLL_FD, list_empty(&ready_list)? 100:0);
		epoll_thread->epoll_wait_num++;
		if (nfds < 0) {
			LOG(LOG_WARNING, "%s epoll_wait=%d ingnore: %s\n", epoll_thread->name, nfds, strerror(errno));
		}
		for (i = 0; i < nfds; i++) {
			connection = event_result[i].data.ptr;
			if (event_result[i].events & (EPOLLIN | EPOLLERR | EPOLLHUP)) {
				//LOG("%s fd=%d EPOLLIN\n", epoll_thread->name, connection->fd);
				connection->trigger_event |= EPOLLIN;
			}
			if (event_result[i].events & (EPOLLOUT | EPOLLERR | EPOLLHUP)) {
				//LOG("%s fd=%d EPOLLOUT\n", epoll_thread->name, connection->fd);
				connection->trigger_event |= EPOLLOUT;
			}
			if (list_node_null(&connection->ready_node)) {
				list_add_tail(&connection->ready_node, &ready_list);
			}
		}
		while (!list_empty(&ready_list)) {
			connection = d_list_head(&ready_list, struct connection_t, ready_node);
			list_del(&connection->ready_node);
			connection_handle(connection);
		}
		while (!list_empty(&epoll_thread->free_list)) {
			connection = d_list_head(&epoll_thread->free_list, struct connection_t, node);
			list_del(&connection->node);
			http_free(connection);
		}
	}
	return NULL;
}

void epoll_thread_clean(struct epoll_thread_t *epoll_thread)
{
	struct connection_t *connection = NULL;
	if (epoll_thread->dns_connection) {
		epoll_thread_dns_connection_close(epoll_thread);
	}
	while (!list_empty(&epoll_thread->listen_list)) {
		connection = d_list_head(&epoll_thread->listen_list, struct connection_t, node);
		list_del(&connection->node);
		connection_close(connection, CONNECTION_FREE_NOW);
	}
	assert(list_empty(&epoll_thread->ready_list));
	assert(list_empty(&epoll_thread->free_list));
	close(epoll_thread->epoll_fd);
}

struct epoll_thread_t* epoll_thread_select()
{
	return epoll_threads + 0;
}

void aio_thread_init(struct aio_thread_t *aio_thread)
{
}

void* aio_thread_loop(void *arg)
{
	return NULL;
}

void aio_thread_clean(struct aio_thread_t *aio_thread)
{
}

int main()
{
	int i = 0;
	if (signal(SIGINT, sig_int) == SIG_ERR) {
		LOG(LOG_ERROR, "regist SIGINT error\n");
	}
	if (signal(SIGPIPE, sig_pipe) == SIG_ERR) {
		LOG(LOG_ERROR, "regist SIGPIPE error\n");
	}
	LOG(LOG_INFO, "pid=%d\n", getpid());
	dns_cache_table_init();
	cache_table_init();

	epoll_threads = http_malloc(sizeof(struct epoll_thread_t) * epoll_threads_num);
	memset(epoll_threads, 0, sizeof(struct epoll_thread_t) * epoll_threads_num);
	aio_threads = http_malloc(sizeof(struct aio_thread_t) * aio_threads_num);
	memset(aio_threads, 0, sizeof(struct aio_thread_t) * aio_threads_num);

	for (i = 0; i < epoll_threads_num; i++) {
		snprintf(epoll_threads[i].name, sizeof(epoll_threads[i].name), "net[%d]", i);
		epoll_thread_init(&epoll_threads[i]);
	}
	for (i = 0; i < aio_threads_num; i++) {
		snprintf(aio_threads[i].name, sizeof(aio_threads[i].name), "aio[%d]", i);
		aio_thread_init(&aio_threads[i]);
	}

	http_session_listen("0.0.0.0", 8888);

	for (i = 0; i < epoll_threads_num; i++) {
		if (pthread_create(&epoll_threads[i].tid, NULL, epoll_thread_loop, &epoll_threads[i])) {
			LOG(LOG_ERROR, "%s pthread_create error\n", epoll_threads[i].name);
			assert(0);
		}
	}
	for (i = 0; i < aio_threads_num; i++) {
		if (pthread_create(&aio_threads[i].tid, NULL, aio_thread_loop, &aio_threads[i])) {
			LOG(LOG_ERROR, "%s pthread_create error\n", aio_threads[i].name);
			assert(0);
		}
	}

	for (i = 0; i < epoll_threads_num; i++) {
		pthread_join(epoll_threads[i].tid, NULL);
	}
	for (i = 0; i < aio_threads_num; i++) {
		pthread_join(aio_threads[i].tid, NULL);
	}

	for (i = 0; i < epoll_threads_num; i++) {
		epoll_thread_clean(&epoll_threads[i]);
	}
	for (i = 0; i < aio_threads_num; i++) {
		aio_thread_clean(&aio_threads[i]);
	}

	http_free(epoll_threads);
	http_free(aio_threads);

	dns_cache_table_clean();
	cache_table_clean();
	return 0;
}
