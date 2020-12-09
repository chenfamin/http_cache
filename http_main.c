#include "http.h"
#include "http_log.h"
#include "http_aio.h"
#include "http_connection.h"
#include "http_dns.h"
#include "http_session.h"

static int epoll_threads_num = 2;
static int aio_threads_num = 4;
static struct epoll_thread_t *epoll_threads = NULL;
static struct aio_thread_t *aio_threads = NULL;

static volatile int epoll_thread_exit = 0;
static volatile int aio_thread_exit = 0;

static void sig_int(int sig);
static void sig_pipe(int sig);

static void epoll_thread_process_events(struct epoll_thread_t *epoll_thread, struct list_head_t *ready_list);
static void epoll_thread_pipe_read(struct connection_t *connection);
static void epoll_thread_abort_session(struct epoll_thread_t *epoll_thread);

static void sig_int(int sig)
{
	epoll_thread_exit = 1;
}

static void sig_pipe(int sig)
{
}

void epoll_thread_init(struct epoll_thread_t *epoll_thread)
{
	int event_pipe[2];
	struct connection_t *connection = NULL;
	LOG(LOG_INFO, "%s init\n", epoll_thread->name);
	epoll_thread->epoll_fd = epoll_create(MAX_EPOLL_FD);
	if (epoll_thread->epoll_fd < 0) {
		LOG(LOG_ERROR, "%s epoll_create error:%s\n", epoll_thread->name, strerror(errno));
		exit(-1);
	}
	if (pipe(event_pipe)) {
		LOG(LOG_ERROR, "%s pipe error:%s\n", epoll_thread->name, strerror(errno));
		exit(-1);
	} 
	INIT_LIST_HEAD(&epoll_thread->listen_list);
	INIT_LIST_HEAD(&epoll_thread->ready_list);
	INIT_LIST_HEAD(&epoll_thread->free_list);
	INIT_LIST_HEAD(&epoll_thread->http_session_list);
	INIT_LIST_HEAD(&epoll_thread->done_list);
	pthread_mutex_init(&epoll_thread->done_mutex, NULL);
	socket_non_block(event_pipe[0]);
	socket_non_block(event_pipe[1]);

	connection = http_malloc(sizeof(struct connection_t));
	memset(connection, 0, sizeof(struct connection_t));
	connection->fd = event_pipe[0];
	connection->epoll_thread = epoll_thread;
	epoll_thread->pipe_read_connection = connection;
	epoll_thread->pipe_write_fd = event_pipe[1];
	epoll_thread->dns_session = dns_session_create(epoll_thread);
}

void epoll_thread_clean(struct epoll_thread_t *epoll_thread)
{
	struct connection_t *connection = NULL;
	LOG(LOG_INFO, "%s epoll_fd=%d clean\n", epoll_thread->name, epoll_thread->epoll_fd);
	if (epoll_thread->dns_session) {
		dns_session_close(epoll_thread->dns_session);
		epoll_thread->dns_session = NULL;
	}
	while (!list_empty(&epoll_thread->listen_list)) {
		connection = d_list_head(&epoll_thread->listen_list, struct connection_t, node);
		list_del(&connection->node);
		connection_close(connection, CONNECTION_FREE_NOW);
	}
	connection_close(epoll_thread->pipe_read_connection, CONNECTION_FREE_NOW);
	close(epoll_thread->pipe_write_fd);
	close(epoll_thread->epoll_fd);
	assert(list_empty(&epoll_thread->ready_list));
	assert(list_empty(&epoll_thread->free_list));
	assert(list_empty(&epoll_thread->http_session_list));
	assert(list_empty(&epoll_thread->done_list));
	pthread_mutex_destroy(&epoll_thread->done_mutex);
}

void* epoll_thread_loop(void *arg)
{
	struct epoll_thread_t *epoll_thread = arg;
	struct connection_t *connection;
	struct list_head_t ready_list;
	struct epoll_event event_result[MAX_EPOLL_FD];
	int i = 0;
	int nfds = 0;
	while (1) {
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
		epoll_thread_process_events(epoll_thread, &ready_list);
		while (!list_empty(&epoll_thread->free_list)) {
			connection = d_list_head(&epoll_thread->free_list, struct connection_t, node);
			list_del(&connection->node);
			http_free(connection);
		}
		if (epoll_thread_exit) {
			if (list_empty(&epoll_thread->http_session_list)) {
				LOG(LOG_INFO, "%s epoll_fd=%d exit\n", epoll_thread->name, epoll_thread->epoll_fd);
				break;
			} else {
				epoll_thread_abort_session(epoll_thread);
			}
		}
	}
	return NULL;
}

static void epoll_thread_process_events(struct epoll_thread_t *epoll_thread, struct list_head_t *ready_list)
{
	struct list_head_t done_list;
	struct connection_t *connection = NULL;
	struct aio_t *aio = NULL;
	INIT_LIST_HEAD(&done_list);
	while (!list_empty(ready_list)) {
		connection = d_list_head(ready_list, struct connection_t, ready_node);
		list_del(&connection->ready_node);
		connection_handle(connection);
	}
	pthread_mutex_lock(&epoll_thread->done_mutex);
	list_splice_init(&epoll_thread->done_list, &done_list);
	pthread_mutex_unlock(&epoll_thread->done_mutex);
	while (!list_empty(&done_list)) {
		aio = d_list_head(&done_list, struct aio_t, node);
		list_del(&aio->node);
		aio_done(aio);
	}
}

static void epoll_thread_abort_session(struct epoll_thread_t *epoll_thread)
{
	struct http_session_t *http_session = NULL;
	while (!list_empty(&epoll_thread->http_session_list)) {
		http_session = d_list_head(&epoll_thread->http_session_list, struct http_session_t, node);
		http_session_abort(http_session);
	}
}

struct epoll_thread_t* epoll_thread_select()
{
	return epoll_threads + 0;
}

static void epoll_thread_pipe_read(struct connection_t *connection)
{
	char buf[256];
	int loop = 0;
	ssize_t nread = 0;
	struct epoll_thread_t *epoll_thread = connection->epoll_thread;
	assert(connection == epoll_thread->pipe_read_connection);
	do {
		loop++;
		nread = read(connection->fd, buf, sizeof(buf));
		if (nread <= 0) {
			if (nread == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
				LOG(LOG_DEBUG, "%s fd=%d wait for read\n", epoll_thread->name, connection->fd);
				connection_read_done(connection);
				epoll_thread->signal = 0;
			} else {
				LOG(LOG_DEBUG, "%s fd=%d nread=%d error:%s\n", epoll_thread->name, connection->fd, nread, strerror(errno));
			}
			break;
		}
	} while (loop < MAX_LOOP);
	connection_read_enable(connection, epoll_thread_pipe_read);
}

void epoll_thread_pipe_signal(struct epoll_thread_t *epoll_thread)
{
	if (!epoll_thread->signal) {
		epoll_thread->signal = 1;
		write(epoll_thread->pipe_write_fd, "1", 1);
	}
}

void aio_thread_init(struct aio_thread_t *aio_thread)
{
	LOG(LOG_INFO, "%s init\n", aio_thread->name);
	aio_thread->aio_list = aio_list_get();
}

void aio_thread_clean(struct aio_thread_t *aio_thread)
{
	LOG(LOG_INFO, "%s clean\n", aio_thread->name);
}

void* aio_thread_loop(void *arg)
{
	struct aio_thread_t *aio_thread = arg;
	struct aio_list_t *aio_list = aio_thread->aio_list;
	struct aio_t *aio = NULL;
	while (1) {
		pthread_mutex_lock(&aio_list->mutex);
		if (list_empty(&aio_list->list)) {
			if (aio_thread_exit) {
				pthread_mutex_unlock(&aio_list->mutex);
				LOG(LOG_INFO, "%s exit\n", aio_thread->name);
				break;
			} else {
				pthread_cond_wait(&aio_list->cond, &aio_list->mutex);
				if (list_empty(&aio_list->list)) {
					pthread_mutex_unlock(&aio_list->mutex);
					continue;
				}
			}
		}
		aio = d_list_head(&aio_list->list, struct aio_t, node);
		list_del(&aio->node);
		pthread_mutex_unlock(&aio_list->mutex);
		aio_exec(aio);
	}
	return NULL;
}

int main()
{
	int i = 0;
	log_file_open();
	if (signal(SIGINT, sig_int) == SIG_ERR) {
		LOG(LOG_ERROR, "regist SIGINT error\n");
	}
	if (signal(SIGPIPE, sig_pipe) == SIG_ERR) {
		LOG(LOG_ERROR, "regist SIGPIPE error\n");
	}
	aio_list_create();
	dns_cache_table_create();
	cache_table_create();
	LOG(LOG_INFO, "pid=%d\n", getpid());
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
			exit(-1);
		}
	}
	for (i = 0; i < aio_threads_num; i++) {
		if (pthread_create(&aio_threads[i].tid, NULL, aio_thread_loop, &aio_threads[i])) {
			LOG(LOG_ERROR, "%s pthread_create error\n", aio_threads[i].name);
			exit(-1);
		}
	}

	for (i = 0; i < epoll_threads_num; i++) {
		pthread_join(epoll_threads[i].tid, NULL);
	}
	aio_thread_exit = 1;
	aio_list_broadcast();
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

	aio_list_free();
	dns_cache_table_free();
	cache_table_free();
	log_file_close();
	return 0;
}
