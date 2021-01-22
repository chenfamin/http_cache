#include "http_log.h"
#include "http_session.h"
#include "listen_session.h"

static void listen_session_accept(struct connection_t *connection);

void listen_session_create(struct epoll_thread_t *epoll_thread, int fd)
{
	struct listen_session_t *listen_session = NULL;
	struct connection_t *connection = NULL;
	socklen_t addr_len = sizeof(struct sockaddr);
	char ip_str[64] = {0};
	assert(fd > 0);
	listen_session = http_malloc(sizeof(struct listen_session_t));
	memset(listen_session, 0, sizeof(struct listen_session_t));
	list_add_tail(&listen_session->node, &epoll_thread->listen_session_list);
	listen_session->epoll_thread = epoll_thread;
	listen_session->connection = connection = http_malloc(sizeof(struct connection_t));
	memset(connection, 0, sizeof(struct connection_t));
	socket_non_block(fd);
	connection->fd = fd;
	getsockname(connection->fd, &connection->local_addr, &addr_len);
	connection->epoll_thread = epoll_thread;
	connection->arg = listen_session;
	LOG(LOG_INFO, "%s listen %s fd=%d\n", epoll_thread->name, sockaddr_to_string(&connection->local_addr, ip_str, sizeof(ip_str)), connection->fd);
	connection_read_enable(connection, listen_session_accept);
}

void listen_session_close(struct listen_session_t *listen_session)
{
	struct connection_t *connection = listen_session->connection;
	list_del(&listen_session->node);
	connection_close(connection, CONNECTION_FREE_NOW);
	http_free(listen_session);
}

static void listen_session_accept(struct connection_t *connection)
{
	struct listen_session_t *listen_session = connection->arg;
	struct epoll_thread_t *epoll_thread = connection->epoll_thread;
	struct sockaddr peer_addr;
	socklen_t addr_len = sizeof(struct sockaddr);
	char ip_str[64] = {0};
	int fd;
	assert(listen_session->epoll_thread == connection->epoll_thread);
	fd = accept(connection->fd, (struct sockaddr*)&peer_addr, &addr_len);
	if (fd <= 0) {
		if (fd == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			LOG(LOG_DEBUG, "%s fd=%d again\n", epoll_thread->name, connection->fd);
			connection_read_done(connection);
			connection_read_enable(connection, listen_session_accept);
		} else {
			LOG(LOG_ERROR, "%s fd=%d accept=%d error:%s\n", epoll_thread->name, connection->fd, fd, strerror(errno));
		}
		return;
	}
	connection_read_enable(connection, listen_session_accept);
	socket_non_block(fd);
	LOG(LOG_INFO, "%s accept %s fd=%d\n", epoll_thread->name, sockaddr_to_string(&peer_addr, ip_str, sizeof(ip_str)), fd);
	http_session_create(epoll_thread, fd);
}
