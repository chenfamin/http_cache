#include "http.h"
#include "http_log.h"
#include "http_connection.h"
int connection_epoll_add(struct connection_t *connection, uint32_t event)
{
	int r;
	struct epoll_event ev = {0};
	ev.data.ptr = connection;
	ev.events = event | EPOLLET;
	if (ev.events & EPOLLET) { 
		connection->edge_mode = 1;// EPOLLET must use edge_mode=1
	} else {
		connection->edge_mode = 1;//  both edge_mode=0 or edge_mode=1 are ok
	}
	r = epoll_ctl(connection->epoll_thread->epoll_fd, EPOLL_CTL_ADD, connection->fd, &ev);
	if (r) {
		LOG(LOG_ERROR, "fail epoll_fd=%d fd=%d: %s\n", connection->epoll_thread->epoll_fd, connection->fd, strerror(errno));
		assert(0);
	} else {
		connection->event = ev.events;
	}
	connection->epoll_thread->epoll_add_num++;
	return r;
}

int connection_epoll_mod(struct connection_t *connection, uint32_t event)
{
	int r;
	struct epoll_event ev = {0};
	ev.data.ptr = connection;
	ev.events = event;
	r = epoll_ctl(connection->epoll_thread->epoll_fd, EPOLL_CTL_MOD, connection->fd, &ev);
	if (r) {
		LOG(LOG_ERROR, "fail epoll_fd=%d fd=%d: %s\n", connection->epoll_thread->epoll_fd, connection->fd, strerror(errno));
		assert(0);
	} else {
		connection->event = ev.events;
	}
	connection->epoll_thread->epoll_mod_num++;
	return r;
}

int connection_epoll_del(struct connection_t *connection)
{
	int r;
	struct epoll_event ev = {0};
	r = epoll_ctl(connection->epoll_thread->epoll_fd, EPOLL_CTL_DEL, connection->fd, &ev);
	if (r) {
		LOG(LOG_ERROR, "fail epoll_fd=%d fd=%d: %s\n", connection->epoll_thread->epoll_fd, connection->fd, strerror(errno));
		assert(0);
	} else {
		connection->event = 0;
	}
	connection->epoll_thread->epoll_del_num++;
	return r;
}

void connection_read_enable(struct connection_t *connection, void (*handle_read)(struct connection_t *connection))
{
	if (connection->handle_read != handle_read) {
		connection->handle_read = handle_read;
	}
	if (connection->edge_mode && (connection->trigger_event & EPOLLIN)) {
		if (list_node_null(&connection->ready_node)) {
			list_add_tail(&connection->ready_node, &connection->epoll_thread->ready_list);
		}
	} else if (connection->event == 0) {
		connection_epoll_add(connection, EPOLLIN);
	} else if ((connection->event & EPOLLIN) == 0) {
		connection_epoll_mod(connection, connection->event | EPOLLIN);
	}
}

void connection_read_disable(struct connection_t *connection)
{
	connection->read_disable_num++;
	connection->handle_read = NULL;
	if (connection->edge_mode) {
		if (connection->handle_write == NULL && !list_node_null(&connection->ready_node)) {
			list_del(&connection->ready_node);
		}
	}
	if (connection->event) {
		if ((connection->event & (~EPOLLIN)) == 0) {
			connection_epoll_del(connection);
		} else {
			connection_epoll_mod(connection, connection->event & (~EPOLLIN));
		}
	}
}

void connection_write_enable(struct connection_t *connection, void (*handle_write)(struct connection_t *connection))
{
	if (connection->handle_write != handle_write) {
		connection->handle_write = handle_write;
	}
	if (connection->edge_mode && (connection->trigger_event & EPOLLOUT)) {
		if (list_node_null(&connection->ready_node)) {
			list_add_tail(&connection->ready_node, &connection->epoll_thread->ready_list);
		}
	} else if (connection->event == 0) {
		connection_epoll_add(connection, EPOLLOUT);
	} else if ((connection->event & EPOLLOUT) == 0) {
		connection_epoll_mod(connection, connection->event | EPOLLOUT);
	}
}

void connection_write_disable(struct connection_t *connection)
{
	connection->write_disable_num++;
	connection->handle_write = NULL;
	if (connection->edge_mode) {
		if (connection->handle_read == NULL && !list_node_null(&connection->ready_node)) {
			list_del(&connection->ready_node);
		}
	}
	if (connection->event) {
		if ((connection->event & (~EPOLLOUT)) == 0) {
			connection_epoll_del(connection);
		} else {
			connection_epoll_mod(connection, connection->event & (~EPOLLOUT));
		}
	}
}

void connection_read_done(struct connection_t *connection)
{
	connection->trigger_event &= (~EPOLLIN);
}

void connection_write_done(struct connection_t *connection)
{
	connection->trigger_event &= (~EPOLLOUT);
}

void connection_handle(struct connection_t *connection)
{
	if (connection->handle_read && (connection->trigger_event & (EPOLLIN | EPOLLERR | EPOLLHUP))) {
		connection->handle_read(connection);
	}
	if (connection->handle_write && (connection->trigger_event & (EPOLLOUT | EPOLLERR | EPOLLHUP))) {
		connection->handle_write(connection);
	}
}

void connection_close(struct connection_t *connection, int delay_free)
{
	struct epoll_thread_t *epoll_thread = connection->epoll_thread;
	connection_read_disable(connection);
	connection_write_disable(connection);
	LOG(LOG_INFO, "%s epoll_fd=%d fd=%d read_disable=%"PRId64" write_disable=%"PRId64" epoll_add=%"PRId64" epoll_del=%"PRId64" epoll_mod=%"PRId64" epoll_wait=%"PRId64"\n", 
			epoll_thread->name, epoll_thread->epoll_fd, connection->fd, connection->read_disable_num, connection->write_disable_num,
			epoll_thread->epoll_add_num, epoll_thread->epoll_del_num, epoll_thread->epoll_mod_num, epoll_thread->epoll_wait_num);
	connection->trigger_event = 0;
	close(connection->fd);
	connection->fd = -1;
	if (delay_free == CONNECTION_FREE_DELAY) {
		list_add_tail(&connection->node, &connection->epoll_thread->free_list);
	} else {
		assert(delay_free == CONNECTION_FREE_NOW);
		http_free(connection);
	}
}

