#ifndef LISTEN_SESSION_H
#define LISTEN_SESSION_H

#include "http_util.h"
#include "http_connection.h"

struct listen_session_t {
	struct list_head_t node;// for epoll_thread->listen_session_list
	struct connection_t *connection;
	struct epoll_thread_t *epoll_thread;
};

void listen_session_create(struct epoll_thread_t *epoll_thread, int fd);
void listen_session_close(struct listen_session_t *listen_session);
#endif
