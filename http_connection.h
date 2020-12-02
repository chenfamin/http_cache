#ifndef HTTP_CONNECTION_H
#define HTTP_CONNECTION_H

#include "http.h"

struct connection_t {
	int fd; 
	struct sockaddr local_addr;
	struct sockaddr peer_addr;
	int edge_mode;
	uint32_t event;
	uint32_t trigger_event;
	struct list_head_t node;
	struct list_head_t ready_node;
	void (*handle_read)(struct connection_t *connection);
	void (*handle_write)(struct connection_t *connection);
	void *arg;

	int64_t read_disable_num;
	int64_t write_disable_num;

	//struct timer_node_t timer_node;
	struct epoll_thread_t *epoll_thread;
};

int connection_epoll_add(struct connection_t *connection, uint32_t event);
int connection_epoll_mod(struct connection_t *connection, uint32_t event);
int connection_epoll_del(struct connection_t *connection);

void connection_read_enable(struct connection_t *connection, void (*handle_read)(struct connection_t *connection));
void connection_read_disable(struct connection_t *connection);
void connection_write_enable(struct connection_t *connection, void (*handle_write)(struct connection_t *connection));
void connection_write_disable(struct connection_t *connection);
void connection_read_done(struct connection_t *connection);
void connection_write_done(struct connection_t *connection);
void connection_handle(struct connection_t *connection);
void connection_close(struct connection_t *connection, int delay_free);


#endif
