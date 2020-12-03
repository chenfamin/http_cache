#ifndef HTTP_SESSION_H
#define HTTP_SESSION_H

#include "http.h"
#include "http_header.h"

struct http_request_t {
	enum http_method method;
	int http_major;
	int http_minor;
	struct string_t url;
	struct http_header_t header;
	struct http_range_t *range;
	int64_t content_length;
	enum parser_header_state parse_state;
};

struct http_reply_t {
	int status_code;
	int http_major;
	int http_minor;
	struct http_header_t header;
	int64_t content_length;
	enum parser_header_state parse_state;
};

struct cache_table_t {
	pthread_mutex_t mutex;
	struct rb_root rb_root;
	struct list_head_t list;
	int64_t count;
};

struct cache_t {
	char *key;
	struct rb_node rb_node;
	struct epoll_thread_t *epoll_thread;
	int lock;

	struct http_reply_t *http_reply;
	int header_size;
};

struct aio_t {
	struct list_head_t node;
	int fd;
	struct iovec iovecs[MAX_IOVEC];
	int count;
	void (*aio_exec)(struct aio_t *aio);
	void (*aio_done)(struct aio_t *aio);
	struct epoll_thread_t *epoll_thread;
};

struct http_cache_client_t {
	struct cache_t *cache;
	int64_t body_offset;
	int64_t body_write_size;
	struct aio_t aio;
	int busy;
};

struct http_client_t {
	struct connection_t *connection;
	http_parser parser;
	int64_t post_current_size;
	int64_t post_expect_size;
	int keep_alive;
	struct string_t reply_header; 
	int64_t reply_send_size; 
	int64_t body_offset;
	int64_t body_expect_size;
	struct continuation_t continuation;
};

struct http_server_t {
	struct connection_t *connection;
	struct http_range_t *range;
	struct string_t request_header;
	int64_t request_send_size;
	http_parser parser;
	int chunked;
	struct http_chunked_t http_chunked;
	struct dns_info_t dns_info;
	uint16_t port;
	int keep_alive;
	int64_t body_offset;
	int64_t body_current_size;
	int64_t body_expect_size;
	struct continuation_t continuation;
};

struct http_session_t {
	struct list_head_t node;// for epoll_thread->http_session_list
	struct http_request_t http_request;
	struct mem_list_t post_list;
	struct http_client_t *http_client;
	struct http_cache_client_t *http_cache_client;
	struct http_server_t *http_server;

	struct mem_list_t body_list;
	struct epoll_thread_t *epoll_thread;
};

void http_session_listen(const char *host, int port);
void cache_table_create();
void cache_table_free();

#endif
