#ifndef HTTP_SESSION_H
#define HTTP_SESSION_H

#include "http.h"
#include "http_mem.h"
#include "http_aio.h"
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

struct cache_file_t {
	struct list_head_t delay_list;
	struct http_reply_t *http_reply;
	char  *header_buf;
	size_t header_size;
	size_t bitmap_bit_size;
	size_t bitmap_byte_size;
	unsigned char *bitmap;
	size_t bitmap_size;
	char path[256];
	int64_t file_number;
	int fd;
};

struct cache_t {
	char *key;
	char *url;
	struct rb_node rb_node;
	struct epoll_thread_t *epoll_thread;
	int lock;

	int64_t file_number;
	struct cache_file_t *cache_file;
};

enum {
	CACHE_DELAY_NONE,
	CACHE_DELAY_READ,
	CACHE_DELAY_WRITE,
};

struct cache_client_t {
	struct cache_t *cache;
	void *http_session;
	int bitmap_flush;
	struct fifo_t body_fifo;

	int64_t body_pos;
	size_t bitmap_pos;

	struct aio_t aio;
	int delay;
	struct http_parser parser;
};

struct http_client_t {
	struct connection_t *connection;
	http_parser parser;
	int keep_alive;
	struct string_t reply_header; 
	int64_t reply_header_send_size; 
	int64_t body_offset;
	int64_t body_offset_current;
	int64_t body_offset_expect;
	struct continuation_t continuation;
};

struct http_server_t {
	struct connection_t *connection;
	int connected;
	struct http_range_t *range;
	struct string_t request_header;
	int64_t request_header_send_size;
	int64_t post_offset_current;
	http_parser parser;
	int chunked;
	struct http_chunked_t http_chunked;
	struct dns_info_t dns_info;
	uint16_t port;
	int keep_alive;
	struct http_reply_t *http_reply;
	int64_t body_offset;
	//int64_t body_offset_current; equal http_sesssion->body_high
	int64_t body_offset_expect;
	struct continuation_t continuation;
};

struct http_session_t {
	struct list_head_t node;// for epoll_thread->http_session_list
	struct http_request_t http_request;
	int64_t post_low;
	int64_t post_high;
	struct fifo_t post_fifo;
	struct http_client_t *http_client;
	struct cache_client_t *cache_client;
	struct http_server_t *http_server;
	int abort;
	int64_t body_low;
	int64_t body_high;
	struct fifo_t body_fifo;
	struct epoll_thread_t *epoll_thread;
};

void http_session_listen(const char *host, int port);
void http_session_create(struct epoll_thread_t *epoll_thread, int fd);
void http_session_abort(struct http_session_t *http_session);
void cache_table_create();
void cache_table_free();

#endif
