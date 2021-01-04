#include "http.h"
#include "http_log.h"
#include "http_aio.h"
#include "http_connection.h"
#include "http_dns.h"
#include "http_header.h"
#include "http_session.h"

static struct cache_table_t cache_table;

static int socket_listen(const char *host, uint16_t port, int family);
static int request_on_message_begin(http_parser *hp);
static int request_on_url(http_parser *hp, const char *at, size_t length);
static int request_on_header_field(http_parser *hp, const char *at, size_t length);
static int request_on_header_value(http_parser *hp, const char *at, size_t length);
static int request_on_headers_complete(http_parser *hp);
static int request_on_body(http_parser *hp, const char *at, size_t length);
static int request_on_message_complete(http_parser *hp);
static int reply_on_message_begin(http_parser *hp);
static int reply_on_status(http_parser *hp, const char *at, size_t length); 
static int reply_on_header_field(http_parser *hp, const char *at, size_t length); 
static int reply_on_header_value(http_parser *hp, const char *at, size_t length); 
static int reply_on_headers_complete(http_parser *hp); 
static int reply_on_body(http_parser *hp, const char *at, size_t length);
static int reply_on_message_complete(http_parser *hp); 
static void http_session_accept(struct connection_t *connection);
static void http_session_close(struct http_session_t *http_session);
static void http_client_create(struct http_session_t *http_session, struct connection_t *connection);
static void http_client_check_close(struct http_session_t *http_session, int error_code);
static void http_client_close(struct http_session_t *http_session, int error_code);
static struct buffer_t* http_session_post_alloc(struct http_session_t *http_session);
static void http_session_post_free(struct http_session_t *http_session);
static void http_session_post_append(struct http_session_t *http_session, const char *buf, size_t len);
static void http_client_read_resume(struct http_session_t *http_session);
static void http_client_header_read(struct connection_t *connection);
static void http_client_body_read(struct connection_t *connection);
static int http_client_header_process(struct http_session_t *http_session);
static void http_client_dispatch(struct http_session_t *http_session);
static void http_client_dump_header(struct http_session_t *http_session);
static void http_client_build_reply(struct http_session_t *http_session, struct http_reply_t *http_reply);
static void http_client_build_error_reply(struct http_session_t *http_session, int status_code);
static void http_client_write_resume(struct http_session_t *http_session);
static void http_client_header_write(struct connection_t *connection);
static void http_client_body_write(struct connection_t *connection);
static void http_server_create(struct http_session_t *http_session, struct http_range_t *range);
static void http_server_close(struct http_session_t *http_session, int error_code);
static void http_server_connect(void *data);
static void http_server_connect_check(struct connection_t *connection);
static void http_server_connect_done(struct http_session_t *http_session, int error);
static void http_server_write_resume(struct http_session_t *http_session);
static void http_server_header_write(struct connection_t *connection);
static void http_server_body_write(struct connection_t *connection);
static struct buffer_t* http_session_body_alloc_head(struct http_session_t *http_session);
static struct buffer_t* http_session_body_alloc(struct http_session_t *http_session);
static void http_session_body_free(struct http_session_t *http_session);
static void http_session_body_append(struct http_session_t *http_session, const char *buf, size_t len);
static void http_server_read_resume(struct http_session_t *http_session);
static void http_server_header_read(struct connection_t *connection);
static void http_server_body_read(struct connection_t *connection);
static int http_server_header_process(struct http_session_t *http_session);
static int http_server_parse_chunk(struct http_session_t *http_session, const char *buf, size_t len); 
static void http_server_dump_header(struct http_session_t *http_session);
static struct http_reply_t* http_reply_create();
static void http_reply_free(struct http_reply_t *http_reply);
static int http_request_cacheable(struct http_request_t *http_request);
static int http_reply_cacheable(struct http_reply_t *http_reply);
static void http_session_lookup_cache(struct http_session_t *http_session);

static int cache_client_header_process(struct cache_client_t *cache_client, struct http_reply_t *http_reply);
static void cache_client_create(struct http_session_t *http_session);
static void cache_client_free(struct cache_client_t *cache_client);
static void cache_client_lock(struct cache_client_t *cache_client, struct cache_t *cache);
static void cache_client_unlock(struct cache_client_t *cache_client, int del);
static struct cache_file_t* cache_file_alloc();
static void cache_file_free(struct cache_file_t *cache_file);
static void cache_client_file_open(struct cache_client_t *cache_client);
static void cache_client_file_open_exec(struct aio_t *aio);
static void cache_client_file_open_done(struct aio_t *aio);
static void cache_client_resume(struct aio_t *aio);
static void cache_client_file_close(struct cache_client_t *cache_client);
static void cache_client_file_close_exec(struct aio_t *aio);
static void cache_client_file_close_done(struct aio_t *aio);
static void cache_client_read_open_done(struct aio_t *aio);
static void cache_client_do_read(struct cache_client_t *cache_client);
static void cache_client_header_read_exec(struct aio_t *aio);
static void cache_client_header_read_done(struct aio_t *aio);
static void cache_client_dump_header(struct cache_client_t *cache_client);
static void cache_client_write_open_done(struct aio_t *aio);
static void cache_client_header_append(struct cache_client_t *cache_client);
static void cache_client_header_write_exec(struct aio_t *aio);
static void cache_client_header_write_done(struct aio_t *aio);
static void cache_client_body_append(struct cache_client_t *cache_client, struct buffer_t *buffer);
static void cache_client_body_append_end(struct cache_client_t *cache_client);
static void cache_client_bitmap_update(struct cache_client_t *cache_client);
static void cache_client_do_write(struct cache_client_t *cache_client);
static void cache_client_body_write_exec(struct aio_t *aio);
static void cache_client_body_write_done(struct aio_t *aio);
static struct cache_t* cache_alloc(const char *key);
static void cache_free(struct cache_t *cache);
static int cache_table_lock();
static int cache_table_unlock();
static struct cache_t* cache_table_lookup(const void *key);
static int cache_table_insert(struct cache_t *cache);
static int cache_table_erase(struct cache_t *cache);

http_parser_settings request_parser_settings = { 
	.on_message_begin = request_on_message_begin,
	.on_url = request_on_url,
	.on_status = NULL,
	.on_header_field = request_on_header_field,
	.on_header_value = request_on_header_value,
	.on_headers_complete = request_on_headers_complete,
	.on_body = request_on_body,
	.on_message_complete = request_on_message_complete
};

http_parser_settings reply_parser_settings = {
	.on_message_begin = reply_on_message_begin,
	.on_url = NULL,
	.on_status = reply_on_status,
	.on_header_field = reply_on_header_field,
	.on_header_value = reply_on_header_value,
	.on_headers_complete = reply_on_headers_complete,
	.on_body = reply_on_body,
	.on_message_complete = reply_on_message_complete
};

ssize_t http_recv(int s, void *buf, size_t len, int flags)
{
	return recv(s, buf, len, flags);
}
ssize_t http_send(int s, const void *buf, size_t len, int flags)
{
	return send(s, buf, len, flags);
}

void strlow(uint8_t *dst, uint8_t *src, size_t n)
{
	while (n) {
		*dst = tolower(*src);
		dst++;
		src++;
		n--;
	}   
}

const char* sockaddr_to_string(struct sockaddr *addr, char *str, int size)
{
	if (addr->sa_family == AF_INET) {
		inet_ntop(addr->sa_family, &((struct sockaddr_in *)addr)->sin_addr, str, size);
	} else if (addr->sa_family == AF_INET6) {
		inet_ntop(addr->sa_family, &((struct sockaddr_in6 *)addr)->sin6_addr, str, size);
	}
	return str;
}

static int socket_listen(const char *host, uint16_t port, int family)
{
	struct sockaddr addr;
	struct in_addr sin_addr;
	struct in6_addr sin6_addr;
	int fd = -1;
	int var = 1;
	if (inet_pton(AF_INET, host, &sin_addr) > 0) {
		((struct sockaddr_in *)&addr)->sin_family = AF_INET;
		((struct sockaddr_in *)&addr)->sin_port = htons(port);
		((struct sockaddr_in *)&addr)->sin_addr = sin_addr;
	} else if (inet_pton(AF_INET6, host, &sin6_addr) > 0) {
		((struct sockaddr_in6 *)&addr)->sin6_family = AF_INET6;
		((struct sockaddr_in6 *)&addr)->sin6_port = htons(port);
		((struct sockaddr_in6 *)&addr)->sin6_addr = sin6_addr;
	} else {
		LOG(LOG_ERROR, "%s addr error\n", host);
		return -1;
	}
	fd = socket(addr.sa_family, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0) {
		LOG(LOG_ERROR, "socket fd=%d error:%s\n", fd, strerror(errno));
		return -1;
	}
	var = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &var, sizeof(var)) == -1) {
		LOG(LOG_ERROR, "setsockopt fd=%d error:%s\n", fd, strerror(errno));
		close(fd);
		return -1;
	}
	if (bind(fd, &addr, sizeof(addr)) != 0) {
		LOG(LOG_ERROR, "listen fd=%d error:%s\n", fd, strerror(errno));
		close(fd);
		return -1;
	}
	if (listen(fd, 1024) != 0) {
		LOG(LOG_ERROR, "listen fd=%d error:%s\n", fd, strerror(errno));
		close(fd);
		return -1;
	}
	return fd;
}

int socket_non_block(int fd) 
{
	int flags, r;
	while ((flags = fcntl(fd, F_GETFL, 0)) == -1 && errno == EINTR);
	if (flags == -1) {
		return -1; 
	}   
	while ((r = fcntl(fd, F_SETFL, flags | O_NONBLOCK)) == -1 && errno == EINTR);
	if (r == -1) {
		return -1; 
	}   
	return 0;
}

static int request_on_message_begin(http_parser *hp)
{
	struct http_request_t *http_request = (struct http_request_t*)hp->data;;
	http_request->parse_state = PARSER_HEADER_NONE;
	return 0;
}

static int request_on_url(http_parser *hp, const char *at, size_t length)
{
	struct http_request_t *http_request = (struct http_request_t*)hp->data;;
	string_strncat(&http_request->url, at, length);
	return 0;
}

static int request_on_header_field(http_parser *hp, const char *at, size_t length)
{
	struct http_request_t *http_request = (struct http_request_t*)hp->data;;
	struct http_header_entry_t *header_entry = NULL;
	if (http_request->parse_state != PARSER_HEADER_FIELD) {
		http_request->parse_state = PARSER_HEADER_FIELD;
		header_entry = http_malloc(sizeof(struct http_header_entry_t));
		string_init_size(&header_entry->field_string, 64);
		string_init_size(&header_entry->value_string, 128);
		http_header_add_entry(&http_request->header, header_entry);
	} else {
		header_entry = http_header_entry_tail(&http_request->header);
	}
	string_strncat(&header_entry->field_string, at, length);
	return 0;
}

static int request_on_header_value(http_parser *hp, const char *at, size_t length)
{
	struct http_request_t *http_request = (struct http_request_t*)hp->data;;
	struct http_header_entry_t *header_entry = NULL;
	if (http_request->parse_state != PARSER_HEADER_VALUE) {
		http_request->parse_state = PARSER_HEADER_VALUE;
	} else {
	}
	header_entry = http_header_entry_tail(&http_request->header);
	string_strncat(&header_entry->value_string, at, length);
	return 0;
}

static int request_on_headers_complete(http_parser *hp)
{
	struct http_request_t *http_request = (struct http_request_t*)hp->data;
	http_request->http_major = hp->http_major;
	http_request->http_minor = hp->http_minor;
	http_request->method = hp->method;
	http_request->parse_state = PARSER_HEADER_DONE;
	return 1;
}

static int request_on_body(http_parser *hp, const char *at, size_t length)
{
	return 0;
}

static int request_on_message_complete(http_parser *hp)
{
	return 1;
}

static int reply_on_message_begin(http_parser *hp)
{
	struct http_reply_t *http_reply = hp->data;
	http_reply->parse_state = PARSER_HEADER_NONE;
	return 0;
}

static int reply_on_status(http_parser *hp, const char *at, size_t length) 
{
	return 0;
}

static int reply_on_header_field(http_parser *hp, const char *at, size_t length) 
{
	struct http_reply_t *http_reply = hp->data;
	struct http_header_entry_t *header_entry = NULL;
	if (http_reply->parse_state != PARSER_HEADER_FIELD) {
		http_reply->parse_state  = PARSER_HEADER_FIELD;
		header_entry = http_malloc(sizeof(struct http_header_entry_t));
		string_init_size(&header_entry->field_string, 64);
		string_init_size(&header_entry->value_string, 128);
		http_header_add_entry(&http_reply->header, header_entry);
	} else {
		header_entry = http_header_entry_tail(&http_reply->header);
	}
	string_strncat(&header_entry->field_string, at, length);
	return 0;
}

static int reply_on_header_value(http_parser *hp, const char *at, size_t length) 
{
	struct http_reply_t *http_reply = hp->data;
	struct http_header_entry_t *header_entry = NULL;
	if (http_reply->parse_state != PARSER_HEADER_VALUE) {
		http_reply->parse_state = PARSER_HEADER_VALUE;
	} else {
	}
	header_entry = http_header_entry_tail(&http_reply->header);
	string_strncat(&header_entry->value_string, at, length);
	return 0;
}

static int reply_on_headers_complete(http_parser *hp) 
{
	struct http_reply_t *http_reply = hp->data;
	http_reply->status_code = hp->status_code;
	http_reply->http_major = hp->http_major;
	http_reply->http_minor = hp->http_minor;
	http_reply->parse_state = PARSER_HEADER_DONE;
	return 1; 
}

static int reply_on_body(http_parser *hp, const char *at, size_t length)
{
	return 0;
}

static int reply_on_message_complete(http_parser *hp) 
{
	return 1;
}

void http_session_listen(const char *host, int port)
{
	int fd = -1;
	struct connection_t *connection = NULL;
	socklen_t addr_len = sizeof(struct sockaddr);
	fd = socket_listen(host, port, AF_INET);
	if (fd < 0) {
		LOG(LOG_ERROR, "listen_socket %s:%d error:%s\n", host, port, strerror(errno));
		return;
	}
	LOG(LOG_INFO, "listen %s:%d fd=%d\n", host, port, fd);
	socket_non_block(fd);
	connection = http_malloc(sizeof(struct connection_t));
	memset(connection, 0, sizeof(struct connection_t));
	connection->fd = fd;
	getsockname(connection->fd, &connection->local_addr, &addr_len);
	connection->epoll_thread = epoll_thread_select();
	connection_read_enable(connection, http_session_accept);
	list_add_tail(&connection->node, &connection->epoll_thread->listen_list);
}

static void http_session_accept(struct connection_t *connection)
{
	struct epoll_thread_t *epoll_thread = connection->epoll_thread;
	struct sockaddr local_addr = connection->local_addr;
	struct sockaddr peer_addr;
	struct connection_t *new_connection = NULL;
	struct http_session_t *http_session = NULL;
	socklen_t addr_len = sizeof(struct sockaddr);
	char ip_str[64] = {0};
	int fd = -1;
	fd = accept(connection->fd, (struct sockaddr*)&peer_addr, &addr_len);
	if (fd <= 0) {
		if (fd == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			LOG(LOG_DEBUG, "%s fd=%d again\n", epoll_thread->name, connection->fd);
			connection_read_done(connection);
			connection_read_enable(connection, http_session_accept);
		} else {
			LOG(LOG_ERROR, "%s fd=%d accept=%d error:%s\n", epoll_thread->name, connection->fd, fd, strerror(errno));
		}
		return;
	}
	connection_read_enable(connection, http_session_accept);
	socket_non_block(fd);
	new_connection = http_malloc(sizeof(struct connection_t));
	memset(new_connection, 0, sizeof(struct connection_t));
	new_connection->local_addr = local_addr;
	new_connection->peer_addr = peer_addr;
	new_connection->fd = fd;
	new_connection->epoll_thread = epoll_thread;
	LOG(LOG_INFO, "%s accept %s fd=%d\n", epoll_thread->name, sockaddr_to_string(&new_connection->peer_addr, ip_str, sizeof(ip_str)), new_connection->fd);

	http_session = http_malloc(sizeof(struct http_session_t));
	memset(http_session, 0, sizeof(struct http_session_t));
	http_header_init(&http_session->http_request.header);
	string_init_size(&http_session->http_request.url, 1024);
	buffer_node_pool_init(&http_session->post_free_pool, PAGE_MAX_COUNT);
	buffer_node_pool_init(&http_session->post_data_pool, 0);
	buffer_node_pool_init(&http_session->body_free_pool, PAGE_MAX_COUNT);
	buffer_node_pool_init(&http_session->body_data_pool, 0);
	http_session->epoll_thread = epoll_thread;
	list_add_tail(&http_session->node, &epoll_thread->http_session_list);
	http_client_create(http_session, new_connection);
}

void http_session_abort(struct http_session_t *http_session)
{
	struct http_request_t *http_request = &http_session->http_request;
	http_session->abort = 1;
	LOG(LOG_INFO, "%s %s abort\n", http_session->epoll_thread->name, string_buf(&http_request->url));
	if (http_session->http_client) {
		http_client_close(http_session, -1);
	} else if (http_session->http_server) {
		http_server_close(http_session, -1);
	} else {
		assert(0);
	}
}

static void http_session_close(struct http_session_t *http_session)
{
	struct http_request_t *http_request = &http_session->http_request;
	struct cache_client_t *cache_client = http_session->cache_client;
	assert(http_session->http_client == NULL);
	assert(http_session->http_server == NULL);
	list_del(&http_session->node);
	if (cache_client) {
		if (aio_busy(&cache_client->aio)) {
			LOG(LOG_INFO, "%s %s aio busy\n", http_session->epoll_thread->name, string_buf(&http_request->url));
			cache_client->http_session = NULL;
		} else {
			cache_client_unlock(cache_client, 0);
		}
		http_session->cache_client = NULL;
	}
	while (buffer_node_pool_size(&http_session->post_data_pool)) {
		http_session_post_free(http_session);
	}
	buffer_node_pool_clean(&http_session->post_free_pool);
	while (buffer_node_pool_size(&http_session->body_data_pool)) {
		http_session_body_free(http_session);
	}
	buffer_node_pool_clean(&http_session->body_free_pool);
	LOG(LOG_INFO, "%s %s\n", http_session->epoll_thread->name, string_buf(&http_request->url));
	http_header_clean(&http_request->header);
	if (http_request->range) {
		http_free(http_request->range);
	}
	string_clean(&http_request->url);
	http_free(http_session);
}

static void http_client_create(struct http_session_t *http_session, struct connection_t *connection)
{
	struct http_client_t *http_client = NULL;
	http_session->http_client = http_client = http_malloc(sizeof(struct http_client_t));
	memset(http_client, 0, sizeof(struct http_client_t));
	http_client->connection = connection;
	http_parser_init(&http_client->parser, HTTP_REQUEST);
	http_client->parser.data = &http_session->http_request;
	string_init_size(&http_client->reply_header, 1024);

	connection->arg = http_session;
	connection_read_enable(connection, http_client_header_read);
}

static void http_client_check_close(struct http_session_t *http_session, int error_code)
{
	struct http_client_t *http_client = http_session->http_client;
	if (http_session->abort) {
		http_client_close(http_session, -1);
		return;
	}
	if (string_strlen(&http_client->reply_header) == 0) {
		if (error_code) {
			http_client_build_error_reply(http_session, error_code);
			connection_write_enable(http_client->connection, http_client_header_write);
		}
	} else  {
		if (http_session->body_high > http_client->body_offset + http_client->body_send_size) {
		} else {
			http_client_close(http_session, -1);
		}
	}
}

static void http_client_close(struct http_session_t *http_session, int error_code)
{
	struct http_request_t *http_request = &http_session->http_request;
	struct http_client_t *http_client = http_session->http_client;
	struct connection_t *connection = http_client->connection;
	LOG(LOG_INFO, "%s %s fd=%d body_send_size=%"PRId64" body_expect_size=%"PRId64" body_offset=%"PRId64" error_code=%d\n",
			http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd,
			http_client->body_send_size , http_client->body_expect_size, http_client->body_offset, error_code);
	connection_close(connection, CONNECTION_FREE_DELAY);
	string_clean(&http_client->reply_header);
	http_free(http_client);
	http_session->http_client = NULL;
	if (http_session->http_server) {
		if (http_session->abort) {
			http_server_close(http_session, -1);
		} else {
			http_server_read_resume(http_session);//continue read body if need
		}
	} else {
		http_session_close(http_session);
	}
}

static struct buffer_t* http_session_post_alloc(struct http_session_t *http_session)
{
	struct buffer_node_t *buffer_node = NULL;
	struct buffer_t *buffer = NULL;
	buffer_node = buffer_node_pool_tail(&http_session->post_data_pool);
	if (buffer_node) {
		buffer = buffer_node->buffer;
		if (!buffer_full(buffer)) {
			return buffer;
		}
	}
	if (buffer_node_pool_size(&http_session->post_free_pool) == 0) {
		return NULL;
	} else {
		buffer_node_pool_pop(&http_session->post_free_pool, &buffer_node);
		buffer = buffer_alloc(PAGE_SIZE);
		buffer_node->buffer = buffer;
		buffer_node_pool_push(&http_session->post_data_pool, buffer_node);
		return buffer;
	}
}

static void http_session_post_free(struct http_session_t *http_session)
{
	struct http_request_t *http_request = &http_session->http_request;
	struct buffer_node_t *buffer_node = NULL;
	struct buffer_t *buffer = NULL;
	buffer_node_pool_pop(&http_session->post_data_pool, &buffer_node);
	buffer = buffer_node->buffer;
	buffer_node->buffer = NULL;
	http_session->post_low += buffer->len;
	buffer_node_pool_push(&http_session->post_free_pool, buffer_node);
	LOG(LOG_DEBUG, "%s %s size=%d len=%d\n", http_session->epoll_thread->name, string_buf(&http_request->url), buffer->size, buffer->len);
	buffer_unref(buffer);
}

static void http_session_post_append(struct http_session_t *http_session, const char *buf, size_t len)
{
	struct http_request_t *http_request = &http_session->http_request;
	struct http_client_t *http_client = http_session->http_client;
	struct connection_t *connection = http_client->connection;
	struct buffer_t *buffer = NULL;
	size_t ncopy = 0;
	while (len > 0) {
		buffer = http_session_post_alloc(http_session);
		assert(buffer != NULL);
		ncopy = buffer->size - buffer->len;
		if (ncopy > len) {
			ncopy = len;
		}
		memcpy(buffer->buf + buffer->len, buf, ncopy);
		buf += ncopy;
		len -= ncopy;
		buffer->len += ncopy;
		http_session->post_high += ncopy;
		LOG(LOG_DEBUG, "%s %s fd=%d ncopy=%d\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd, ncopy);
	}
}

static void http_client_read_resume(struct http_session_t *http_session)
{
	struct http_request_t *http_request = &http_session->http_request;
	struct http_client_t *http_client = http_session->http_client;
	if (http_client) {
		if (http_request->parse_state < PARSER_HEADER_DONE) {
			connection_read_enable(http_client->connection, http_client_header_read);
		} else if (buffer_node_pool_size(&http_session->post_free_pool) >= buffer_node_pool_size(&http_session->post_data_pool)) {
			connection_read_enable(http_client->connection, http_client_body_read);
		}
	}
}

static void http_client_header_read(struct connection_t *connection)
{
	struct http_session_t *http_session = connection->arg;
	struct http_request_t *http_request = &http_session->http_request;
	struct http_client_t *http_client = http_session->http_client;
	char buf[PAGE_SIZE];
	ssize_t nread = 0;
	size_t nparse = 0;
	const char *str = NULL;
	assert(connection == http_client->connection);
	assert(connection->epoll_thread == http_session->epoll_thread);
	nread = http_recv(connection->fd, buf, sizeof(buf), 0);
	if (nread <= 0) {
		if (nread == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			LOG(LOG_DEBUG, "%s %s fd=%d nread=%d again\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd, nread);
			connection_read_done(connection);
			connection_read_enable(connection, http_client_header_read);
		} else {
			LOG(LOG_DEBUG, "%s %s fd=%d nread=%d error:%s\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd, nread, strerror(errno));
			http_client_close(http_session, -1);
		}
		return;
	}
	LOG(LOG_DEBUG, "%s %s fd=%d nread=%d\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd, nread);
	nparse = http_parser_execute(&http_client->parser, &request_parser_settings, buf, nread);
	if (nparse < nread && http_request->parse_state < PARSER_HEADER_DONE) {
		LOG(LOG_DEBUG, "%s http_parser_execute nparse=%d\n", http_session->epoll_thread->name, nparse);
		http_client_build_error_reply(http_session, 400);
		connection_write_enable(connection, http_client_header_write);
		return;
	}
	if (http_request->parse_state < PARSER_HEADER_DONE) {
		connection_read_enable(connection, http_client_header_read);
		return;
	}
	if (strncmp(string_buf(&http_request->url), "http://", sizeof("http://") - 1) != 0) {
		if (http_request->method != HTTP_CONNECT) {
			str = http_header_find(&http_request->header, "Host");
			if (str) {
				struct string_t uri;
				string_init_str(&uri, string_buf(&http_request->url));
				string_clean(&http_request->url);
				string_init_size(&http_request->url, 1024);
				string_strcat(&http_request->url, "http://");
				string_strcat(&http_request->url, str);
				string_strcat(&http_request->url, string_buf(&uri));
				string_clean(&uri);
			} else {
				http_client_build_error_reply(http_session, 400);
				connection_write_enable(connection, http_client_header_write);
				return;
			}
		}
	}
	http_client_dump_header(http_session);
	if (http_client_header_process(http_session)) {
		http_client_build_error_reply(http_session, 400);
		connection_write_enable(connection, http_client_header_write);
		return;
	}
	if (nread > nparse) {
		http_session_post_append(http_session, buf + nparse, nread - nparse);
	}
	connection_read_enable(connection, http_client_body_read);
	http_session_lookup_cache(http_session);
}

static void http_client_body_read(struct connection_t *connection)
{
	struct http_session_t *http_session = connection->arg;
	struct http_request_t *http_request = &http_session->http_request;
	struct http_client_t *http_client = http_session->http_client;
	struct buffer_t *buffer = NULL;
	char *buf = NULL;
	size_t len = 0;
	ssize_t nread = 0;
	size_t total_read = 0;
	int error = 0;
	assert(connection == http_client->connection);
	assert(connection->epoll_thread == http_session->epoll_thread);
	while ((buffer = http_session_post_alloc(http_session)) && total_read < MAX_READ) {
		buf = buffer->buf + buffer->len;
		len = buffer->size - buffer->len;
		nread = http_recv(connection->fd, buf, len, 0);
		if (nread <= 0) {
			if (nread == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
				LOG(LOG_DEBUG, "%s %s fd=%d nread=%d again\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd, nread);
				connection_read_done(connection);
			} else {
				LOG(LOG_DEBUG, "%s %s fd=%d nread=%d error:%s\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd, nread, strerror(errno));
				error = -1;
			}
			break;
		}
		total_read += nread;
		buffer->len += nread;
		http_session->post_high += nread;
	}
	LOG(LOG_DEBUG, "%s %s fd=%d total_read=%d\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd, total_read);
	if (total_read > 0) {
		http_server_write_resume(http_session);
	}
	if (error) {
		http_client_close(http_session, error);
		return;
	}
	if (http_session->body_high >= http_request->content_length) {
		LOG(LOG_DEBUG, "%s %s fd=%d read done\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd);
	}
	if (buffer) {
		connection_read_enable(connection, http_client_body_read);
	} else {
		LOG(LOG_DEBUG, "%s %s fd=%d buffer full\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd);
		connection_read_disable(connection);
	}
}

static int http_client_header_process(struct http_session_t *http_session)
{
	struct http_request_t *http_request = &http_session->http_request;
	struct http_client_t *http_client = http_session->http_client;
	const char *str = NULL;
	str = http_header_find(&http_request->header, "Content-Length");
	if (str) {
		http_request->content_length = atol(str);
		//http_client->post_expect_size = http_request->content_length;
	}
	http_session->post_low = http_session->post_high = 0;
	if (http_request->http_minor >= 1) {
		http_client->keep_alive = 1;
	}
	str = http_header_find(&http_request->header, "Proxy-Connection");
	if (str) {
		if (strcasecmp(str, "Keep-Alive") == 0) {
			http_client->keep_alive = 1;
		} else if (strcasecmp(str, "Close") == 0) {
			http_client->keep_alive = 0;
		}
		http_header_del(&http_request->header, "Proxy-Connection");
	}
	str = http_header_find(&http_request->header, "Range");
	if (str) {
		http_request->range = http_range_parse(str, strlen(str));
		if (http_request->range == NULL) {
			LOG(LOG_ERROR, "%s %s error Range: %s\n", http_session->epoll_thread->name, string_buf(&http_request->url), str);
			return -1;
		}    
	}
	return 0;
}

static void http_client_dispatch(struct http_session_t *http_session)
{
}

static void http_client_dump_header(struct http_session_t *http_session)
{
	struct http_request_t *http_request = &http_session->http_request;
	struct http_header_entry_t *header_entry;
	struct string_t string;
	string_init_size(&string, 1024);
	string_strcat_printf(&string, "%s %s HTTP/%d.%d\r\n", http_method_str(http_request->method),
			string_buf(&http_request->url), http_request->http_major, http_request->http_minor);
	list_for_each_entry(header_entry, &http_request->header.header_list, header_entry_node) {
		string_strcat(&string, string_buf(&header_entry->field_string));
		string_strcat(&string, ": ");
		string_strcat(&string, string_buf(&header_entry->value_string));
		string_strcat(&string, "\r\n");
	}    
	string_strcat(&string, "\r\n"); 
	LOG(LOG_INFO, "%s %s request=\n%s", http_session->epoll_thread->name, string_buf(&http_request->url), string_buf(&string));
	string_clean(&string);
}

static void http_client_build_reply(struct http_session_t *http_session, struct http_reply_t *http_reply)
{
	struct http_request_t *http_request = &http_session->http_request;
	struct http_client_t *http_client = http_session->http_client;
	struct http_header_entry_t *header_entry = NULL;
	int status_code = http_reply->status_code;
	int64_t offset;
	int64_t length;
	assert(string_strlen(&http_client->reply_header) == 0);
	if (http_request->range && http_reply->status_code == 200 && http_reply->content_length > 0) {
		offset = http_request->range->offset;
		length = http_request->range->length;
		if (offset == -1) {
			assert(length >= 0);
			if (length > http_reply->content_length) {
				length = http_reply->content_length;
			}
			offset = http_reply->content_length - length;
		}
		if (offset >= http_reply->content_length) {
			status_code = 416;
			offset = 0;
			length = 0;
		} else {
			if (length == -1 || length > http_reply->content_length - offset) {
				length = http_reply->content_length - offset;
			}
			status_code = 206;
		}
	} else {
		offset = 0;
		length = http_reply->content_length;
	}
	LOG(LOG_DEBUG, "%s %s offset=%"PRId64" length=%"PRId64"\n", http_session->epoll_thread->name, string_buf(&http_request->url), offset, length);
	string_strcat_printf(&http_client->reply_header, "HTTP/%d.%d %s\r\n",
			http_reply->http_major, http_reply->http_minor, http_status_reasons_get(status_code));
	list_for_each_entry(header_entry, &http_reply->header.header_list, header_entry_node) {
		if (strcasecmp("Content-Length", string_buf(&header_entry->field_string)) == 0 ||
				strcasecmp("Content-Range", string_buf(&header_entry->field_string)) == 0) {
			continue;
		}
		string_strcat(&http_client->reply_header, string_buf(&header_entry->field_string));
		string_strcat(&http_client->reply_header, ": ");
		string_strcat(&http_client->reply_header, string_buf(&header_entry->value_string));
		string_strcat(&http_client->reply_header, "\r\n");
	}    
	if (status_code == 206) {
		http_client->body_offset = offset;
		http_client->body_expect_size = length;
		string_strcat_printf(&http_client->reply_header, "Content-Range: bytes %"PRId64"-%"PRId64"/%"PRId64"\r\n", offset, offset + length -1, http_reply->content_length);
		string_strcat_printf(&http_client->reply_header, "Content-Length: %"PRId64"\r\n", length);
	} else {
		http_client->body_offset = 0;
		if (length >= 0) {
			string_strcat_printf(&http_client->reply_header, "Content-Length: %"PRId64"\r\n", length);
			http_client->body_expect_size = length;
		} else {
			http_client->body_expect_size = INT64_MAX;
		}
	}
	string_strcat(&http_client->reply_header, "Via: http_cache\r\n");
	string_strcat(&http_client->reply_header, "\r\n");
	LOG(LOG_INFO, "%s %s reply=\n%s", http_session->epoll_thread->name, string_buf(&http_request->url), string_buf(&http_client->reply_header));
}

static void http_client_build_error_reply(struct http_session_t *http_session, int status_code)
{
	struct http_request_t *http_request = &http_session->http_request;
	struct http_client_t *http_client = http_session->http_client;
	assert(string_strlen(&http_client->reply_header) == 0);
	http_client->body_offset = 0;
	http_client->body_expect_size = 0;
	string_strcat_printf(&http_client->reply_header, "HTTP/%d.%d %s\r\n", 1, 1, http_status_reasons_get(status_code));
	string_strcat(&http_client->reply_header, "Via: cache_client\r\n");
	string_strcat(&http_client->reply_header, "\r\n");
	LOG(LOG_INFO, "%s %s reply=\n%s", http_session->epoll_thread->name, string_buf(&http_request->url), string_buf(&http_client->reply_header));
}

static void http_client_write_resume(struct http_session_t *http_session)
{
	struct http_client_t *http_client = http_session->http_client;
	struct buffer_node_t *buffer_node = NULL;
	struct buffer_t *buffer = NULL;
	if (http_client) {
		if (string_strlen(&http_client->reply_header) > http_client->reply_header_send_size) {
			connection_write_enable(http_client->connection, http_client_header_write);
		} else {
			connection_write_enable(http_client->connection, http_client_body_write);
		}
	} else {
		while ((buffer_node = buffer_node_pool_head(&http_session->body_data_pool))) {
			buffer = buffer_node->buffer;
			if (buffer_full(buffer)) {
				http_session_body_free(http_session);
			} else {
				break;
			}
		}
	}	
}

static void http_client_header_write(struct connection_t *connection)
{
	struct http_session_t *http_session = connection->arg;
	struct http_request_t *http_request = &http_session->http_request;
	struct http_client_t *http_client = http_session->http_client;
	char *buf = NULL;
	size_t len = 0;
	ssize_t nwrite = 0;
	assert(connection == http_client->connection);
	assert(connection->epoll_thread == http_session->epoll_thread);
	buf = string_buf(&http_client->reply_header) + http_client->reply_header_send_size;
	len = string_strlen(&http_client->reply_header) - http_client->reply_header_send_size;
	nwrite = http_send(connection->fd, buf, len, 0);
	if (nwrite <= 0) {
		if (nwrite == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			LOG(LOG_DEBUG, "%s %s fd=%d nwrite=%d again\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd, nwrite);
			connection_write_done(connection);
		} else {
			LOG(LOG_DEBUG, "%s %s fd=%d send=%d error:%s\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd, nwrite, strerror(errno));
			http_client_close(http_session, -1);
			return;
		}
	}
	LOG(LOG_DEBUG, "%s %s fd=%d nwrite=%d\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd, nwrite);
	http_client->reply_header_send_size += nwrite;
	if (http_client->reply_header_send_size < string_strlen(&http_client->reply_header)) {
		connection_write_enable(connection, http_client_header_write);//read write next event loop
	} else {
		http_client_body_write(connection);
	}
}

static void http_client_body_write(struct connection_t *connection)
{
	struct http_session_t *http_session = connection->arg;
	struct http_request_t *http_request = &http_session->http_request;
	struct http_client_t *http_client = http_session->http_client;
	struct buffer_node_t *buffer_node = NULL;
	struct buffer_t *buffer = NULL;
	char *buf = NULL;
	size_t len = 0;
	ssize_t nwrite = 0;
	size_t total_write = 0;
	int error = 0;
	int64_t body_pos = 0;
	assert(connection == http_client->connection);
	assert(connection->epoll_thread == http_session->epoll_thread);
	while ((buffer_node = buffer_node_pool_head(&http_session->body_data_pool)) && http_client->body_expect_size > 0 && total_write < MAX_WRITE) {
		buffer = buffer_node->buffer;
		body_pos = http_client->body_offset + http_client->body_send_size;
		if (body_pos >= http_session->body_low + buffer->len) {
			if (buffer_full(buffer)) {
				http_session_body_free(http_session);
				continue;
			} else {
				buffer_node = NULL;
				break;
			}
		}
		nwrite = (ssize_t)(body_pos - http_session->body_low);
		buf = buffer->buf + nwrite;
		len = buffer->len - nwrite;
		nwrite = http_send(connection->fd, buf, MIN(len, http_client->body_expect_size), 0);
		if (nwrite <= 0) {
			if (nwrite == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
				LOG(LOG_DEBUG, "%s %s fd=%d nwrite=%d again\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd, nwrite);
				connection_write_done(connection);
			} else {
				LOG(LOG_DEBUG, "%s %s fd=%d send=%d error:%s\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd, nwrite, strerror(errno));
				error = -1;
			}
			break;
		}
		if (buffer_full(buffer) && buf + nwrite == buffer->buf + buffer->len) {
			http_session_body_free(http_session);
		}
		http_client->body_send_size += nwrite;
		http_client->body_expect_size -= nwrite;
		total_write += nwrite;
	}
	LOG(LOG_DEBUG, "%s %s fd=%d total_write=%d\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd, total_write);
	http_server_read_resume(http_session);
	if (error == 0 && http_client->body_expect_size > 0) {
		if (buffer_node) {
			connection_write_enable(connection, http_client_body_write);//read write next event loop
		} else {
			LOG(LOG_DEBUG, "%s %s fd=%d buffer empty\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd);
			connection_write_disable(connection);
		}
	} else {
		LOG(LOG_DEBUG, "%s %s fd=%d client write done\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd);
		http_client_close(http_session, error);
	}
}

static void http_server_create(struct http_session_t *http_session, struct http_range_t *range)
{
	struct http_request_t *http_request = &http_session->http_request;
	struct http_client_t *http_client = http_session->http_client;
	struct http_server_t *http_server = NULL;
	struct http_header_entry_t *header_entry = NULL;
	struct http_parser_url parser_url;
	char *path = "/"; 
	char str[256];
	struct string_t host;
	if (http_parser_parse_url(string_buf(&http_request->url), string_strlen(&http_request->url), http_request->method == HTTP_CONNECT, &parser_url)) {
		LOG(LOG_ERROR, "%s %s http_parser_parse_url error\n", http_session->epoll_thread->name, string_buf(&http_request->url));
		if (string_strlen(&http_client->reply_header) == 0) {
			http_client_build_error_reply(http_session, 400);
			connection_write_enable(http_client->connection, http_client_header_write);
		} else {
			http_client_close(http_session, -1);
		}
		return;
	}
	http_session->http_server = http_server = http_malloc(sizeof(struct http_server_t));
	memset(http_server, 0, sizeof(struct http_server_t));
	if (http_request->content_length >= 0) {
		http_server->post_expect_size = http_request->content_length;
	}
	if (range) {
		http_server->range = http_malloc(sizeof(struct http_range_t));
		http_server->range->offset = range->offset;
		http_server->range->length = range->length;
	}
	http_server->port = 80;
	if (parser_url.field_set & (1 << UF_PORT)) {
		http_server->port = parser_url.port;
	} 
	string_init_size(&http_server->request_header, 1024);
	if (parser_url.field_set & (1 << UF_PATH)) {
		path = string_buf(&http_request->url) + parser_url.field_data[UF_PATH].off;
	}    
	string_strcat_printf(&http_server->request_header, "%s %s HTTP/%d.%d\r\n", http_method_str(http_request->method),
			path, http_request->http_major, http_request->http_minor);
	list_for_each_entry(header_entry, &http_request->header.header_list, header_entry_node) {
		if (strcasecmp("Range", string_buf(&header_entry->field_string)) == 0) {
			continue;
		}
		string_strcat(&http_server->request_header, string_buf(&header_entry->field_string));
		string_strcat(&http_server->request_header, ": ");
		string_strcat(&http_server->request_header, string_buf(&header_entry->value_string));
		string_strcat(&http_server->request_header, "\r\n");
	}    
	if (http_server->range) {
		if (http_server->range->offset == -1) {
			snprintf(str, sizeof(str), "Range: bytes=-%"PRId64"\r\n", http_server->range->length);
		} else if (http_server->range->length == -1) {
			snprintf(str, sizeof(str), "Range: bytes=%"PRId64"-\r\n", http_server->range->offset);
		} else {
			snprintf(str, sizeof(str), "Range: bytes=%"PRId64"-%"PRId64"\r\n", http_server->range->offset, http_server->range->offset + http_server->range->length - 1);
		}
		string_strcat(&http_server->request_header, str);
	}    
	string_strcat(&http_server->request_header, "\r\n"); 
	LOG(LOG_INFO, "%s %s request=\n%s\n", http_session->epoll_thread->name, string_buf(&http_request->url), string_buf(&http_server->request_header));
	http_parser_init(&http_server->parser, HTTP_RESPONSE);
	http_server->parser.data = http_reply_create();

	string_init_size(&host, 1024);
	string_strncat(&host, string_buf(&http_request->url) + parser_url.field_data[UF_HOST].off, parser_url.field_data[UF_HOST].len);
	http_server->continuation.callback_data = http_session;
	http_server->continuation.callback = http_server_connect;
	http_server->continuation.buf = &http_server->dns_info;
	dns_session_query(http_session->epoll_thread->dns_session, string_buf(&host), &http_server->continuation);
	string_clean(&host);
}

static void http_server_close(struct http_session_t *http_session, int error_code)
{
	struct http_request_t *http_request = &http_session->http_request;
	struct http_server_t *http_server = http_session->http_server;
	struct connection_t *connection = http_server->connection;
	LOG(LOG_INFO, "%s %s fd=%d body_recv_size=%"PRId64" body_expect_size=%"PRId64" body_offset=%"PRId64" error_code=%d\n",
			http_session->epoll_thread->name, string_buf(&http_request->url), connection? connection->fd:0,
			http_session->body_high - http_server->body_offset, http_server->body_expect_size, http_server->body_offset, error_code);
	if (connection) {
		connection_close(connection, CONNECTION_FREE_DELAY);
	}
	if (http_server->range) {
		http_free(http_server->range);
	}
	string_clean(&http_server->request_header);
	if (http_server->parser.data) {
		http_reply_free(http_server->parser.data);
	}
	dns_info_clean(&http_server->dns_info);
	http_free(http_server);
	http_session->http_server = NULL;
	if (http_session->cache_client) {
		cache_client_body_append_end(http_session->cache_client);
	}
	if (http_session->http_client) {
		http_client_check_close(http_session, error_code);
	} else {
		http_session_close(http_session);
	}
}

static void http_server_connect(void *data)
{
	struct http_session_t *http_session = data;
	struct http_request_t *http_request = &http_session->http_request;
	struct http_server_t *http_server = http_session->http_server;
	struct connection_t *connection = NULL;
	socklen_t addr_len = sizeof(struct sockaddr);
	int fd;
	char ip_str[64] = {0};
	int i, r;
	for (i = 0; i < http_server->dns_info.ipv4_num; i++) {
		inet_ntop(AF_INET, &http_server->dns_info.sin_addrs[i], ip_str, sizeof(ip_str));
		LOG(LOG_INFO, "%s %s ipv4[%d]=%s\n", http_session->epoll_thread->name, string_buf(&http_request->url), i, ip_str);
	}
	for (i = 0; i < http_server->dns_info.ipv6_num; i++) {
		inet_ntop(AF_INET6, &http_server->dns_info.sin6_addrs[i], ip_str, sizeof(ip_str));
		LOG(LOG_INFO, "%s %s ipv6[%d]=%s\n", http_session->epoll_thread->name, string_buf(&http_request->url), i, ip_str);
	}
	fd = socket(AF_INET , SOCK_STREAM, 0);
	if (fd < 0) {
		LOG(LOG_ERROR, "%s %s socket fd=%d error:%s\n", http_session->epoll_thread->name, string_buf(&http_request->url), fd, strerror(errno));
		http_server_close(http_session, 503);
		return;
	}
	connection = http_malloc(sizeof(struct connection_t));
	memset(connection, 0, sizeof(struct connection_t));
	connection->fd = fd;
	if (http_server->dns_info.ipv4_num > 0) {
		((struct sockaddr_in *)&connection->peer_addr)->sin_family = AF_INET;
		((struct sockaddr_in *)&connection->peer_addr)->sin_port = htons(http_server->port);
		((struct sockaddr_in *)&connection->peer_addr)->sin_addr.s_addr = http_server->dns_info.sin_addrs[0].s_addr;
	}
	getsockname(connection->fd, &connection->local_addr, &addr_len);
	socket_non_block(connection->fd);
	connection->arg = http_session;
	connection->epoll_thread = http_session->epoll_thread;
	http_server->connection = connection;
	r = connect(connection->fd, &connection->peer_addr, sizeof(struct sockaddr));
	if (r == 0) {
		http_server_connect_done(http_session, 0);
	} else if (errno == EINPROGRESS) {
		connection_write_enable(connection, http_server_connect_check);
	} else {
		http_server_connect_done(http_session, -1);
	}
}

static void http_server_connect_check(struct connection_t *connection)
{
	struct http_session_t *http_session = connection->arg;
	struct http_server_t *http_server = http_session->http_server;
	socklen_t len = sizeof(int);
	int error = 0;
	assert(connection == http_server->connection);
	assert(connection->epoll_thread == http_session->epoll_thread);
	if (getsockopt(connection->fd, SOL_SOCKET, SO_ERROR, &error, &len) || error) {
		http_server_connect_done(http_session, -1);
	} else {
		http_server_connect_done(http_session, 0);
	}
}

static void http_server_connect_done(struct http_session_t *http_session, int error)
{
	struct http_request_t *http_request = &http_session->http_request;
	struct http_server_t *http_server = http_session->http_server;
	struct connection_t *connection = http_server->connection;
	char ip_str[64] = {0};
	uint16_t port = ntohs(((struct sockaddr_in *)&connection->peer_addr)->sin_port);
	sockaddr_to_string(&connection->peer_addr, ip_str, sizeof(ip_str));
	if (error) {
		LOG(LOG_INFO, "%s %s fd=%d connect to %s:%d fail\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd, ip_str, port);
		http_server_close(http_session, 503);
		return;
	}
	LOG(LOG_INFO, "%s %s fd=%d connect to %s:%d ok\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd, ip_str, port);
	http_server->connected = 1;
	connection_read_enable(connection, http_server_header_read);
	connection_write_enable(connection, http_server_header_write);
}

static void http_server_write_resume(struct http_session_t *http_session)
{
	struct http_server_t *http_server = http_session->http_server;
	if (http_server && http_server->connection && http_server->connected) {
		if (string_strlen(&http_server->request_header) > http_server->request_header_send_size) {
			connection_write_enable(http_server->connection, http_server_header_write);
		} else if (http_server->post_expect_size > 0) {
			connection_write_enable(http_server->connection, http_server_body_write);
		}
	}
}

static void http_server_header_write(struct connection_t *connection)
{
	struct http_session_t *http_session = connection->arg;
	struct http_request_t *http_request = &http_session->http_request;
	struct http_server_t *http_server = http_session->http_server;
	char *buf = NULL;
	ssize_t len = 0;
	ssize_t nwrite = 0;
	assert(connection == http_server->connection);
	assert(connection->epoll_thread == http_session->epoll_thread);
	buf = string_buf(&http_server->request_header) + http_server->request_header_send_size;
	len = string_strlen(&http_server->request_header) - http_server->request_header_send_size;
	nwrite = http_send(connection->fd, buf, len, 0);
	if (nwrite <= 0) {
		if (nwrite == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			LOG(LOG_DEBUG, "%s %s fd=%d nwrite=%d again\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd, nwrite);
			connection_write_done(connection);
		} else {
			LOG(LOG_DEBUG, "%s %s fd=%d send=%d error:%s\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd, nwrite, strerror(errno));
			http_server_close(http_session, -1);
			return;
		}
	}
	LOG(LOG_DEBUG, "%s %s fd=%d nwrite=%d\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd, nwrite);
	http_server->request_header_send_size += nwrite;
	if (string_strlen(&http_server->request_header) > http_server->request_header_send_size) {
		connection_write_enable(connection, http_server_header_write);//read write next event loop
	} else {
		http_server_body_write(connection);
	}
}

static void http_server_body_write(struct connection_t *connection)
{
	struct http_session_t *http_session = connection->arg;
	struct http_request_t *http_request = &http_session->http_request;
	struct http_server_t *http_server = http_session->http_server;
	struct buffer_node_t *buffer_node = NULL;
	struct buffer_t *buffer = NULL;
	char *buf = NULL;
	ssize_t len = 0;
	ssize_t nwrite = 0;
	size_t total_write = 0;
	int error = 0;
	int64_t post_pos = 0;
	assert(connection == http_server->connection);
	assert(connection->epoll_thread == http_session->epoll_thread);
	while ((buffer_node = buffer_node_pool_head(&http_session->post_data_pool)) && http_server->post_expect_size > 0 && total_write < MAX_WRITE) {
		buffer = buffer_node->buffer;
		post_pos = 0 + http_server->post_send_size;
		if (post_pos >= http_session->post_low + buffer->len) {
			if (buffer_full(buffer)) {
				http_session_post_free(http_session);
				continue;
			} else {
				buffer_node = NULL;
				break;
			}
		}
		nwrite = (ssize_t)(post_pos - http_session->post_low);
		buf = buffer->buf + nwrite;
		len = buffer->len - nwrite;
		nwrite = http_send(connection->fd, buf, MIN(len, http_server->post_expect_size), 0);
		if (nwrite <= 0) {
			if (nwrite == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
				LOG(LOG_DEBUG, "%s %s fd=%d nwrite=%d again\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd, nwrite);
				connection_write_done(connection);
			} else {
				LOG(LOG_DEBUG, "%s %s fd=%d send=%d error:%s\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd, nwrite, strerror(errno));
				error = -1;
			}
			break;
		}
		http_server->post_send_size += nwrite;
		http_server->post_expect_size -= nwrite;
		if (buffer_full(buffer) && buf + nwrite == buffer->buf + buffer->len) {
			http_session_post_free(http_session);
		}
	}
	LOG(LOG_DEBUG, "%s %s fd=%d total_write=%d\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd, total_write);
	http_client_read_resume(http_session);
	if (error) {
		http_server_close(http_session, error);
		return;
	}
	if (http_server->post_expect_size > 0) {
		if (buffer_node) {
			connection_write_enable(connection, http_server_body_write);//read write next event loop
		} else {
			LOG(LOG_DEBUG, "%s %s fd=%d buffer empty\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd);
			connection_write_disable(connection);
		}
	} else {
		LOG(LOG_DEBUG, "%s %s fd=%d request write done\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd);
		connection_write_disable(connection);
	}
}

static struct buffer_t* http_session_body_alloc_head(struct http_session_t *http_session)
{
	struct buffer_node_t *buffer_node = NULL;
	struct buffer_t *buffer = NULL;
	assert(buffer_node_pool_size(&http_session->body_data_pool) == 0);
	assert(buffer_node_pool_size(&http_session->body_free_pool) > 0);
	buffer_node_pool_pop(&http_session->body_free_pool, &buffer_node);
	buffer = buffer_alloc(PAGE_SIZE - http_session->body_low % PAGE_SIZE);
	buffer_node->buffer = buffer;
	buffer_node_pool_push(&http_session->body_data_pool, buffer_node);
	return buffer;
}

static struct buffer_t* http_session_body_alloc(struct http_session_t *http_session)
{
	struct cache_client_t *cache_client = http_session->cache_client;
	struct buffer_node_t *buffer_node = NULL;
	struct buffer_t *buffer = NULL;
	if (cache_client && buffer_node_pool_size(&cache_client->body_free_pool) == 0) {
		return NULL;
	}
	buffer_node = buffer_node_pool_tail(&http_session->body_data_pool);
	if (buffer_node) {
		buffer = buffer_node->buffer;
		if (!buffer_full(buffer)) {
			return buffer;
		}
	}
	if (buffer_node_pool_size(&http_session->body_free_pool) == 0) {
		return NULL;
	} else {
		buffer_node_pool_pop(&http_session->body_free_pool, &buffer_node);
		buffer = buffer_alloc(PAGE_SIZE);
		buffer_node->buffer = buffer;
		buffer_node_pool_push(&http_session->body_data_pool, buffer_node);
		return buffer;
	}
}

static void http_session_body_free(struct http_session_t *http_session)
{
	//struct http_request_t *http_request = &http_session->http_request;
	struct buffer_node_t *buffer_node = NULL;
	struct buffer_t *buffer = NULL;
	buffer_node_pool_pop(&http_session->body_data_pool, &buffer_node);
	buffer = buffer_node->buffer;
	buffer_node->buffer = NULL;
	http_session->body_low += buffer->len;
	buffer_node_pool_push(&http_session->body_free_pool, buffer_node);
	//LOG(LOG_DEBUG, "%s %s size=%d len=%d\n", http_session->epoll_thread->name, string_buf(&http_request->url), buffer->size, buffer->len);
	buffer_unref(buffer);
}

static void http_session_body_append(struct http_session_t *http_session, const char *buf, size_t len)
{
	struct http_request_t *http_request = &http_session->http_request;
	struct http_server_t *http_server = http_session->http_server;
	struct connection_t *connection = http_server->connection;
	struct buffer_t *buffer = NULL;
	size_t ncopy = 0;
	while (len > 0) {
		buffer = http_session_body_alloc(http_session);
		assert(buffer != NULL);
		ncopy = buffer->size - buffer->len;
		if (ncopy > len) {
			ncopy = len;
		}
		memcpy(buffer->buf + buffer->len, buf, ncopy);
		buf += ncopy;
		len -= ncopy;
		buffer->len += ncopy;
		http_session->body_high += ncopy;
		http_server->body_expect_size -= ncopy;
		if (buffer_full(buffer) && http_session->cache_client) {
			cache_client_body_append(http_session->cache_client, buffer);
		}
		LOG(LOG_DEBUG, "%s %s fd=%d ncopy=%d\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd, ncopy);
	}
}

static void http_server_read_resume(struct http_session_t *http_session)
{
	struct http_server_t *http_server = http_session->http_server;
	struct http_reply_t *http_reply = NULL;
	if (http_server && http_server->connection && http_server->connected) {
		http_reply = http_server->parser.data;
		if (http_reply && http_reply->parse_state < PARSER_HEADER_DONE) {
			connection_read_enable(http_server->connection, http_server_header_read);
		} else if (http_server->body_expect_size > 0) {
			if (buffer_node_pool_size(&http_session->body_free_pool) >= buffer_node_pool_size(&http_session->body_data_pool)) {
				connection_read_enable(http_server->connection, http_server_body_read);
			}
		}
	}
}

static void http_server_header_read(struct connection_t *connection)
{
	struct http_session_t *http_session = connection->arg;
	struct http_request_t *http_request = &http_session->http_request;
	struct http_server_t *http_server = http_session->http_server;
	struct http_reply_t *http_reply = http_server->parser.data;
	char buf[PAGE_SIZE];
	ssize_t nread = 0;
	size_t nparse = 0;
	size_t body_size = 0;
	assert(connection == http_server->connection);
	assert(connection->epoll_thread == http_session->epoll_thread);
	nread = http_recv(connection->fd, buf, sizeof(buf), 0);
	if (nread <= 0) {
		if (nread == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			LOG(LOG_DEBUG, "%s %s fd=%d nread=%d again\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd, nread);
			connection_read_done(connection);
			connection_read_enable(connection, http_server_header_read);
		} else {
			LOG(LOG_DEBUG, "%s %s fd=%d nread=%d error:%s\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd, nread, strerror(errno));
			http_server_close(http_session, 503);
		}
		return;
	}
	LOG(LOG_DEBUG, "%s %s fd=%d nread=%d\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd, nread);
	nparse = http_parser_execute(&http_server->parser, &reply_parser_settings, buf, nread);
	if (nparse < nread && http_reply->parse_state < PARSER_HEADER_DONE) {
		LOG(LOG_ERROR, "%s %s http_parser_execute nparse=%d\n", http_session->epoll_thread->name, string_buf(&http_request->url), nparse);
		http_server_close(http_session, 400);
		return;
	}
	if (http_reply->parse_state < PARSER_HEADER_DONE) {
		connection_read_enable(connection, http_server_header_read);
		return;
	}
	http_server_dump_header(http_session);
	if (http_server_header_process(http_session)) {
		http_server_close(http_session, 503);
		return;
	}
	http_session_body_alloc_head(http_session);
	if (nread > nparse) {
		body_size = nread - nparse;
		body_size = MIN(body_size, http_server->body_expect_size);
		http_session_body_append(http_session, buf + nparse, body_size);
		if (http_server->chunked) {
			http_server_parse_chunk(http_session, buf + nparse, body_size);
		}
	}
	if (http_server->body_expect_size > 0) {
		http_server_body_read(connection);
	} else {
		http_server_close(http_session, 0);
	}
}

static void http_server_body_read(struct connection_t *connection)
{
	struct http_session_t *http_session = connection->arg;
	struct http_request_t *http_request = &http_session->http_request;
	struct http_server_t *http_server = http_session->http_server;
	struct cache_client_t *cache_client = http_session->cache_client;
	struct buffer_t *buffer = NULL;
	char *buf = NULL;
	size_t len = 0;
	ssize_t nread = 0;
	size_t total_read = 0;
	int error = 0;
	assert(connection == http_server->connection);
	assert(connection->epoll_thread == http_session->epoll_thread);
	while ((buffer = http_session_body_alloc(http_session)) && http_server->body_expect_size > 0 && total_read < MAX_READ) {
		buf = buffer->buf + buffer->len;
		len = buffer->size - buffer->len;
		nread = http_recv(connection->fd, buf, MIN(len, http_server->body_expect_size), 0);
		if (nread <= 0) {
			if (nread == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
				LOG(LOG_DEBUG, "%s %s fd=%d nread=%d again\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd, nread);
				connection_read_done(connection);
			} else {
				LOG(LOG_DEBUG, "%s %s fd=%d nread=%d %s\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd, nread, strerror(errno));
				error = 1;
			}
			break;
		}
		buffer->len += nread;
		total_read += nread;
		http_session->body_high += nread;
		http_server->body_expect_size -= nread;
		if (cache_client && buffer_full(buffer)) {
			cache_client_body_append(cache_client, buffer);
		}
		if (http_server->chunked) {
			http_server_parse_chunk(http_session, buf, nread);
		}
	}
	LOG(LOG_DEBUG, "%s %s fd=%d total_read=%d\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd, total_read);
	if (total_read > 0) {
		http_client_write_resume(http_session);
	}
	if (error == 0 && http_server->body_expect_size > 0) {
		if (buffer) {
			connection_read_enable(connection, http_server_body_read);
		} else {
			LOG(LOG_DEBUG, "%s %s fd=%d buffer full\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd);
			connection_read_disable(connection);
		}
	} else {
		http_server_close(http_session, error);
	}
}

static int http_server_header_process(struct http_session_t *http_session)
{
	struct http_request_t *http_request = &http_session->http_request;
	struct http_client_t *http_client = http_session->http_client;
	struct http_server_t *http_server = http_session->http_server;
	struct connection_t *connection = http_server->connection;
	struct http_reply_t *http_reply = http_server->parser.data;
	char buf[256];
	const char *str = NULL;
	struct http_content_range_t *content_range = NULL;
	if (http_reply->status_code == 206) {
		str = http_header_find(&http_reply->header, "Content-Range");
		if (str) {
			content_range = http_content_range_parse(str);
			http_header_del(&http_reply->header, "Content-Range");
			if (content_range) {
				http_reply->content_length = content_range->entity_length;
				http_server->body_offset = content_range->start;
				http_server->body_expect_size = content_range->end - content_range->start + 1;
				http_session->body_low = http_session->body_high = content_range->start;
				snprintf(buf, sizeof(buf), "%"PRId64"", http_reply->content_length);
				http_header_replace(&http_reply->header, "Content-Length", buf);
				http_free(content_range);
				http_reply->status_code = 200;
			} else {
				http_reply->status_code = 416;
			}
		} else {
			http_reply->status_code = 416;
		}
	} else {
		http_server->body_offset = 0;
		if ((str = http_header_find(&http_reply->header, "Transfer-Encoding"))) {
			if (strcasecmp(str, "chunked") == 0) {
				http_server->chunked = 1;
				http_server->body_expect_size = INT64_MAX;
			} else {
				http_header_del(&http_reply->header, "Transfer-Encoding");
			}
		} else if ((str = http_header_find(&http_reply->header, "Content-Length"))) {
			http_reply->content_length = atoll(str);
			http_server->body_expect_size = http_reply->content_length;
		}
		http_session->body_low = http_session->body_high = 0;
		if (http_reply->status_code == 204 || http_reply->status_code == 304) {
			http_server->body_expect_size = 0;
		}
	}
	if (http_request->method == HTTP_HEAD) {
		http_server->body_expect_size = 0;
	}
	if (http_client) {
		if (string_strlen(&http_client->reply_header) == 0) {
			http_client_build_reply(http_session, http_reply);
			connection_write_enable(http_client->connection, http_client_header_write);
		} else if (http_reply->status_code != 200) {
			LOG(LOG_ERROR, "%s %s fd=%d client need abort\n%s", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd);
			return -1;
		}
	}
	if (http_session->cache_client) {
		if (cache_client_header_process(http_session->cache_client, http_reply)) {
			LOG(LOG_ERROR, "%s %s fd=%d cache need abort\n%s", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd);
			return -1;
		}
	}
	return 0;
}

static int http_server_parse_chunk(struct http_session_t *http_session, const char *buf, size_t len) 
{
	struct http_request_t *http_request = &http_session->http_request;
	struct http_server_t *http_server = http_session->http_server;
	struct http_client_t *http_client = http_session->http_client;
	struct connection_t *connection = http_server->connection;
	int rc;
	size_t buf_pos;
	const char *ptr = NULL;
	size_t ptr_len = 0; 
	size_t nparsed = 0; 
	while (1) {
		ptr = buf + nparsed;
		ptr_len = len - nparsed;
		rc = http_parse_chunked(ptr, ptr_len, &buf_pos, &http_server->http_chunked);
		nparsed += buf_pos;
		if (rc == HTTP_OK) {
			if (ptr_len - buf_pos >= http_server->http_chunked.size) {
				nparsed += http_server->http_chunked.size;
				http_server->http_chunked.size = 0; 
				continue;
			}    
			http_server->http_chunked.size -= ptr_len - buf_pos;
			nparsed += ptr_len - buf_pos;
			continue;
		}    
		if (rc == HTTP_DONE) {
			LOG(LOG_DEBUG, "%s %s fd=%d done\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd);
			http_server->body_expect_size = 0;
			if (http_client) {
				http_client->body_expect_size = http_session->body_high - http_client->body_send_size;
			}
			break;
		}    
		if (rc == HTTP_AGAIN) {
			break;
		}    
		LOG(LOG_ERROR, "%s %s fd=%d error\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd);
		assert(0);
		return -1;
	}
	return 0;
}

static void http_server_dump_header(struct http_session_t *http_session)
{
	struct http_request_t *http_request = &http_session->http_request;
	struct http_server_t *http_server = http_session->http_server;
	struct http_reply_t *http_reply = http_server->parser.data;
	struct http_header_entry_t *header_entry;
	struct string_t string;
	string_init_size(&string, 1024);
	string_strcat_printf(&string, "HTTP/%d.%d %s\r\n", 
			http_reply->http_major, http_reply->http_minor, http_status_reasons_get(http_reply->status_code));
	list_for_each_entry(header_entry, &http_reply->header.header_list, header_entry_node) {
		string_strcat(&string, string_buf(&header_entry->field_string));
		string_strcat(&string, ": ");
		string_strcat(&string, string_buf(&header_entry->value_string));
		string_strcat(&string, "\r\n");
	}    
	string_strcat(&string, "\r\n"); 
	LOG(LOG_INFO, "%s %s reply=\n%s", http_session->epoll_thread->name, string_buf(&http_request->url), string_buf(&string));
	string_clean(&string);
}

static struct http_reply_t* http_reply_create()
{
	struct http_reply_t *http_reply = NULL;
	http_reply = http_malloc(sizeof(struct http_reply_t));
	memset(http_reply, 0, sizeof(struct http_reply_t));
	http_header_init(&http_reply->header);
	http_reply->content_length = -1;
	return http_reply;
}

static void http_reply_free(struct http_reply_t *http_reply)
{
	http_header_clean(&http_reply->header);
	http_free(http_reply);
}

static int http_request_cacheable(struct http_request_t *http_request)
{
	return 1;
}

static int http_reply_cacheable(struct http_reply_t *http_reply)
{
	switch (http_reply->status_code) {
		case 200:
		case 204:
		case 206:
			return 1;
			break;
		default:
			return 0;
			break;
	}
}

static void http_session_lookup_cache(struct http_session_t *http_session)
{
	struct http_request_t *http_request = &http_session->http_request;
	struct cache_t *cache = NULL;
	if (http_request_cacheable(http_request)) {
		cache_client_create(http_session);
		cache_table_lock();
		cache = cache_table_lookup(string_buf(&http_request->url));
		if (cache == NULL) {
			cache = cache_alloc(string_buf(&http_request->url));
			cache_table_insert(cache);
			cache_client_lock(http_session->cache_client, cache);
			cache_table_unlock();
			http_server_create(http_session, http_request->range);
			return;
		} else {
			cache_client_lock(http_session->cache_client, cache);
			cache_table_unlock();
			if (http_session->cache_client->aio.epoll_thread != cache->epoll_thread) {
				http_client_dispatch(http_session);
			} else {
				http_session->cache_client->type = CACHE_CLIENT_READ;
				cache_client_file_open(http_session->cache_client);
			}
			return;
		}
	} else {
		http_server_create(http_session, http_request->range);
		return;
	}
}

static int cache_client_header_process(struct cache_client_t *cache_client, struct http_reply_t *http_reply)
{
	struct http_session_t *http_session = cache_client->http_session;
	struct http_server_t *http_server = http_session->http_server;
	struct cache_t *cache = cache_client->cache;
	assert(!aio_busy(&cache_client->aio));
	if (http_reply_cacheable(http_reply)) {
		if (cache->http_reply) {
			if (cache->http_reply->content_length != http_reply->content_length) {
				LOG(LOG_ERROR, "%s %s reply disable cache old content_length=%"PRId64" new content_length=%"PRId64"\n%s",
						cache_client->aio.epoll_thread->name, cache->url, cache->http_reply->content_length, http_reply->content_length);
				cache_client_unlock(cache_client, 1);
				return 0;
			}
		} else {
			cache->http_reply = http_reply;
			http_server->parser.data = NULL;
			cache_client_header_append(cache_client);
		}
	} else {
		LOG(LOG_DEBUG, "%s %s reply disable cache\n", cache_client->aio.epoll_thread->name, cache->url);
		cache_client_unlock(cache_client, 1);
		return 0;
	}
	cache_client->body_pos = http_server->body_offset;
	cache_client->type = CACHE_CLIENT_WRITE;
	cache_client_file_open(cache_client);
	return 0;
}

static void cache_client_create(struct http_session_t *http_session)
{
	struct cache_client_t *cache_client = NULL;
	http_session->cache_client = cache_client = http_malloc(sizeof(struct cache_client_t));
	memset(cache_client, 0, sizeof(struct cache_client_t));
	cache_client->http_session = http_session;
	buffer_node_pool_init(&cache_client->body_free_pool, PAGE_MAX_COUNT);
	buffer_node_pool_init(&cache_client->body_data_pool, 0);
	cache_client->aio.callback_data = cache_client;
	cache_client->aio.epoll_thread = http_session->epoll_thread;
}

static void cache_client_free(struct cache_client_t *cache_client)
{
	struct buffer_node_t *buffer_node = NULL;
	while (buffer_node_pool_size(&cache_client->body_data_pool) > 0) {
		buffer_node_pool_pop(&cache_client->body_data_pool, &buffer_node);
		buffer_unref(buffer_node->buffer);
		http_free(buffer_node);
	}
	while (buffer_node_pool_size(&cache_client->body_free_pool) > 0) {
		buffer_node_pool_pop(&cache_client->body_free_pool, &buffer_node);
		http_free(buffer_node);
	}
	if (cache_client->header) {
		http_free(cache_client->header);
	}
	http_free(cache_client);
}

static void cache_client_lock(struct cache_client_t *cache_client, struct cache_t *cache)
{
	cache->lock++;
	if (cache->epoll_thread == NULL) {
		cache->epoll_thread = cache_client->aio.epoll_thread;
	}
	cache_client->cache = cache;
}

static void cache_client_unlock(struct cache_client_t *cache_client, int del)
{
	struct http_session_t *http_session = cache_client->http_session;
	struct cache_t *cache = cache_client->cache;
	struct cache_file_t *cache_file = cache->cache_file;
	LOG(LOG_DEBUG, "%s %s\n", cache_client->aio.epoll_thread->name, cache->url);
	if (http_session) {
		http_session->cache_client = NULL;
	}
	cache_client->cache = NULL;
	cache_table_lock();
	if (del && cache->flags.del == 0) {
		cache_table_erase(cache);
		cache->flags.del = 1;
	}
	if (--cache->lock == 0) {
		cache->epoll_thread = NULL;
		if (cache_file) {
			cache_client->aio.fd = cache_file->fd;
			cache->cache_file = NULL;
		}
		if (cache->flags.del && cache->file_number > 0) {
			cache_client->file_number = cache->file_number;
		}
	}
	cache_table_unlock();
	if (cache_file) {
		cache_file_free(cache_file);
	}
	if (cache_client->aio.fd > 0 || cache_client->file_number > 0) {
		cache_client_file_close(cache_client);
	} else {
		cache_client_free(cache_client);
	}
}

static struct cache_file_t* cache_file_alloc()
{
	struct cache_file_t *cache_file = NULL;
	cache_file = http_malloc(sizeof(struct cache_file_t));
	memset(cache_file, 0, sizeof(struct cache_file_t));
	INIT_LIST_HEAD(&cache_file->delay_list);
	return cache_file;
}

static void cache_file_free(struct cache_file_t *cache_file)
{
	if (cache_file->bitmap) {
		http_free(cache_file->bitmap);
	}
	http_free(cache_file);
}

static void cache_client_file_open(struct cache_client_t *cache_client)
{
	struct cache_t *cache = cache_client->cache;
	struct cache_file_t *cache_file = cache->cache_file;
	if (cache_file == NULL) {
		LOG(LOG_DEBUG, "%s %s cache file open start\n", cache_client->aio.epoll_thread->name, cache->url);
		cache->cache_file = cache_file = cache_file_alloc();
		if (cache_client->type == CACHE_CLIENT_WRITE) {
			assert(cache_client->header_size > 0);
			cache_file->header_size = cache_client->header_size;
			if (cache->http_reply->content_length > 0) {
				cache_file->bitmap_bit_size = BLOCK_SIZE;
				cache_file->bitmap_byte_size = cache_file->bitmap_bit_size * 8;
				cache_file->bitmap_size = (cache->http_reply->content_length + cache_file->bitmap_byte_size - 1) / cache_file->bitmap_byte_size;
				cache_file->bitmap = http_malloc(cache_file->bitmap_size);
				memset(cache_file->bitmap, 0, cache_file->bitmap_size);
				LOG(LOG_DEBUG, "%s %s bitmap_bit_size=%d bitmap_byte_size=%d bitmap_size=%d\n",
						cache_client->aio.epoll_thread->name, cache->url, cache_file->bitmap_bit_size, cache_file->bitmap_byte_size, cache_file->bitmap_size);
			}
		}
		aio_summit(&cache_client->aio, cache_client_file_open_exec, cache_client_file_open_done);
	} else if (cache_file->fd > 0) {
		LOG(LOG_DEBUG, "%s %s cache file fd=%d\n", cache_client->aio.epoll_thread->name, cache->url, cache_file->fd);
		cache_client->aio.fd = cache_file->fd;
		cache_client_resume(&cache_client->aio);
	} else {
		LOG(LOG_DEBUG, "%s %s cache file open wait\n", cache_client->aio.epoll_thread->name, cache->url);
		cache_client->aio.status = AIO_STATUS_SUMMIT;
		list_add_tail(&cache_client->aio.node, &cache_file->delay_list);
	}
}

static void cache_client_file_open_exec(struct aio_t *aio)
{
	struct cache_client_t *cache_client = aio->callback_data;
	struct cache_t *cache = cache_client->cache;
	struct cache_file_t *cache_file = cache->cache_file;
	int flags = 0;
	mode_t mode = S_IRWXU | S_IRWXG | S_IRWXO;
	if (cache->file_number > 0) {
		flags = O_RDWR;
	} else {
		cache->file_number = 1;
		flags = O_RDWR|O_CREAT|O_TRUNC;
	}
	snprintf(cache_file->path, sizeof(cache_file->path), "/tmp/cache_%"PRId64".dat", cache->file_number);
	aio->fd = aio->return_ret = open(cache_file->path, flags, mode);
	aio->return_errno = errno;
}

static void cache_client_file_open_done(struct aio_t *aio)
{
	struct cache_client_t *cache_client = aio->callback_data;
	struct cache_t *cache = cache_client->cache;
	struct cache_file_t *cache_file = cache->cache_file;
	struct aio_t *aio_delay;
	int fd = aio->fd;
	if (aio->fd > 0) {
		LOG(LOG_DEBUG, "%s %s %s fd=%d file open ok\n", aio->epoll_thread->name, cache->url, cache_file->path, aio->fd);
		cache_file->fd = fd;
	} else {
		LOG(LOG_ERROR, "%s %s %s fd=%d file open error:%s\n", aio->epoll_thread->name, cache->url, cache_file->path, aio->fd, strerror(aio->return_errno));
		cache_file_free(cache_file);
		cache->cache_file = NULL;
	}
	cache_client_resume(aio);
	while (!list_empty(&cache_file->delay_list)) {
		aio_delay = d_list_head(&cache_file->delay_list, struct aio_t, node);
		list_del(&aio_delay->node);
		aio_delay->fd = fd;
		cache_client_resume(aio_delay);
	}
}

static void cache_client_resume(struct aio_t *aio)
{
	struct cache_client_t *cache_client = aio->callback_data;
	struct cache_t *cache = cache_client->cache;
	struct cache_file_t *cache_file = cache->cache_file;
	cache_client->aio.status = AIO_STATUS_DONE;
	if (cache_client->type == CACHE_CLIENT_READ) {
		cache_client_read_open_done(&cache_client->aio);
	} else if (cache_client->type == CACHE_CLIENT_WRITE) {
		cache_client_write_open_done(&cache_client->aio);
	} else {
		LOG(LOG_DEBUG, "%s %s %s fd=%d do nothing\n", aio->epoll_thread->name, cache->url, cache_file->path, aio->fd);
	}
}

static void cache_client_read_open_done(struct aio_t *aio)
{
	struct cache_client_t *cache_client = aio->callback_data;
	struct cache_t *cache = cache_client->cache;
	struct cache_file_t *cache_file = cache->cache_file;
	if (aio->fd > 0) {
		LOG(LOG_DEBUG, "%s %s %s fd=%d start read\n", cache_client->aio.epoll_thread->name, cache->url, cache_file->path, aio->fd);
		cache_client_do_read(cache_client);
	} else {
		LOG(LOG_ERROR, "%s %s %s fd=%d cannot read\n", cache_client->aio.epoll_thread->name, cache->url, cache_file->path, aio->fd);
		cache_client_unlock(cache_client, 1);
	}
}

static void cache_client_do_read(struct cache_client_t *cache_client)
{
	struct cache_t *cache = cache_client->cache;
	struct cache_file_t *cache_file = cache->cache_file;
	assert(!aio_busy(&cache_client->aio));
	assert(cache_client->aio.fd > 0);
	cache_client->aio.return_ret = 0;
	cache_client->aio.return_errno = 0;
	if (cache->http_reply == NULL) {
		cache_client->aio.offset = 0;
		cache_client->header_size = PAGE_SIZE;
		cache_client->header = http_malloc(cache_client->header_size);
		http_parser_init(&cache_client->parser, HTTP_RESPONSE);
		cache_client->parser.data = http_reply_create();
		LOG(LOG_DEBUG, "%s %s %s fd=%d header=%d\n", cache_client->aio.epoll_thread->name, cache->url, cache_file->path, cache_client->aio.fd, cache_client->header_size);
		aio_summit(&cache_client->aio, cache_client_header_read_exec, cache_client_header_read_done);
	} else {
	}
}

static void cache_client_header_read_exec(struct aio_t *aio)
{
	struct cache_client_t *cache_client = aio->callback_data;
	ssize_t nread = 0;
	nread = posix_pread(aio->fd, cache_client->header, cache_client->header_size, aio->offset);
	if (nread > 0) {
		aio->return_ret = nread;
		aio->offset += nread;
	}
	aio->return_errno = errno;
}

static void cache_client_header_read_done(struct aio_t *aio)
{
	struct cache_client_t *cache_client = aio->callback_data;
	struct cache_t *cache = cache_client->cache;
	struct cache_file_t *cache_file = cache->cache_file;
	struct http_reply_t *http_reply = cache_client->parser.data;
	size_t nparse = 0;
	int nread = aio->return_ret;
	if (nread <= 0) {
		LOG(LOG_ERROR, "%s %s %s fd=%d nread=%d error:%s\n", cache_client->aio.epoll_thread->name, cache->url, cache_file->path, aio->fd, nread, strerror(aio->return_errno));
		cache_client_unlock(cache_client, 1);
		return;
	}
	LOG(LOG_DEBUG, "%s %s %s fd=%d nread=%d\n", cache_client->aio.epoll_thread->name, cache->url, cache_file->path, aio->fd, nread);
	nparse = http_parser_execute(&cache_client->parser, &reply_parser_settings, cache_client->header, nread);
	if (nparse < nread && http_reply->parse_state < PARSER_HEADER_DONE) {
		LOG(LOG_ERROR, "%s %s %s fd=%d nread=%d nparse=%d error\n", cache_client->aio.epoll_thread->name, cache->url, cache_file->path, aio->fd, nread, nparse);
		cache_client_unlock(cache_client, 1);
		return;
	}
	if (http_reply->parse_state < PARSER_HEADER_DONE) {
		LOG(LOG_DEBUG, "%s %s %s fd=%d header=%d\n", cache_client->aio.epoll_thread->name, cache->url, cache_file->path, cache_client->aio.fd, cache_client->header_size);
		aio_summit(&cache_client->aio, cache_client_header_read_exec, cache_client_header_read_done);
		return;
	}
	cache_client->parser.data = NULL;
	if (cache->http_reply == NULL) {
		cache->http_reply = http_reply;
		cache_file->header_size = aio->offset - (cache_client->header_size - nparse);
		LOG(LOG_DEBUG, "%s %s %s fd=%d header_size=%d\n", cache_client->aio.epoll_thread->name, cache->url, cache_file->path, cache_client->aio.fd, cache_file->header_size);
	} else {
		LOG(LOG_DEBUG, "%s %s %s fd=%d drop http_reply\n", cache_client->aio.epoll_thread->name, cache->url, cache_file->path, cache_client->aio.fd);
	}
	cache_client_dump_header(cache_client);
}

static void cache_client_dump_header(struct cache_client_t *cache_client)
{
	struct cache_t *cache = cache_client->cache;
	struct http_reply_t *http_reply = cache->http_reply;
	struct http_header_entry_t *header_entry;
	struct string_t string;
	string_init_size(&string, 1024);
	string_strcat_printf(&string, "HTTP/%d.%d %s\r\n", 
			http_reply->http_major, http_reply->http_minor, http_status_reasons_get(http_reply->status_code));
	list_for_each_entry(header_entry, &http_reply->header.header_list, header_entry_node) {
		string_strcat(&string, string_buf(&header_entry->field_string));
		string_strcat(&string, ": ");
		string_strcat(&string, string_buf(&header_entry->value_string));
		string_strcat(&string, "\r\n");
	}    
	string_strcat(&string, "\r\n"); 
	LOG(LOG_INFO, "%s %s reply=\n%s", cache_client->aio.epoll_thread->name, cache->url, string_buf(&string));
	string_clean(&string);
}

static void cache_client_write_open_done(struct aio_t *aio)
{
	struct cache_client_t *cache_client = aio->callback_data;
	struct cache_t *cache = cache_client->cache;
	struct cache_file_t *cache_file = cache->cache_file;
	if (aio->fd > 0) {
		LOG(LOG_DEBUG, "%s %s %s fd=%d start write\n", cache_client->aio.epoll_thread->name, cache->url, cache_file->path, aio->fd);
		cache_client_do_write(cache_client);
	} else {
		LOG(LOG_ERROR, "%s %s %s fd=%d cannot write\n", cache_client->aio.epoll_thread->name, cache->url, cache_file->path, aio->fd);
		cache_client_unlock(cache_client, 1);
	}
}

static void cache_client_file_close(struct cache_client_t *cache_client)
{
	LOG(LOG_DEBUG, "%s fd=%d start close\n", cache_client->aio.epoll_thread->name, cache_client->aio.fd);
	assert(cache_client->aio.fd > 0);
	aio_summit(&cache_client->aio, cache_client_file_close_exec, cache_client_file_close_done);
}

static void cache_client_file_close_exec(struct aio_t *aio)
{
	struct cache_client_t *cache_client = aio->callback_data;
	char path[256];
	if (aio->fd > 0) {
		aio->return_ret = close(aio->fd);
		aio->return_errno = errno;
	}
	if (cache_client->file_number > 0) {
		snprintf(path, sizeof(path), "/tmp/cache_%"PRId64".dat", cache_client->file_number);
		aio->return_ret = unlink(path);
		aio->return_errno = errno;
	}
}

static void cache_client_file_close_done(struct aio_t *aio)
{
	struct cache_client_t *cache_client = aio->callback_data;
	if (aio->return_ret == 0) {
		LOG(LOG_DEBUG, "%s fd=%d close ok\n", aio->epoll_thread->name, aio->fd);
	} else {
		LOG(LOG_ERROR, "%s fd=%d close error:%s\n", aio->epoll_thread->name, aio->fd, strerror(aio->return_errno));
	}
	aio->fd = -1;
	cache_client_free(cache_client);
}

static void cache_client_header_append(struct cache_client_t *cache_client)
{
	struct cache_t *cache = cache_client->cache;
	struct http_reply_t *http_reply = cache->http_reply;
	struct string_t string;
	struct http_header_entry_t *header_entry;
	string_init_size(&string, PAGE_SIZE);
	string_strcat_printf(&string, "HTTP/%d.%d %s\r\n", 
			http_reply->http_major, http_reply->http_minor, http_status_reasons_get(http_reply->status_code));
	list_for_each_entry(header_entry, &http_reply->header.header_list, header_entry_node) {
		string_strcat(&string, string_buf(&header_entry->field_string));
		string_strcat(&string, ": ");
		string_strcat(&string, string_buf(&header_entry->value_string));
		string_strcat(&string, "\r\n");
	}    
	string_strcat(&string, "\r\n"); 
	memset(string_buf(&string) + string_strlen(&string), 0, string_strsize(&string) - string_strlen(&string));
	LOG(LOG_INFO, "%s %s reply=\n%s", cache_client->aio.epoll_thread->name, cache->url, string_buf(&string));
	cache_client->header = string_buf(&string);
	cache_client->header_size = string_strlen(&string);
}

static void cache_client_header_write_exec(struct aio_t *aio)
{
	struct cache_client_t *cache_client = aio->callback_data;
	struct cache_t *cache = cache_client->cache;
	struct cache_file_t *cache_file = cache->cache_file;
	ssize_t nwrite = 0;
	nwrite = posix_pwrite(aio->fd, cache_client->header, cache_file->header_size, aio->offset);
	if (nwrite > 0) {
		aio->return_ret = nwrite;
		aio->offset += nwrite;
	}
	aio->return_errno = errno;
}

static void cache_client_header_write_done(struct aio_t *aio)
{
	struct cache_client_t *cache_client = aio->callback_data;
	struct cache_t *cache = cache_client->cache;
	struct cache_file_t *cache_file = cache->cache_file;
	int nwrite = aio->return_ret;
	if (cache_client->header) {
		http_free(cache_client->header);
		cache_client->header = NULL;
		if (nwrite > 0) {
			LOG(LOG_DEBUG, "%s %s %s fd=%d nwrite=%d\n", cache_client->aio.epoll_thread->name, cache->url, cache_file->path, aio->fd, nwrite);
		} else {
			LOG(LOG_ERROR, "%s %s %s fd=%d nwrite=%d error:%s\n", cache_client->aio.epoll_thread->name, cache->url, cache_file->path, aio->fd, nwrite, strerror(aio->return_errno));
			cache_client_unlock(cache_client, 1);
			return;
		}
	}
	cache_client_do_write(cache_client);
}

static void cache_client_body_append(struct cache_client_t *cache_client, struct buffer_t *buffer)
{
	struct cache_t *cache = cache_client->cache;
	struct buffer_node_t *buffer_node = NULL;
	assert(buffer_node_pool_size(&cache_client->body_free_pool) > 0);
	buffer_node_pool_pop(&cache_client->body_free_pool, &buffer_node);
	buffer_node->buffer = buffer_ref(buffer);
	buffer_node_pool_push(&cache_client->body_data_pool, buffer_node);
	LOG(LOG_DEBUG, "%s %s len=%d\n", cache_client->aio.epoll_thread->name, cache->url, buffer->len);
	if (aio_busy(&cache_client->aio)) {
		return;
	}
	if (!aio_busy(&cache_client->aio)) {
		cache_client_do_write(cache_client);
	}
}

static void cache_client_body_append_end(struct cache_client_t *cache_client)
{
	struct http_session_t *http_session = cache_client->http_session;
	struct cache_t *cache = cache_client->cache;
	struct buffer_t *buffer = NULL;
	buffer = http_session_body_alloc(http_session);
	if (buffer && buffer->len > 0) {
		if (http_session->body_high == cache->http_reply->content_length) {
			cache_client_body_append(cache_client, buffer);
		} else {
			LOG(LOG_DEBUG, "%s %s skip len=%d\n", cache_client->aio.epoll_thread->name, cache->url, buffer->len);
			if (!aio_busy(&cache_client->aio)) {
				cache_client_do_write(cache_client);
			}
		}
	}
}

static void cache_client_bitmap_update(struct cache_client_t *cache_client)
{
	struct cache_t *cache = cache_client->cache;
	struct cache_file_t *cache_file = cache->cache_file;
	size_t byte_pos;
	size_t bit_pos;
	while (cache_client->body_pos - cache_client->bitmap_pos >= cache_file->bitmap_bit_size) {
		bit_pos = cache_client->bitmap_pos / cache_file->bitmap_bit_size;
		byte_pos = cache_client->bitmap_pos / cache_file->bitmap_byte_size;
		cache_file->bitmap[byte_pos] |= 1 << (bit_pos & 0x7);
		cache_client->bitmap_pos += cache_file->bitmap_bit_size;
	}
	if (cache_client->body_pos == cache->http_reply->content_length &&
			cache_client->bitmap_pos < cache->http_reply->content_length) {
		bit_pos = cache_client->bitmap_pos / cache_file->bitmap_bit_size;
		byte_pos = cache_client->bitmap_pos / cache_file->bitmap_byte_size;
		cache_file->bitmap[byte_pos] |= 1 << (bit_pos & 0x7);
		cache_client->bitmap_pos = cache->http_reply->content_length;
	}
}

static void cache_client_do_write(struct cache_client_t *cache_client)
{
	struct cache_t *cache = cache_client->cache;
	struct cache_file_t *cache_file = cache->cache_file;
	struct buffer_node_t *buffer_node = NULL;
	struct buffer_t *buffer = NULL;
	int i = 0;
	assert(!aio_busy(&cache_client->aio));
	assert(cache_client->aio.fd > 0);
	cache_client->aio.return_ret = 0;
	cache_client->aio.return_errno = 0;
	if (cache_client->header) {
		assert(cache_client->header_size > 0);
		cache_client->aio.offset = 0;
		LOG(LOG_DEBUG, "%s %s %s fd=%d header=%d\n", cache_client->aio.epoll_thread->name, cache->url, cache_file->path, cache_client->aio.fd, cache_client->header_size);
		aio_summit(&cache_client->aio, cache_client_header_write_exec, cache_client_header_write_done);
	} else if (buffer_node_pool_size(&cache_client->body_data_pool) > 0) {
		cache_client->buffer_size = 0;
		cache_client->aio.offset = cache_client->body_pos + cache_file->header_size;
		for (i = 0; i < MAX_LOOP; i++) {
			buffer_node_pool_pop(&cache_client->body_data_pool, &buffer_node);
			if (buffer_node == NULL) {
				break;
			}
			buffer = buffer_node->buffer;
			cache_client->buffer_array[i] = buffer;
			cache_client->buffer_size += buffer->len;
			buffer_node->buffer = NULL;
			buffer_node_pool_push(&cache_client->body_free_pool, buffer_node);
		}
		cache_client->buffer_array[i] = NULL;
		LOG(LOG_DEBUG, "%s %s %s fd=%d body=%d\n", cache_client->aio.epoll_thread->name, cache->url, cache_file->path, cache_client->aio.fd, cache_client->buffer_size);
		aio_summit(&cache_client->aio, cache_client_body_write_exec, cache_client_body_write_done);
	} else if (cache_client->http_session == NULL) {
		cache_client_unlock(cache_client, 0);
	}	else {
		LOG(LOG_DEBUG, "%s %s %s fd=%d nothing write\n", cache_client->aio.epoll_thread->name, cache->url, cache_file->path, cache_client->aio.fd);
	}
}

static void cache_client_body_write_exec(struct aio_t *aio)
{
	struct cache_client_t *cache_client = aio->callback_data;
	struct buffer_t *buffer = NULL;
	int64_t offset = aio->offset;
	ssize_t nwrite = 0;
	int i = 0;
	while ((buffer = cache_client->buffer_array[i++])) {
		nwrite = posix_pwrite(aio->fd, buffer->buf, buffer->len, offset);
		if (nwrite > 0) {
			aio->return_ret += nwrite;
			offset += nwrite;
		}
		if (nwrite < buffer->len) {
			break;
		}
	}
	aio->return_errno = errno;
}

static void cache_client_body_write_done(struct aio_t *aio)
{
	struct cache_client_t *cache_client = aio->callback_data;
	struct cache_t *cache = cache_client->cache;
	struct cache_file_t *cache_file = cache->cache_file;
	struct buffer_t *buffer = NULL;
	struct http_session_t *http_session = cache_client->http_session;
	int nwrite = aio->return_ret;
	int i = 0;
	while ((buffer = cache_client->buffer_array[i++])) {
		buffer_unref(buffer);
	}
	if (http_session) {
		http_server_read_resume(http_session);
	}
	if (nwrite > 0) {
		cache_client->body_pos += nwrite;
		if (cache_file->bitmap) {
			cache_client_bitmap_update(cache_client);
		}
		LOG(LOG_DEBUG, "%s %s %s fd=%d nwrite=%d\n", cache_client->aio.epoll_thread->name, cache->url, cache_file->path, aio->fd, nwrite);
		if (cache_client->buffer_size > nwrite) {
			LOG(LOG_ERROR, "%s %s %s fd=%d buffer_size=%d > nwrite=%d\n", cache_client->aio.epoll_thread->name, cache->url, cache_file->path, aio->fd, cache_client->buffer_size, nwrite);
			cache_client_unlock(cache_client, 1);
		} else {
			cache_client_do_write(cache_client);
		}
	} else {
		LOG(LOG_ERROR, "%s %s %s fd=%d nwrite=%d error:%s\n", cache_client->aio.epoll_thread->name, cache->url, cache_file->path, aio->fd, nwrite, strerror(aio->return_errno));
		cache_client_unlock(cache_client, 1);
	}
}

static struct cache_t* cache_alloc(const char *key)
{
	struct cache_t *cache = NULL;
	cache = http_malloc(sizeof(struct cache_t));
	memset(cache, 0, sizeof(struct cache_t));
	cache->key = http_strdup(key);
	cache->url = http_strdup(key);
	return cache;
}

static void cache_free(struct cache_t *cache)
{
	http_free(cache->key);
	http_free(cache->url);
	if (cache->http_reply) {
		http_reply_free(cache->http_reply);
	}
	http_free(cache);
}

void cache_table_create()
{
	memset(&cache_table, 0, sizeof(struct cache_table_t));
	pthread_mutex_init(&cache_table.mutex, NULL);
	cache_table.rb_root = RB_ROOT;
	INIT_LIST_HEAD(&cache_table.list);
}

void cache_table_free()
{
	struct cache_t *cache = NULL;
	struct rb_node *node = NULL;
	while ((node = rb_first(&cache_table.rb_root))) {
		cache = rb_entry(node, struct cache_t, rb_node);
		cache_table_erase(cache);
		cache_free(cache);
	}
	memset(&cache_table, 0, sizeof(struct cache_table_t));
}

static int cache_table_lock()
{
	return pthread_mutex_lock(&cache_table.mutex);
}

static int cache_table_unlock()
{
	return pthread_mutex_unlock(&cache_table.mutex);
}

static struct cache_t* cache_table_lookup(const void *key)
{
	struct rb_node *node = cache_table.rb_root.rb_node;
	struct cache_t *cache = NULL;
	int cmp = 0;
	while (node)
	{   
		cache = (struct cache_t *)rb_entry(node, struct cache_t, rb_node);
		cmp = strcmp(key, cache->key);
		if (cmp < 0)
			node = node->rb_left;
		else if (cmp > 0)
			node = node->rb_right;
		else
			return cache;
	} 
	return NULL;
};

static int cache_table_insert(struct cache_t *cache)
{
	struct rb_node **p = &cache_table.rb_root.rb_node;
	struct rb_node *parent = NULL;
	struct cache_t *cache_tmp = NULL;
	int cmp;
	while (*p)
	{   
		parent = *p; 
		cache_tmp = rb_entry(parent, struct cache_t, rb_node);
		cmp = strcmp(cache->key, cache_tmp->key);
		if (cmp < 0)
			p = &(*p)->rb_left;
		else if (cmp > 0)
			p = &(*p)->rb_right;
		else
			return -1; 
	}   
	rb_link_node(&cache->rb_node, parent, p); 
	rb_insert_color(&cache->rb_node, &cache_table.rb_root);
	cache_table.count--;
	return 0;
}

static int cache_table_erase(struct cache_t *cache)
{
	rb_erase(&cache->rb_node, &cache_table.rb_root);
	cache_table.count--;
	return 0;
}

