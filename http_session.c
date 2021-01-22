#include "http.h"
#include "http_log.h"
#include "http_aio.h"
#include "http_connection.h"
#include "http_dns.h"
#include "http_header.h"
#include "http_session.h"

static struct cache_table_t cache_table;

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
static void http_session_close(struct http_session_t *http_session);
static void http_client_create(struct http_session_t *http_session, struct connection_t *connection);
static void http_client_check_close(struct http_session_t *http_session, int error_code);
static void http_client_close(struct http_session_t *http_session, int error_code);
static void http_client_post_append(struct http_session_t *http_session, const char *buf, size_t len);
static void http_client_read_resume(struct http_session_t *http_session);
static void http_client_header_read(struct connection_t *connection);
static void http_client_body_read(struct connection_t *connection);
static int http_client_header_process(struct http_session_t *http_session);
static void http_client_dump_header(struct http_session_t *http_session);
static void http_client_build_reply(struct http_session_t *http_session, struct http_reply_t *http_reply);
static void http_client_build_error_reply(struct http_session_t *http_session, int status_code);
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
static void http_session_body_append(struct http_session_t *http_session, const char *buf, size_t len);
static void http_server_header_read(struct connection_t *connection);
static void http_server_body_read_resume(struct http_session_t *http_session);
static void http_server_body_read(struct connection_t *connection);
static int http_server_header_process(struct http_session_t *http_session);
static int http_server_parse_chunk(struct http_session_t *http_session, const char *buf, size_t len); 
static void http_server_dump_header(struct http_session_t *http_session);
static struct http_reply_t* http_reply_alloc();
static void http_reply_copy(struct http_reply_t *dest, struct http_reply_t *src);
static void http_reply_free(struct http_reply_t *http_reply);
static int http_request_cacheable(struct http_request_t *http_request);
static int http_reply_cacheable(struct http_reply_t *http_reply);
static void cache_client_dispatch(struct cache_client_t *cache_client);
static void cache_client_dispatch_done(struct aio_t *aio);
static void http_session_cache_lookup(struct http_session_t *http_session);
static void http_session_cache_hit(struct http_session_t *http_session);
static void http_session_body_read(struct http_session_t *http_session);
static void http_session_body_write(struct http_session_t *http_session);
static void cache_client_close(struct cache_client_t *cache_client, int del);
static void cache_client_dump_header(struct cache_client_t *cache_client);
static void cache_client_header_build(struct cache_client_t *cache_client, struct http_reply_t *http_reply);
static void cache_client_header_write(struct cache_client_t *cache_client, struct http_reply_t *http_reply);
static void cache_client_body_append(struct cache_client_t *cache_client, struct buffer_t *buffer);
static void cache_client_body_append_end(struct cache_client_t *cache_client);
static void cache_client_bitmap_update(struct cache_client_t *cache_client);
static void cache_file_open_aio(struct aio_t *aio);
static void cache_file_open_done(struct aio_t *aio);
static void cache_client_resume(struct cache_client_t *cache_client, int abort);
static void cache_client_do_write(struct cache_client_t *cache_client);
static void cache_file_header_write_done(struct aio_t *aio);
static void cache_client_body_write_done(struct aio_t *aio);
static void cache_client_bitmap_write_done(struct aio_t *aio);
static void cache_file_header_read_done(struct aio_t *aio);
static void cache_client_bitmap_read_done(struct aio_t *aio);
static int cache_file_body_read(struct cache_client_t *cache_client, int64_t start, int64_t end);
static void cache_file_body_read_done(struct aio_t *aio);
static void cache_file_close_aio(struct aio_t *aio);
static void cache_file_close_done(struct aio_t *aio);
static struct cache_client_t *cache_client_alloc();
static void cache_client_free(struct cache_client_t *cache_client);
static struct cache_file_t* cache_file_alloc();
static void cache_file_free(struct cache_file_t *cache_file);
static void cache_file_number_alloc(struct cache_file_t *cache_file);
static void cache_file_number_free(struct cache_file_t *cache_file);
static void cache_file_path_init(struct cache_file_t *cache_file, int64_t file_number);
static void cache_file_bitmap_init(struct cache_file_t *cache_file, int64_t content_length, size_t block_size);
static struct cache_t* cache_alloc();
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

void http_session_create(struct epoll_thread_t *epoll_thread, int fd)
{
	struct http_session_t *http_session = NULL;
	struct connection_t *connection = NULL;
	socklen_t addr_len = sizeof(struct sockaddr);
	http_session = http_malloc(sizeof(struct http_session_t));
	memset(http_session, 0, sizeof(struct http_session_t));
	http_session->epoll_thread = epoll_thread;
	http_header_init(&http_session->http_request.header);
	string_init_size(&http_session->http_request.url, 1024);
	fifo_init(&http_session->post_fifo, PAGE_MAX_COUNT);
	fifo_init(&http_session->body_fifo, PAGE_MAX_COUNT);
	list_add_tail(&http_session->node, &epoll_thread->http_session_list);

	connection = http_malloc(sizeof(struct connection_t));
	memset(connection, 0, sizeof(struct connection_t));
	connection->fd = fd;
	getsockname(connection->fd, &connection->local_addr, &addr_len);
	getpeername(connection->fd, &connection->peer_addr, &addr_len);
	connection->epoll_thread = epoll_thread;

	http_client_create(http_session, connection);
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
	struct buffer_t *buffer = NULL;
	assert(http_session->http_client == NULL);
	assert(http_session->http_server == NULL);
	LOG(LOG_INFO, "%s %s\n", http_session->epoll_thread->name, string_buf(&http_request->url));
	list_del(&http_session->node);
	if (cache_client) {
		if (aio_busy(&cache_client->aio)) {
			LOG(LOG_INFO, "%s %s aio busy\n", http_session->epoll_thread->name, string_buf(&http_request->url));
			cache_client->http_session = NULL;
		} else {
			cache_client_close(cache_client, 0);
		}
		http_session->cache_client = NULL;
	}
	while (fifo_len(&http_session->post_fifo) > 0) {
		fifo_pop_head(&http_session->post_fifo, (void **)&buffer);
		http_session->post_low += buffer->len;
		buffer_unref(buffer);
	}
	fifo_clean(&http_session->post_fifo);
	while (fifo_len(&http_session->body_fifo) > 0) {
		fifo_pop_head(&http_session->body_fifo, (void **)&buffer);
		http_session->body_low += buffer->len;
		buffer_unref(buffer);
	}
	fifo_clean(&http_session->body_fifo);
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
		if (http_session->body_high > http_client->body_offset_current) {
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
	LOG(LOG_INFO, "%s %s fd=%d body_offset=%"PRId64" body_send_size=%"PRId64" body_expect_size=%"PRId64" error_code=%d\n",
			http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd,
			http_client->body_offset, http_client->body_offset_current - http_client->body_offset,
			http_client->body_offset_expect - http_client->body_offset, error_code);
	connection_close(connection, CONNECTION_FREE_DELAY);
	string_clean(&http_client->reply_header);
	http_free(http_client);
	http_session->http_client = NULL;
	if (http_session->http_server) {
		if (http_session->abort) {
			http_server_close(http_session, -1);
		} else {
			//http_server_read_resume(http_session);//continue read body if need
		}
	} else {
		http_session_close(http_session);
	}
}

static void http_client_post_append(struct http_session_t *http_session, const char *buf, size_t len)
{
	struct http_request_t *http_request = &http_session->http_request;
	struct http_client_t *http_client = http_session->http_client;
	struct connection_t *connection = http_client->connection;
	struct buffer_t *buffer = NULL;
	size_t ncopy = 0;
	while (len > 0) {
		buffer = fifo_tail(&http_session->body_fifo);
		if (buffer == NULL || buffer->len == buffer->size) {
			buffer = buffer_alloc(PAGE_SIZE);
			fifo_push_tail(&http_session->body_fifo, buffer);
		}
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
		} else if (fifo_len(&http_session->post_fifo) <= fifo_size(&http_session->post_fifo) / 2) {
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
	nparse = http_parser_execute(&http_client->parser, &request_parser_settings, buf, nread);
	LOG(LOG_DEBUG, "%s %s fd=%d nread=%d nparse=%d\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd, nread, nparse);
	if (nparse < nread && http_request->parse_state < PARSER_HEADER_DONE) {
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
		http_client_post_append(http_session, buf + nparse, nread - nparse);
	}
	connection_read_enable(connection, http_client_body_read);
	if (http_request_cacheable(http_request)) {
		http_session_cache_lookup(http_session);
	} else {
		http_session_body_read(http_session);
	}
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
	while (total_read < MAX_READ) {
		buffer = fifo_tail(&http_session->post_fifo);
		if (buffer == NULL || buffer_full(buffer)) {
			if (fifo_len(&http_session->post_fifo) < fifo_size(&http_session->post_fifo)) {
				buffer = buffer_alloc(PAGE_SIZE);
				fifo_push_tail(&http_session->post_fifo, buffer);
			} else {
				buffer = NULL;
				break;
			}
		}
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
		http_client->body_offset_expect = http_client->body_offset + length;
		string_strcat_printf(&http_client->reply_header, "Content-Range: bytes %"PRId64"-%"PRId64"/%"PRId64"\r\n",
				http_client->body_offset, http_client->body_offset_expect - 1, http_reply->content_length);
		string_strcat_printf(&http_client->reply_header, "Content-Length: %"PRId64"\r\n", length);
	} else {
		http_client->body_offset = 0;
		if (length >= 0) {
			string_strcat_printf(&http_client->reply_header, "Content-Length: %"PRId64"\r\n", length);
			http_client->body_offset_expect = length;
		} else {
			http_client->body_offset_expect = INT64_MAX;
		}
	}
	string_strcat(&http_client->reply_header, "Via: http_cache\r\n");
	string_strcat(&http_client->reply_header, "\r\n");
	LOG(LOG_INFO, "%s %s reply=\n%s", http_session->epoll_thread->name, string_buf(&http_request->url), string_buf(&http_client->reply_header));
	http_client->body_offset_current = http_client->body_offset;
}

static void http_client_build_error_reply(struct http_session_t *http_session, int status_code)
{
	struct http_request_t *http_request = &http_session->http_request;
	struct http_client_t *http_client = http_session->http_client;
	assert(string_strlen(&http_client->reply_header) == 0);
	http_client->body_offset = 0;
	http_client->body_offset_current = 0;
	http_client->body_offset_expect = 0;
	string_strcat_printf(&http_client->reply_header, "HTTP/%d.%d %s\r\n", 1, 1, http_status_reasons_get(status_code));
	string_strcat(&http_client->reply_header, "Via: cache_client\r\n");
	string_strcat(&http_client->reply_header, "\r\n");
	LOG(LOG_INFO, "%s %s reply=\n%s", http_session->epoll_thread->name, string_buf(&http_request->url), string_buf(&http_client->reply_header));
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
	struct buffer_t *buffer = NULL;
	char *buf = NULL;
	size_t len = 0;
	ssize_t nwrite = 0;
	size_t total_write = 0;
	int error = 0;
	assert(connection == http_client->connection);
	assert(connection->epoll_thread == http_session->epoll_thread);
	while ((buffer = fifo_head(&http_session->body_fifo)) && http_client->body_offset_current < http_client->body_offset_expect && total_write < MAX_WRITE) {
		if (http_client->body_offset_current >= http_session->body_low + buffer->len) {
			if (buffer_full(buffer)) {
				fifo_pop_head(&http_session->body_fifo, (void **)&buffer);
				http_session->body_low += buffer->len;
				buffer_unref(buffer);
				continue;
			} else {
				buffer = NULL;
				break;
			}
		}
		nwrite = (ssize_t)(http_client->body_offset_current - http_session->body_low);
		buf = buffer->buf + nwrite;
		len = buffer->len - nwrite;
		nwrite = http_send(connection->fd, buf, MIN(len, http_client->body_offset_expect - http_client->body_offset_current), 0);
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
			fifo_pop_head(&http_session->body_fifo, (void **)&buffer);
			http_session->body_low += buffer->len;
			buffer_unref(buffer);
		}
		http_client->body_offset_current += nwrite;
		total_write += nwrite;
	}
	LOG(LOG_DEBUG, "%s %s fd=%d total_write=%d\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd, total_write);
	if (error == 0 && http_client->body_offset_current < http_client->body_offset_expect) {
		if (buffer) {
			connection_write_enable(connection, http_client_body_write);//read write next event loop
		} else {
			LOG(LOG_DEBUG, "%s %s fd=%d buffer empty\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd);
			connection_write_disable(connection);
		}
		http_session_body_read(http_session);
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
	http_server->http_reply = http_reply_alloc();
	http_parser_init(&http_server->parser, HTTP_RESPONSE);
	http_server->parser.data = http_server->http_reply;

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
	LOG(LOG_INFO, "%s %s fd=%d body_offset=%"PRId64" body_recv_size=%"PRId64" body_expect_size=%"PRId64" error_code=%d\n",
			http_session->epoll_thread->name, string_buf(&http_request->url), connection? connection->fd:0,
			http_server->body_offset, http_session->body_high - http_server->body_offset,
			http_server->body_offset_expect - http_server->body_offset, error_code);
	if (connection) {
		connection_close(connection, CONNECTION_FREE_DELAY);
	}
	if (http_server->range) {
		http_free(http_server->range);
	}
	string_clean(&http_server->request_header);
	http_reply_free(http_server->http_reply);
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
	struct http_request_t *http_request = &http_session->http_request;
	struct http_server_t *http_server = http_session->http_server;
	if (http_server && http_server->connection && http_server->connected) {
		if (http_server->request_header_send_size < string_strlen(&http_server->request_header)) {
			connection_write_enable(http_server->connection, http_server_header_write);
		} else if (http_server->post_offset_current < http_request->content_length) {
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
	} else if (http_request->content_length >= 0) {
		http_server_body_write(connection);
	}
}

static void http_server_body_write(struct connection_t *connection)
{
	struct http_session_t *http_session = connection->arg;
	struct http_request_t *http_request = &http_session->http_request;
	struct http_server_t *http_server = http_session->http_server;
	struct buffer_t *buffer = NULL;
	char *buf = NULL;
	ssize_t len = 0;
	ssize_t nwrite = 0;
	size_t total_write = 0;
	int error = 0;
	assert(connection == http_server->connection);
	assert(connection->epoll_thread == http_session->epoll_thread);
	while ((buffer = fifo_head(&http_session->post_fifo)) && http_server->post_offset_current < http_request->content_length && total_write < MAX_WRITE) {
		if (http_server->post_offset_current >= http_session->post_low + buffer->len) {
			if (buffer_full(buffer)) {
				fifo_pop_head(&http_session->post_fifo, (void **)&buffer);
				http_session->post_low += buffer->len;
				buffer_unref(buffer);
				continue;
			} else {
				buffer = NULL;
				break;
			}
		}
		nwrite = (ssize_t)(http_server->post_offset_current - http_session->post_low);
		buf = buffer->buf + nwrite;
		len = buffer->len - nwrite;
		nwrite = http_send(connection->fd, buf, MIN(len, http_request->content_length - http_server->post_offset_current), 0);
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
		http_server->post_offset_current += nwrite;
		if (buffer_full(buffer) && buf + nwrite == buffer->buf + buffer->len) {
			fifo_pop_head(&http_session->post_fifo, (void **)&buffer);
			http_session->post_low += buffer->len;
			buffer_unref(buffer);
		}
	}
	LOG(LOG_DEBUG, "%s %s fd=%d total_write=%d\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd, total_write);
	http_client_read_resume(http_session);
	if (error) {
		http_server_close(http_session, error);
		return;
	}
	if (http_server->post_offset_current < http_request->content_length) {
		if (buffer) {
			connection_write_enable(connection, http_server_body_write);//read write next event loop
		} else {
			LOG(LOG_DEBUG, "%s %s fd=%d buffer empty\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd);
			connection_write_disable(connection);
		}
	} else {
		LOG(LOG_DEBUG, "%s %s fd=%d body write done body_size=%"PRId64"\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd,
				http_server->post_offset_current);
		connection_write_disable(connection);
	}
}

static void http_session_body_append(struct http_session_t *http_session, const char *buf, size_t len)
{
	struct http_request_t *http_request = &http_session->http_request;
	struct http_server_t *http_server = http_session->http_server;
	struct cache_client_t *cache_client = http_session->cache_client;
	struct connection_t *connection = http_server->connection;
	struct buffer_t *buffer = NULL;
	size_t ncopy = 0;
	while (len > 0 && http_session->body_high < http_server->body_offset_expect) {
		if (cache_client && fifo_len(&cache_client->body_fifo) == fifo_size(&cache_client->body_fifo)) {
			assert(0);
		}
		buffer = fifo_tail(&http_session->body_fifo);
		if (buffer == NULL || buffer_full(buffer)) {
			buffer = buffer_alloc(PAGE_SIZE);
			fifo_push_tail(&http_session->body_fifo, buffer);
		}
		ncopy = buffer->size - buffer->len;
		if (ncopy > len) {
			ncopy = len;
		}
		if (http_session->body_high + ncopy > http_server->body_offset_expect) {
			ncopy = http_server->body_offset_expect - http_session->body_high;
		}
		memcpy(buffer->buf + buffer->len, buf, ncopy);
		buf += ncopy;
		len -= ncopy;
		buffer->len += ncopy;
		http_session->body_high += ncopy;
		if (cache_client && buffer_full(buffer)) {
			cache_client_body_append(http_session->cache_client, buffer);
		}
		LOG(LOG_DEBUG, "%s %s fd=%d ncopy=%d\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd, ncopy);
	}
}

static void http_server_header_read(struct connection_t *connection)
{
	struct http_session_t *http_session = connection->arg;
	struct http_request_t *http_request = &http_session->http_request;
	struct http_server_t *http_server = http_session->http_server;
	struct http_reply_t *http_reply = http_server->http_reply;
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
	if (nparse < nread) {
		body_size = nread - nparse;
		body_size = MIN(nread - nparse, http_server->body_offset_expect - http_session->body_high);
		http_session_body_append(http_session, buf + nparse, body_size);
		if (http_server->chunked) {
			http_server_parse_chunk(http_session, buf + nparse, body_size);
		}
	}
	if (http_session->body_high < http_server->body_offset_expect) {
		http_server_body_read(connection);
	} else {
		http_server_close(http_session, 0);
	}
}

static void http_server_body_read_resume(struct http_session_t *http_session)
{
	struct http_server_t *http_server = http_session->http_server;
	if (http_server == NULL) {
		return;
	}
	if (http_server->connection && http_server->connected) {
		if (http_server->http_reply->parse_state < PARSER_HEADER_DONE) {
			connection_read_enable(http_server->connection, http_server_header_read);
		} else if (fifo_len(&http_session->body_fifo) <= fifo_size(&http_session->body_fifo) / 2) {
			assert(http_session->body_high < http_server->body_offset_expect);
			connection_read_enable(http_server->connection, http_server_body_read);
		}
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
	if (connection->fd == 19) assert(0);
	while (http_session->body_high < http_server->body_offset_expect && total_read < MAX_READ) {
		if (cache_client && fifo_len(&cache_client->body_fifo) == fifo_size(&cache_client->body_fifo)) {
			break;
		}
		buffer = fifo_tail(&http_session->body_fifo);
		if (buffer == NULL || buffer_full(buffer)) {
			if (fifo_len(&http_session->body_fifo) < fifo_size(&http_session->body_fifo)) {
				buffer = buffer_alloc(PAGE_SIZE);
				fifo_push_tail(&http_session->body_fifo, buffer);
			} else {
				buffer = NULL;
				break;
			}
		}
		buf = buffer->buf + buffer->len;
		len = buffer->size - buffer->len;
		nread = http_recv(connection->fd, buf, MIN(len, http_server->body_offset_expect - http_session->body_high), 0);
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
		if (cache_client && buffer_full(buffer)) {
			cache_client_body_append(cache_client, buffer);
		}
		if (http_server->chunked) {
			http_server_parse_chunk(http_session, buf, nread);
		}
	}
	LOG(LOG_DEBUG, "%s %s fd=%d total_read=%d\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd, total_read);
	if (total_read > 0) {
		http_session_body_write(http_session);
	}
	if (error == 0 && http_session->body_high < http_server->body_offset_expect) {
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
	struct cache_client_t *cache_client = http_session->cache_client;
	struct connection_t *connection = http_server->connection;
	struct http_reply_t *http_reply = http_server->http_reply;
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
				http_server->body_offset_expect = content_range->end + 1;
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
				http_server->body_offset_expect = INT64_MAX;
			} else {
				http_header_del(&http_reply->header, "Transfer-Encoding");
			}
		} else if ((str = http_header_find(&http_reply->header, "Content-Length"))) {
			http_reply->content_length = atoll(str);
			http_server->body_offset_expect = http_reply->content_length;
		}
		http_session->body_low = http_session->body_high = 0;
		if (http_reply->status_code == 204 || http_reply->status_code == 304) {
			http_server->body_offset_expect = http_server->body_offset;
		}
	}
	if (http_request->method == HTTP_HEAD) {
		http_server->body_offset_expect = http_server->body_offset;
	}
	if (http_session->body_low == 0 && http_session->body_high == 0) {
		http_session->body_low = http_session->body_high = http_server->body_offset;
	} else {
		// todo check range if error return
	}
	if (http_client) {
		if (string_strlen(&http_client->reply_header) == 0) {
			http_client_build_reply(http_session, http_reply);
			connection_write_enable(http_client->connection, http_client_header_write);
		} else if (http_reply->status_code != 200) {
			LOG(LOG_ERROR, "%s %s fd=%d client need abort\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd);
			return -1;
		}
	}
	if (cache_client) {
		if (http_reply_cacheable(http_reply)) {
			cache_client_header_write(cache_client, http_reply);
		} else {
			LOG(LOG_DEBUG, "%s %s fd=%d reply disable cache\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd);
			cache_client_close(cache_client, 1);
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
			http_server->body_offset_expect = http_session->body_high;
			if (http_client) {
				http_client->body_offset_expect = http_session->body_high;
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
	struct http_reply_t *http_reply = http_server->http_reply;
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

static struct http_reply_t* http_reply_alloc()
{
	struct http_reply_t *http_reply = NULL;
	http_reply = http_malloc(sizeof(struct http_reply_t));
	memset(http_reply, 0, sizeof(struct http_reply_t));
	http_header_init(&http_reply->header);
	http_reply->content_length = -1;
	return http_reply;
}

static void http_reply_copy(struct http_reply_t *dest, struct http_reply_t *src)
{
	dest->status_code = src->status_code;
	dest->http_major = src->http_major;
	dest->http_minor = src->http_minor;
	http_header_copy(&dest->header, &src->header);
	dest->content_length = src->content_length;
	dest->parse_state = src->parse_state;
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

static void cache_client_dispatch(struct cache_client_t *cache_client)
{
	struct http_session_t *http_session = cache_client->http_session;
	struct http_request_t *http_request = &http_session->http_request;
	struct http_client_t *http_client = http_session->http_client;
	struct connection_t *connection = http_client->connection;
	struct cache_t *cache = cache_client->cache;
	struct epoll_thread_t *epoll_thread = cache->epoll_thread;
	assert(connection->epoll_thread == http_session->epoll_thread);
	assert(cache_client->aio.epoll_thread == http_session->epoll_thread);
	assert(cache_client->aio.epoll_thread != epoll_thread);
	cache_client->aio.epoll_thread = epoll_thread;// dispatch
	LOG(LOG_INFO, "%s %s ->%s dispatch\n", http_session->epoll_thread->name, string_buf(&http_request->url), epoll_thread->name);
	connection_read_disable(connection);
	connection_write_disable(connection);// do nothing
	assert(connection->event == 0);
	list_del(&http_session->node);
	http_session->epoll_thread = NULL;
	connection->epoll_thread = NULL;
	aio_summit(&cache_client->aio, NULL, cache_client_dispatch_done);
}

static void cache_client_dispatch_done(struct aio_t *aio)
{
	struct cache_client_t *cache_client = aio->callback_data;
	struct cache_t *cache = cache_client->cache;
	struct http_session_t *http_session = cache_client->http_session;
	struct http_request_t *http_request = &http_session->http_request;
	struct http_client_t *http_client = http_session->http_client;
	struct connection_t *connection = http_client->connection;
	struct epoll_thread_t *epoll_thread = aio->epoll_thread;
	assert(epoll_thread == cache->epoll_thread);
	http_session->epoll_thread = epoll_thread;
	list_add_tail(&http_session->node, &epoll_thread->http_session_list);
	connection->epoll_thread = epoll_thread;
	LOG(LOG_INFO, "%s %s dispatch done\n", http_session->epoll_thread->name, string_buf(&http_request->url));
	connection_read_enable(connection, http_client_body_read);
}

static void http_session_cache_lookup(struct http_session_t *http_session)
{
	struct http_request_t *http_request = &http_session->http_request;
	struct http_server_t *http_server = http_session->http_server;
	struct cache_client_t *cache_client = http_session->cache_client;
	struct cache_t *cache = NULL;
	struct cache_file_t *cache_file = NULL;
	assert(http_server == NULL);
	assert(cache_client == NULL);
	http_session->cache_client = cache_client = cache_client_alloc();
	cache_client->http_session = http_session;
	cache_client->aio.epoll_thread = http_session->epoll_thread;

	cache_table_lock();
	cache = cache_table_lookup(string_buf(&http_request->url));
	if (cache == NULL) {
		cache = cache_alloc();
		cache->key = http_strdup(string_buf(&http_request->url));
		cache->url = http_strdup(string_buf(&http_request->url));
		cache_table_insert(cache);
	}
	if (cache->lock++ == 0) {
		assert(cache->epoll_thread == NULL);
		cache->epoll_thread = epoll_thread_select(cache_client->aio.epoll_thread);
	} else {
		assert(cache->epoll_thread != NULL);
	}
	cache_client->cache = cache;
	cache_table_unlock();

	if (cache_client->aio.epoll_thread != cache->epoll_thread) {
		cache_client_dispatch(cache_client);
		return;
	}
	if (cache->file_number == 0) {
		http_session_body_read(http_session);
		return;
	}
	cache_file = cache->cache_file;
	if (cache_file == NULL) {
		cache->cache_file = cache_file = cache_file_alloc();
		cache_file_path_init(cache_file, cache->file_number);
		LOG(LOG_DEBUG, "%s %s %s open\n", cache_client->aio.epoll_thread->name, cache->url, cache_file->path);
		http_parser_init(&cache_client->parser, HTTP_RESPONSE);
		cache_client->parser.data = cache_file->http_reply;
		cache_file->header_buf = http_malloc(PAGE_SIZE);
		cache_client->aio.iovec[0].buffer = cache_file;
		cache_client->aio.iovec[0].buf = cache_file->header_buf;
		cache_client->aio.iovec[0].buf_size = PAGE_SIZE;
		cache_client->aio.iovec[0].buf_len = 0;
		cache_client->aio.iovec_len = 1;
		cache_client->delay = CACHE_DELAY_READ;
		aio_summit(&cache_client->aio, cache_file_open_aio, cache_file_open_done);
	} else if (cache_file->fd == 0) {
		LOG(LOG_DEBUG, "%s %s %s open wait\n", cache_client->aio.epoll_thread->name, cache->url, cache_file->path);
		cache_client->delay = CACHE_DELAY_READ;
		cache_client->aio.status = AIO_STATUS_SUMMIT;
		list_add_tail(&cache_client->aio.node, &cache_file->delay_list);
	} else if (cache_file->fd > 0) {
		LOG(LOG_DEBUG, "%s %s %s open done\n", cache_client->aio.epoll_thread->name, cache->url, cache_file->path);
		cache_client->aio.fd = cache_file->fd;
		http_session_cache_hit(http_session);
	} else {
		LOG(LOG_DEBUG, "%s %s %s open fail\n", cache_client->aio.epoll_thread->name, cache->url, cache_file->path);
		cache_client->aio.fd = -1;
		cache_client_close(cache_client, 1);
		http_session_body_read(http_session);
	}
}

static void http_session_cache_hit(struct http_session_t *http_session)
{
	struct http_client_t *http_client = http_session->http_client;
	struct cache_client_t *cache_client = http_session->cache_client;
	struct cache_t *cache = cache_client->cache;
	struct cache_file_t *cache_file = cache->cache_file;
	assert(http_client != NULL);
	if (string_strlen(&http_client->reply_header) == 0) {
		assert(cache_file->fd > 0 && cache_file->http_reply);
		http_client_build_reply(http_session, cache_file->http_reply);
	}
	http_session_body_read(http_session);
}

static void http_session_body_read(struct http_session_t *http_session)
{
	struct http_request_t *http_request = &http_session->http_request;
	struct http_client_t *http_client = http_session->http_client;
	struct http_server_t *http_server = http_session->http_server;
	struct cache_client_t *cache_client = http_session->cache_client;
	struct http_range_t range = {0};
	assert(http_client != NULL);
	if (http_server) {
		http_server_body_read_resume(http_session);
		return;
	}
	if (string_strlen(&http_client->reply_header) > 0) {
		if (http_session->body_high < http_client->body_offset_expect) {
			range.offset = http_session->body_high;
			range.length = http_client->body_offset_expect - range.offset;
			LOG(LOG_DEBUG, "%s %s range offset=%"PRId64" length=%"PRId64"\n", http_session->epoll_thread->name, string_buf(&http_request->url), range.offset, range.length);
		} else {
			LOG(LOG_DEBUG, "%s %s noting to read\n", http_session->epoll_thread->name, string_buf(&http_request->url));
			return;
		}
	}
	if (range.length > 0) {
		if (cache_client) {
			if (!aio_busy(&cache_client->aio)) {
				if (cache_file_body_read(cache_client, range.offset, range.offset + range.length) == 0) {
					http_server_create(http_session, &range);
				}
			}
		} else {
			http_server_create(http_session, &range);
		}
	} else {
		http_server_create(http_session, NULL);
	}
}

static void http_session_body_write(struct http_session_t *http_session)
{
	struct http_client_t *http_client = http_session->http_client;
	struct buffer_t *buffer = NULL;
	if (http_client) {
		if (string_strlen(&http_client->reply_header) > http_client->reply_header_send_size) {
			connection_write_enable(http_client->connection, http_client_header_write);
		} else {
			connection_write_enable(http_client->connection, http_client_body_write);
		}
	} else {
		while (fifo_len(&http_session->body_fifo) > 0) {
			buffer = fifo_head(&http_session->body_fifo);
			if (buffer_full(buffer)) {
				fifo_pop_head(&http_session->body_fifo, (void **)&buffer);
				http_session->body_low += buffer->len;
				buffer_unref(buffer);
			} else {
				break;
			}
		}
	}	
}

static void cache_client_dump_header(struct cache_client_t *cache_client)
{
	struct cache_t *cache = cache_client->cache;
	struct cache_file_t *cache_file = cache->cache_file;
	struct http_reply_t *http_reply = cache_file->http_reply;
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
	LOG(LOG_INFO, "%s %s header_size=%d bitmap_bit_size=%d bitmap_byte_size=%d bitmap_size=%d\n",
			cache_client->aio.epoll_thread->name, cache->url, cache_file->header_size, cache_file->bitmap_bit_size, cache_file->bitmap_byte_size, cache_file->bitmap_size);
	string_clean(&string);
}

static void cache_client_header_build(struct cache_client_t *cache_client, struct http_reply_t *http_reply)
{
	struct cache_t *cache = cache_client->cache;
	struct cache_file_t *cache_file = cache->cache_file;
	struct string_t string;
	string_init_size(&string, PAGE_SIZE);
	struct http_header_entry_t *header_entry;
	assert(cache_file->bitmap_bit_size == 0);
	http_reply_copy(cache_file->http_reply, http_reply);
	string_strcat_printf(&string, "HTTP/%d.%d %s\r\n", 
			cache_file->http_reply->http_major, cache_file->http_reply->http_minor, http_status_reasons_get(cache_file->http_reply->status_code));
	list_for_each_entry(header_entry, &cache_file->http_reply->header.header_list, header_entry_node) {
		string_strcat(&string, string_buf(&header_entry->field_string));
		string_strcat(&string, ": ");
		string_strcat(&string, string_buf(&header_entry->value_string));
		string_strcat(&string, "\r\n");
	}    
	string_strcat_printf(&string, "X-Internal-Url: %s\r\n", cache->url);
	string_strcat_printf(&string, "X-Internal-Block-Size: %d\r\n", BLOCK_SIZE);
	string_strcat(&string, "\r\n"); 
	memset(string_buf(&string) + string_strlen(&string), 0, string_strsize(&string) - string_strlen(&string));
	cache_file->header_size = string_strlen(&string);
	cache_file->header_buf = string_buf(&string);
	cache_file_bitmap_init(cache_file, cache_file->http_reply->content_length, BLOCK_SIZE);
	cache_client_dump_header(cache_client);
}

static void cache_client_header_write(struct cache_client_t *cache_client, struct http_reply_t *http_reply)
{
	struct aio_t *aio = &cache_client->aio;
	struct cache_t *cache = cache_client->cache;
	struct cache_file_t *cache_file = cache->cache_file;
	struct http_session_t *http_session = cache_client->http_session;
	struct http_server_t *http_server = http_session->http_server;
	assert(!aio_busy(&cache_client->aio));
	cache_client->body_pos = http_server->body_offset;
	if (cache_file == NULL) {
		assert(cache->file_number == 0);
		cache->cache_file = cache_file = cache_file_alloc();
		LOG(LOG_DEBUG, "%s %s cache file create start\n", cache_client->aio.epoll_thread->name, cache->url);
		cache_client_header_build(cache_client, http_reply);
		aio->iovec[0].buffer = cache_file;
		aio->iovec[0].buf = cache_file->header_buf;
		aio->iovec[0].buf_size = cache_file->header_size;
		aio->iovec[0].buf_len = 0;
		aio->iovec_len = 1;
		cache_client->delay = CACHE_DELAY_WRITE;
		aio_summit(&cache_client->aio, cache_file_open_aio, cache_file_open_done);
	} else if (cache_file->fd == 0) {
		LOG(LOG_DEBUG, "%s %s cache file wait for create\n", cache_client->aio.epoll_thread->name, cache->url);
		cache_client->delay = CACHE_DELAY_WRITE;
		cache_client->aio.status = AIO_STATUS_SUMMIT;
		list_add_tail(&cache_client->aio.node, &cache_file->delay_list);
	} else if (cache_file->fd > 0) {
		aio->fd = cache_file->fd;
		cache_client_do_write(cache_client);
	} else {
		aio->fd = -1;
		cache_client_close(cache_client, 1);
	}
}

static void cache_client_body_append(struct cache_client_t *cache_client, struct buffer_t *buffer)
{
	struct cache_t *cache = cache_client->cache;
	assert(fifo_len(&cache_client->body_fifo) < fifo_size(&cache_client->body_fifo));
	fifo_push_tail(&cache_client->body_fifo, buffer_ref(buffer));
	LOG(LOG_DEBUG, "%s %s len=%d\n", cache_client->aio.epoll_thread->name, cache->url, buffer->len);
	if (!aio_busy(&cache_client->aio)) {
		cache_client_do_write(cache_client);
	}
}

static void cache_client_body_append_end(struct cache_client_t *cache_client)
{
	struct http_session_t *http_session = cache_client->http_session;
	struct cache_t *cache = cache_client->cache;
	struct cache_file_t *cache_file = cache->cache_file;
	struct buffer_t *buffer = NULL;
	cache_client->bitmap_flush = 1;
	buffer = fifo_tail(&http_session->body_fifo);
	if (buffer && buffer->len > 0 && !buffer_full(buffer)) {
		if (http_session->body_high == cache_file->http_reply->content_length) {
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
		assert(byte_pos < cache_file->bitmap_size);
		cache_file->bitmap[byte_pos] |= (1 << (bit_pos & 0x7));
		cache_client->bitmap_pos += cache_file->bitmap_bit_size;
	}
	if (cache_client->body_pos == cache_file->http_reply->content_length) {
		byte_pos = cache_client->bitmap_pos / cache_file->bitmap_byte_size;
		cache_file->bitmap[byte_pos] = 0xff;
		cache_client->bitmap_pos = cache_file->http_reply->content_length;
	}
}

static void cache_file_open_aio(struct aio_t *aio)
{
	struct cache_file_t *cache_file = aio->iovec[0].buffer;
	aio->flags = O_RDWR;
	if (cache_file->file_number == 0) {
		cache_file_number_alloc(cache_file);
		aio->flags |= O_CREAT|O_TRUNC;
	}
	if (cache_file->file_number > 0) {
		aio_open(aio, cache_file->path, aio->flags, S_IRWXU | S_IRWXG | S_IRWXO);
	} else {
		aio->fd = -1;
		aio->error = -1;
		aio->error_str = "cache file number alloc fail";
	}
	if (aio->error) {
		return;
	}
	assert(aio->offset == 0);
	if (aio->flags == O_RDWR) {
		aio_readv(aio);
	} else {
		aio_writev(aio);
	}
}

static void cache_file_open_done(struct aio_t *aio)
{
	struct cache_client_t *cache_client = aio->callback_data;
	struct cache_t *cache = cache_client->cache;
	struct cache_file_t *cache_file = cache->cache_file;
	if (aio->flags == O_RDWR) {
		cache_file_header_read_done(aio);
	} else {
		assert(cache->file_number == 0);
		cache->file_number = cache_file->file_number;
		cache_file_header_write_done(aio);
	}
}

static void cache_client_resume(struct cache_client_t *cache_client, int abort)
{
	struct http_session_t *http_session = NULL;
	struct cache_t *cache = cache_client->cache;
	struct cache_file_t *cache_file = cache->cache_file;
	struct aio_t *aio = NULL;
	assert(cache_file->fd == 0);
	assert(cache_client->aio.fd != 0);
	cache_file->fd = cache_client->aio.fd;
	list_add(&cache_client->aio.node, &cache_file->delay_list);
	while (!list_empty(&cache_file->delay_list)) {
		aio = d_list_head(&cache_file->delay_list, struct aio_t, node);
		list_del(&aio->node);
		aio->status = AIO_STATUS_DONE;
		aio->fd = cache_file->fd;
		cache_client = aio->callback_data;
		http_session = cache_client->http_session;
		if (cache_client->delay == CACHE_DELAY_READ) {
			if (http_session == NULL) {
				LOG(LOG_DEBUG, "%s %s %s fd=%d cache_client session null\n", cache_client->aio.epoll_thread->name, cache->url, cache_file->path, cache_client->aio.fd);
				cache_client_close(cache_client, abort? 1:0);
			} else {
				if (abort) {
					LOG(LOG_ERROR, "%s %s %s fd=%d cache_client read abort\n", cache_client->aio.epoll_thread->name, cache->url, cache_file->path, cache_client->aio.fd);
					cache_client_close(cache_client, 1);
					http_session_body_read(http_session);
				} else {
					LOG(LOG_DEBUG, "%s %s %s fd=%d cache_client read\n", cache_client->aio.epoll_thread->name, cache->url, cache_file->path, cache_client->aio.fd);
					http_session_cache_hit(http_session);
				}
			}
		} else if (cache_client->delay == CACHE_DELAY_WRITE) {
			if (abort) {
				LOG(LOG_ERROR, "%s %s %s fd=%d cache_client write abort\n", cache_client->aio.epoll_thread->name, cache->url, cache_file->path, cache_client->aio.fd);
				cache_client_close(cache_client, 1);
			} else {
				cache_client_do_write(cache_client);
			}
		} else {
			LOG(LOG_ERROR, "%s %s %s fd=%d cache_client abort\n", cache_client->aio.epoll_thread->name, cache->url, cache_file->path, cache_client->aio.fd);
			assert(0);
		}
	}
}

static void cache_client_do_write(struct cache_client_t *cache_client)
{
	struct aio_t *aio = &cache_client->aio;
	struct cache_t *cache = cache_client->cache;
	struct cache_file_t *cache_file = cache->cache_file;
	struct buffer_t *buffer = NULL;
	size_t buffer_size = 0;
	assert(!aio_busy(&cache_client->aio));
	assert(aio->fd > 0);
	aio->iovec_len = 0;
	while (fifo_len(&cache_client->body_fifo) > 0 && aio->iovec_len < MAX_LOOP) {
		fifo_pop_head(&cache_client->body_fifo, (void **)&buffer);
		aio->iovec[aio->iovec_len].buffer = buffer;
		aio->iovec[aio->iovec_len].buf = buffer->buf;
		aio->iovec[aio->iovec_len].buf_size = buffer->len;
		aio->iovec[aio->iovec_len].buf_len = 0;
		buffer_size += aio->iovec[aio->iovec_len].buf_size;
		aio->iovec_len++;
	}
	if (aio->iovec_len > 0) {
		if (cache_client->http_session) {
			http_server_body_read_resume(cache_client->http_session);
		}
		LOG(LOG_DEBUG, "%s %s %s fd=%d buffer_size=%d\n", cache_client->aio.epoll_thread->name, cache->url, cache_file->path, cache_client->aio.fd, buffer_size);
		cache_client->aio.offset = cache_client->body_pos + cache_file->header_size + cache_file->bitmap_size;
		aio_summit(&cache_client->aio, aio_writev, cache_client_body_write_done);
	} else if (cache_client->bitmap_flush && cache_file->bitmap) {
		cache_client->bitmap_flush = 0;
		cache_client->aio.offset = cache_file->header_size;
		aio->iovec[0].buffer = NULL;
		aio->iovec[0].buf = cache_file->bitmap;
		aio->iovec[0].buf_size = cache_file->bitmap_size;
		aio->iovec[0].buf_len = 0;
		aio->iovec_len = 1;
		LOG(LOG_DEBUG, "%s %s %s fd=%d bitmap_size=%d\n", cache_client->aio.epoll_thread->name, cache->url, cache_file->path, cache_client->aio.fd, cache_file->bitmap_size);
		aio_summit(&cache_client->aio, aio_writev, cache_client_bitmap_write_done);
	} else if (cache_client->http_session == NULL) {
		cache_client_close(cache_client, 0);
	} else {
		LOG(LOG_DEBUG, "%s %s %s fd=%d nothing write\n", cache_client->aio.epoll_thread->name, cache->url, cache_file->path, cache_client->aio.fd);
	}
}

static void cache_file_header_write_done(struct aio_t *aio)
{
	struct cache_client_t *cache_client = aio->callback_data;
	struct cache_t *cache = cache_client->cache;
	struct cache_file_t *cache_file = cache->cache_file;
	size_t nread = aio->iovec[0].buf_len;
	assert(aio->iovec[0].buf_size == cache_file->header_size);
	if (nread < cache_file->header_size) {
		LOG(LOG_ERROR, "%s %s %s fd=%d header_size=%d nread=%d error:%s\n", 
				cache_client->aio.epoll_thread->name, cache->url, cache_file->path, aio->fd, cache_file->header_size, nread, aio->error_str);
		cache_client_resume(cache_client, 1);
		return;
	}
	LOG(LOG_DEBUG, "%s %s %s fd=%d header_size=%d nread=%d\n", 
			cache_client->aio.epoll_thread->name, cache->url, cache_file->path, aio->fd, cache_file->header_size, nread);
	cache_client_resume(cache_client, 0);
}

static void cache_client_body_write_done(struct aio_t *aio)
{
	struct cache_client_t *cache_client = aio->callback_data;
	struct cache_t *cache = cache_client->cache;
	struct cache_file_t *cache_file = cache->cache_file;
	size_t buffer_size = 0;
	size_t nwrite = 0;
	int i = 0;
	for (i = 0; i < aio->iovec_len; i++) {
		buffer_size += aio->iovec[i].buf_size;
		nwrite += aio->iovec[i].buf_len;
		buffer_unref(aio->iovec[i].buffer);
	}
	cache_client->body_pos += nwrite;
	cache_client_bitmap_update(cache_client);
	if (nwrite < buffer_size) {
		LOG(LOG_ERROR, "%s %s %s fd=%d buffer_size=%d nwrite=%d error:%s\n",
				cache_client->aio.epoll_thread->name, cache->url, cache_file->path, aio->fd, buffer_size, nwrite, aio->error_str);
		cache_client_close(cache_client, 1);
	} else {
		LOG(LOG_DEBUG, "%s %s %s fd=%d buffer_size=%d nwrite=%d\n",
				cache_client->aio.epoll_thread->name, cache->url, cache_file->path, aio->fd, buffer_size, nwrite);
		assert(nwrite == buffer_size);
		cache_client_do_write(cache_client);
	}
}

static void cache_client_bitmap_write_done(struct aio_t *aio)
{
	struct cache_client_t *cache_client = aio->callback_data;
	struct cache_t *cache = cache_client->cache;
	struct cache_file_t *cache_file = cache->cache_file;
	size_t buf_size = aio->iovec[0].buf_size;
	size_t buf_len = aio->iovec[0].buf_len;
	assert(buf_size == cache_file->bitmap_size);
	if (buf_len < cache_file->bitmap_size) {
		LOG(LOG_ERROR, "%s %s %s fd=%d bitmap_size=%d nwrite=%d\n", cache_client->aio.epoll_thread->name, cache->url, cache_file->path, aio->fd, cache_file->bitmap_size, buf_len);
		cache_client_close(cache_client, 1);
	} else {
		LOG(LOG_DEBUG, "%s %s %s fd=%d bitmap_size=%d nwrite=%d\n", cache_client->aio.epoll_thread->name, cache->url, cache_file->path, aio->fd, cache_file->bitmap_size, buf_len);
		cache_client_do_write(cache_client);
	}
}

static void cache_file_header_read_done(struct aio_t *aio)
{
	struct cache_client_t *cache_client = aio->callback_data;
	struct cache_t *cache = cache_client->cache;
	struct cache_file_t *cache_file = cache->cache_file;
	struct http_reply_t *http_reply = cache_file->http_reply;
	const char *str = NULL;
	int block_size = 0;
	char *buf = aio->iovec[0].buf;
	size_t buf_size = aio->iovec[0].buf_size;
	size_t buf_len = aio->iovec[0].buf_len;
	size_t nparse = 0;
	if (buf_len == 0) {
		LOG(LOG_ERROR, "%s %s %s fd=%d buf_size=%d buf_len=%d error:%s\n", 
				cache_client->aio.epoll_thread->name, cache->url, cache_file->path, aio->fd, buf_size, buf_len, aio->error_str);
		cache_client_resume(cache_client, 1);
		return;
	}	
	nparse = http_parser_execute(&cache_client->parser, &reply_parser_settings, buf, buf_len);
	if (http_reply->parse_state < PARSER_HEADER_DONE) {
		if (nparse < buf_len) {
			LOG(LOG_ERROR, "%s %s %s fd=%d header_size=%d nparse=%d error: http parser error\n", 
					cache_client->aio.epoll_thread->name, cache->url, cache_file->path, aio->fd, buf_len, nparse);
			cache_client_resume(cache_client, 1);
		} else {
			aio->iovec[0].buffer = NULL;
			aio->iovec[0].buf_len = 0;
			aio->iovec_len = 1;
			aio_summit(aio, aio_readv, cache_file_header_read_done);
		}
		return;
	}
	if ((str = http_header_find(&http_reply->header, "Content-Length"))) {
		http_reply->content_length = atol(str);
	}
	if ((str = http_header_find(&http_reply->header, "X-Internal-Block-Size"))) {
		block_size = atoi(str);
	}
	http_header_del(&http_reply->header, "X-Internal-Url");
	http_header_del(&http_reply->header, "X-Internal-Block-Size");
	cache_file->header_size = aio->offset - (buf_len - nparse);
	cache_file_bitmap_init(cache_file, http_reply->content_length, block_size);
	cache_client_dump_header(cache_client);
	aio->offset = cache_file->header_size;
	aio->iovec[0].buffer = NULL;
	aio->iovec[0].buf = cache_file->bitmap;
	aio->iovec[0].buf_size = cache_file->bitmap_size;
	aio->iovec[0].buf_len = 0;
	aio->iovec_len = 1;
	if (buf_len - nparse >= aio->iovec[0].buf_size) {
		memcpy(aio->iovec[0].buf, buf + nparse, aio->iovec[0].buf_size);
		aio->iovec[0].buf_len = aio->iovec[0].buf_size;
		cache_client_bitmap_read_done(aio);
	} else {
		aio_summit(aio, aio_readv, cache_client_bitmap_read_done);
	}
}

static void cache_client_bitmap_read_done(struct aio_t *aio)
{
	struct cache_client_t *cache_client = aio->callback_data;
	struct cache_t *cache = cache_client->cache;
	struct cache_file_t *cache_file = cache->cache_file;
	size_t buf_size = aio->iovec[0].buf_size;
	size_t nread = aio->iovec[0].buf_len;
	assert(buf_size == cache_file->bitmap_size);
	if (nread < cache_file->bitmap_size) {
		LOG(LOG_ERROR, "%s %s %s fd=%d bitmap_size=%d nread=%d error:%s\n", 
				cache_client->aio.epoll_thread->name, cache->url, cache_file->path, aio->fd, cache_file->bitmap_size, nread, aio->error_str);
		cache_client_resume(cache_client, 1);
		return;
	}
	LOG(LOG_INFO, "%s %s %s fd=%d bitmap_size=%d nread=%d\n", 
			cache_client->aio.epoll_thread->name, cache->url, cache_file->path, aio->fd, cache_file->bitmap_size, nread);
	cache_client_resume(cache_client, 0);
}

static int cache_file_body_read(struct cache_client_t *cache_client, int64_t start, int64_t end)
{
	struct http_session_t *http_session = cache_client->http_session;
	struct cache_t *cache = cache_client->cache;
	struct aio_t *aio = &cache_client->aio;
	struct cache_file_t *cache_file = cache->cache_file;
	struct buffer_t *buffer = NULL;
	size_t buffer_size = 0;
	size_t byte_pos = 0;
	size_t bit_pos = 0;
	size_t check_size = MAX_LOOP * PAGE_SIZE;
	size_t hit_size = 0;
	if (check_size + start > end) {
		check_size = end - start;
	}
	if (cache_file->http_reply->content_length > 0) {
		while (hit_size < check_size) {
			byte_pos = (start + hit_size) / cache_file->bitmap_byte_size;
			bit_pos = (start + hit_size) / cache_file->bitmap_bit_size;
			if ((cache_file->bitmap[byte_pos] & (1 << (bit_pos & 0x7))) == 0) {
				break;
			}
			hit_size = (bit_pos + 1) * cache_file->bitmap_bit_size - start;
		}
		if (hit_size + start > cache_file->http_reply->content_length) {
			hit_size = cache_file->http_reply->content_length - start;
		}
	} else {
		hit_size = check_size;
	}
	aio->iovec_len = 0;
	if (hit_size > 0) {
		buffer = fifo_tail(&http_session->body_fifo);
		if (buffer && !buffer_full(buffer)) {
			aio->iovec[aio->iovec_len].buffer = buffer_ref(buffer);
			aio->iovec[aio->iovec_len].buf = buffer->buf + buffer->len;
			aio->iovec[aio->iovec_len].buf_size = MIN(hit_size, buffer->size - buffer->len);
			aio->iovec[aio->iovec_len].buf_len = 0;
			buffer_size += aio->iovec[aio->iovec_len].buf_size;
			aio->iovec_len++;
		}
		while (buffer_size < hit_size && buffer_size < check_size && fifo_len(&http_session->body_fifo) < fifo_size(&http_session->body_fifo) && aio->iovec_len < MAX_LOOP) {
			buffer = buffer_alloc(PAGE_SIZE);
			fifo_push_tail(&http_session->body_fifo, buffer);
			aio->iovec[aio->iovec_len].buffer = buffer_ref(buffer);
			aio->iovec[aio->iovec_len].buf = buffer->buf;
			aio->iovec[aio->iovec_len].buf_size = MIN(hit_size - buffer_size, buffer->size);
			aio->iovec[aio->iovec_len].buf_len = 0;
			buffer_size += aio->iovec[aio->iovec_len].buf_size;
			aio->iovec_len++;
		}
	}
	LOG(LOG_DEBUG, "%s %s %s fd=%d check_size=%d hit_size=%d buffer_size=%d\n", 
			cache_client->aio.epoll_thread->name, cache->url, cache_file->path, cache_client->aio.fd, check_size, hit_size, buffer_size);
	if (aio->iovec_len > 0) {
		cache_client->aio.offset = http_session->body_high + cache_file->header_size + cache_file->bitmap_size;
		aio_summit(&cache_client->aio, aio_readv, cache_file_body_read_done);
	}
	return aio->iovec_len;
}

static void cache_file_body_read_done(struct aio_t *aio)
{
	struct cache_client_t *cache_client = aio->callback_data;
	struct cache_t *cache = cache_client->cache;
	struct cache_file_t *cache_file = cache->cache_file;
	struct http_session_t *http_session = cache_client->http_session;
	struct buffer_t *buffer = NULL;
	size_t buffer_size = 0;
	size_t nread = 0;
	int i = 0;
	if (http_session && http_session->http_server) assert(0);
	for (i = 0; i < aio->iovec_len; i++) {
		buffer = aio->iovec[i].buffer;
		buffer_size += aio->iovec[i].buf_size;
		nread += aio->iovec[i].buf_len;
		buffer->len += aio->iovec[i].buf_len;
		buffer_unref(buffer);
	}
	if (nread == buffer_size) {
		LOG(LOG_DEBUG, "%s %s %s fd=%d buffer_size=%d nread=%d\n",
				cache_client->aio.epoll_thread->name, cache->url, cache_file->path, cache_client->aio.fd, buffer_size, nread);
		assert(nread == buffer_size);
	} else {
		LOG(LOG_ERROR, "%s %s %s fd=%d buffer_size=%d nread=%d error:%s\n",
				cache_client->aio.epoll_thread->name, cache->url, cache_file->path, aio->fd, buffer_size, nread, aio->error_str);
		cache_client_close(cache_client, 1);
		cache_client = NULL;
	}
	if (http_session) {
		http_session->body_high += nread;
		http_session_body_write(http_session);
	} else if (cache_client) {
		cache_client_close(cache_client, 0);
	}
}

static void cache_client_close(struct cache_client_t *cache_client, int del)
{
	struct http_session_t *http_session = cache_client->http_session;
	struct cache_t *cache = cache_client->cache;
	struct cache_file_t *cache_file = cache->cache_file;
	int64_t file_number = 0;// for delete
	if (http_session) {
		http_session->cache_client = NULL;
	}
	cache_table_lock();
	if (del && cache->key) {
		cache_table_erase(cache);
	}
	if (--cache->lock > 0) {
		cache_table_unlock();
		LOG(LOG_DEBUG, "%s fd=%d nothing to do\n", cache_client->aio.epoll_thread->name, cache_client->aio.fd);
		cache_client_free(cache_client);
		return;
	}
	cache->epoll_thread = NULL;
	cache->cache_file = NULL;
	if (cache->key == NULL) {
		file_number = cache->file_number;
		cache_free(cache);
	}
	cache_table_unlock();
	cache_client->aio.iovec_len = 0;
	if (file_number > 0) {
		if (cache_file) {
			assert(file_number == cache_file->file_number);
		} else {
			cache_file = cache_file_alloc();
			cache_file_path_init(cache_file, file_number);
		}
		cache_client->aio.fd = cache_file->fd;
		cache_client->aio.iovec[0].buffer = cache_file;
		cache_client->aio.iovec[0].buf = NULL;
		cache_client->aio.iovec[0].buf_size = 0;
		cache_client->aio.iovec[0].buf_len = 0;
		cache_client->aio.iovec_len = 1;
	} else {
		if (cache_file) {
			if (cache_file->fd > 0) {
				cache_client->aio.fd = cache_file->fd;
				cache_client->aio.iovec[0].buffer = NULL;
				cache_client->aio.iovec[0].buf = NULL;
				cache_client->aio.iovec[0].buf_size = 0;
				cache_client->aio.iovec[0].buf_len = 0;
				cache_client->aio.iovec_len = 1;
			}
			cache_file_free(cache_file);
		}
	}
	if (cache_client->aio.iovec_len > 0) {
		LOG(LOG_INFO, "%s fd=%d close\n", cache_client->aio.epoll_thread->name, cache_client->aio.fd);
		aio_summit(&cache_client->aio, cache_file_close_aio, cache_file_close_done);
	} else {
		LOG(LOG_INFO, "%s fd=%d nothing to do\n", cache_client->aio.epoll_thread->name, cache_client->aio.fd);
		cache_client_free(cache_client);
	}
}

static void cache_file_close_aio(struct aio_t *aio)
{
	struct cache_file_t *cache_file = aio->iovec[0].buffer;
	if (aio->fd > 0) {
		aio_close(aio);
	}
	if (cache_file) {
		aio_unlink(aio, cache_file->path);
	}
}

static void cache_file_close_done(struct aio_t *aio)
{
	struct cache_client_t *cache_client = aio->callback_data;
	struct cache_file_t *cache_file = aio->iovec[0].buffer;
	if (aio->fd > 0) {
		if (aio->error) {
			LOG(LOG_ERROR, "%s fd=%d close error:%s\n", aio->epoll_thread->name, aio->fd, aio->error_str);
		} else {
			LOG(LOG_INFO, "%s fd=%d close ok\n", aio->epoll_thread->name, aio->fd);
		}
	}
	cache_client_free(cache_client);
	if (cache_file) {
		LOG(LOG_INFO, "%s %s fd=%d unlink\n", aio->epoll_thread->name, cache_file->path, aio->fd);
		cache_file_number_free(cache_file);
		cache_file_free(cache_file);
	}
}

static struct cache_client_t *cache_client_alloc()
{
	struct cache_client_t *cache_client = NULL;
	cache_client = http_malloc(sizeof(struct cache_client_t));
	memset(cache_client, 0, sizeof(struct cache_client_t));
	fifo_init(&cache_client->body_fifo, PAGE_MAX_COUNT);
	cache_client->aio.callback_data = cache_client;
	return cache_client;
}

static void cache_client_free(struct cache_client_t *cache_client)
{
	struct buffer_t *buffer = NULL;
	while (fifo_len(&cache_client->body_fifo) > 0) {
		fifo_pop_head(&cache_client->body_fifo, (void **)&buffer);
		buffer_unref(buffer);
	}
	fifo_clean(&cache_client->body_fifo);
	http_free(cache_client);
}

static struct cache_file_t* cache_file_alloc()
{
	struct cache_file_t *cache_file = NULL;
	cache_file = http_malloc(sizeof(struct cache_file_t));
	memset(cache_file, 0, sizeof(struct cache_file_t));
	INIT_LIST_HEAD(&cache_file->delay_list);
	cache_file->http_reply = http_reply_alloc();
	return cache_file;
}

static void cache_file_free(struct cache_file_t *cache_file)
{
	if (cache_file->header_buf) {
		http_free(cache_file->header_buf);
	}
	if (cache_file->bitmap) {
		http_free(cache_file->bitmap);
	}
	http_reply_free(cache_file->http_reply);
	http_free(cache_file);
}

static void cache_file_number_alloc(struct cache_file_t *cache_file)
{
	int64_t file_number = 0;
	assert(cache_file->file_number == 0);
	file_number = 1;// todo read disk and get file_number
	cache_file_path_init(cache_file, file_number);
}

static void cache_file_number_free(struct cache_file_t *cache_file)
{
	assert(cache_file->file_number > 0);
	cache_file->file_number = 0;
}

static void cache_file_path_init(struct cache_file_t *cache_file, int64_t file_number)
{
	assert(cache_file->file_number == 0);
	assert(file_number > 0);
	cache_file->file_number = file_number;
	snprintf(cache_file->path, sizeof(cache_file->path), "/tmp/cache_%"PRId64".dat", cache_file->file_number);
}

static void cache_file_bitmap_init(struct cache_file_t *cache_file, int64_t content_length, size_t block_size)
{
	cache_file->bitmap_bit_size = block_size;
	cache_file->bitmap_byte_size = cache_file->bitmap_bit_size * 8;
	if (content_length > 0 && cache_file->bitmap_byte_size > 0) {
		cache_file->bitmap_size = (content_length + cache_file->bitmap_byte_size - 1) / cache_file->bitmap_byte_size;
	} else {
		cache_file->bitmap_size = 1;
	}
	cache_file->bitmap = http_malloc(cache_file->bitmap_size);
	memset(cache_file->bitmap, 0, cache_file->bitmap_size);
}

static struct cache_t* cache_alloc()
{
	struct cache_t *cache = NULL;
	cache = http_malloc(sizeof(struct cache_t));
	memset(cache, 0, sizeof(struct cache_t));
	return cache;
}

static void cache_free(struct cache_t *cache)
{
	assert(cache->key == NULL);
	assert(cache->epoll_thread == NULL);
	assert(cache->cache_file == NULL);
	http_free(cache->url);
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
		LOG(LOG_DEBUG, "free %s\n", cache->url);
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
			assert(0);
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
	http_free(cache->key);
	cache->key = NULL;
	return 0;
}

