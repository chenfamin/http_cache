#include "http.h"
#include "http_log.h"
#include "http_connection.h"
#include "http_dns.h"
#include "http_header.h"
#include "http_session.h"
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

struct cache_table_t cache_table;

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
static void http_session_free(struct http_session_t *http_session);
static void http_client_create(struct http_session_t *http_session, struct connection_t *connection);
static void http_client_close(struct http_session_t *http_session, int error_code);
static void http_client_read_header(struct connection_t *connection);
static void http_client_read_body(struct connection_t *connection);
static int http_client_process_header(struct http_session_t *http_session);

static void http_cache_lookup(struct http_session_t *http_session);
static void http_cache_read_header(struct http_session_t *http_session);
static void http_cache_write_header(struct http_session_t *http_session);
static void http_cache_mark_release(struct http_session_t *http_session);
static void http_cache_unlock(struct http_session_t *http_session);

static void http_client_dispatch(struct http_session_t *http_session);
static void http_client_dump_header(struct http_session_t *http_session);
static void http_client_build_reply(struct http_session_t *http_session, struct http_reply_t *http_reply);
static void http_client_build_error_reply(struct http_session_t *http_session, int status_code);
static void http_client_write(struct connection_t *connection);
static void http_client_expect_chunk_size(struct http_session_t *http_session, int64_t expect_size);
static void http_client_read_resume(struct http_session_t *http_session);
static void http_client_write_resume(struct http_session_t *http_session);

static void http_server_create(struct http_session_t *http_session, struct http_range_t *range);
static void http_server_close(struct http_session_t *http_session, int error_code);
static void http_server_connect(void *data);
static void http_server_connect_check(struct connection_t *connection);
static void http_server_connect_done(struct http_session_t *http_session, int error);
static void http_server_write(struct connection_t *connection);
static void http_server_read_header(struct connection_t *connection);
static void http_server_read_body(struct connection_t *connection);
static int http_server_process_header(struct http_session_t *http_session);
static int http_server_parse_chunk(struct http_session_t *http_session, const char *buf, size_t len); 
static void http_server_read_resume(struct http_session_t *http_session);
static void http_server_write_resume(struct http_session_t *http_session);
static void http_server_dump_header(struct http_session_t *http_session);
static struct http_reply_t* http_reply_create();
static void http_reply_free(struct http_reply_t *http_reply);
static int http_request_cacheable(struct http_request_t *http_request);
static int http_reply_cacheable(struct http_reply_t *http_reply);

static void http_cache_client_create(struct http_session_t *http_session, struct cache_t *cache);
static void http_cache_client_close(struct http_session_t *http_session);
static int cache_table_lock();
static int cache_table_unlock();
static struct cache_t* cache_table_lookup(const void *key);
static int cache_table_insert(struct cache_t *cache);
static int cache_table_erase(struct cache_t *cache);
static struct cache_t* cache_alloc(const char *key);
static void cache_free(struct cache_t *cache);

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

void string_init_size(struct string_t *string, size_t size)
{
	assert(size > 0);
	string->buf = http_malloc(size);
	string->size = size;
	string->len = 0;
	string->buf[0] = '\0';
}

void string_init_str(struct string_t *string, const char *s)
{
	size_t len = strlen(s);
	string_init_size(string, len + 1);
	string_strncat(string, s, len);
}

void string_strcat(struct string_t *string, const char *s)
{
	string_strncat(string, s, strlen(s));
}

void string_strncat(struct string_t *string, const char *s, size_t len)
{
	if (string->size - string->len < len + 1) {
		size_t size2 = string->size;
		while (size2 < string->len + len + 1) size2 <<= 1;
		string->buf = http_realloc(string->buf, size2);
		string->size = size2;
	}
	memcpy(string->buf + string->len, s, len);
	string->len += len;
	string->buf[string->len] = '\0';
}

void string_strcat_printf(struct string_t *string, const char *format, ...)
{
	va_list ap;
	int n = 0;
	size_t size2 = string->size;
	while (1) {
		va_start(ap, format);
		n = vsnprintf(string->buf + string->len, string->size - string->len, format, ap);
		va_end(ap);
		if (n > -1 && n < string->size - string->len) {
			string->len += n;
			return;
		}
		if (n > -1) {
			while (size2 < string->len + n + 1) size2 <<= 1; 
		} else {
			size2 <<= 1;
		}
		string->buf = http_realloc(string->buf, size2);
		string->size = size2;
	}
}

size_t string_strlen(const struct string_t *string)
{
	return string->len;
}

char* string_buf(const struct string_t *string)
{
	return string->buf;
}

void string_clean(struct string_t *string)
{
	http_free(string->buf);
}

struct mem_node_t* mem_node_alloc(size_t size)
{
	struct mem_node_t *mem_node = NULL;
	mem_node = http_malloc(sizeof(struct mem_node_t) + size);
	mem_node->size = size;
	mem_node->len = 0;
	mem_node->buf = (char *)mem_node + sizeof(struct mem_node_t);
	return mem_node;
}

struct mem_node_t* mem_node_realloc(struct mem_node_t *mem_node, size_t size)
{
	assert(mem_node->len == 0);
	if (size > mem_node->size) {
		mem_node_free(mem_node);
		mem_node = mem_node_alloc(size);
	}
	return mem_node;
}

char* mem_node_buf(struct mem_node_t *mem_node)
{
	return mem_node->buf;
}

size_t mem_node_size(struct mem_node_t *mem_node)
{
	return mem_node->size;
}

size_t mem_node_len(struct mem_node_t *mem_node)
{
	return mem_node->len;
}

int mem_node_is_full(struct mem_node_t *mem_node)
{
	assert(mem_node->size > 0 && mem_node->size >= mem_node->len);
	return mem_node->len == mem_node->size;
}

void mem_node_add_len(struct mem_node_t *mem_node, size_t len)
{
	assert(mem_node->size >= mem_node->len + len);
	mem_node->len += len;
}

void mem_node_append(struct mem_node_t *mem_node, const char *buf, size_t len)
{
	assert(mem_node->size >= mem_node->len + len);
	memcpy(mem_node->buf + mem_node->len, buf, len);
	mem_node->len += len;
}

void mem_node_free(struct mem_node_t *mem_node)
{
	http_free(mem_node);
}

void mem_list_init(struct mem_list_t *mem_list)
{
	struct mem_node_t *mem_node = NULL;
	mem_list->low = 0;
	mem_list->hight = 0;
	INIT_LIST_HEAD(&mem_list->list);
	mem_node = mem_node_alloc(PAGE_SIZE);
	list_add_tail(&mem_node->node, &mem_list->list);
}

void mem_list_resize_first_node(struct mem_list_t *mem_list, size_t size)
{
	struct mem_node_t *mem_node = NULL;
	assert(!list_empty(&mem_list->list));
	assert(mem_list->low == mem_list->hight);
	mem_node = d_list_tail(&mem_list->list, struct mem_node_t, node);
	list_del(&mem_node->node);
	mem_node = mem_node_realloc(mem_node, size);
	list_add_tail(&mem_node->node, &mem_list->list);
}

int64_t mem_list_size(struct mem_list_t *mem_list)
{
	return mem_list->hight - mem_list->low;
}

void mem_list_set_low(struct mem_list_t *mem_list, int64_t low)
{
	assert(mem_list->low == mem_list->hight);
	mem_list->low = low;
	mem_list->hight = low;
}

size_t mem_list_read_buf(struct mem_list_t *mem_list, char **buf, int64_t offset)
{
	struct mem_node_t *mem_node = NULL;
	int64_t low = mem_list->low;
	assert(!list_empty(&mem_list->list));
	assert(offset >= mem_list->low && offset < mem_list->hight);
	list_for_each_entry(mem_node, &mem_list->list, node) {
		if (low + mem_node_len(mem_node) > offset) {
			*buf = mem_node_buf(mem_node) + (int)(offset - low);
			return mem_node_len(mem_node) - (int)(offset - low);
		}
		low += mem_node_len(mem_node);
	}
	assert(0);
	return 0;
}

size_t mem_list_write_buf(struct mem_list_t *mem_list, char **buf)
{
	struct mem_node_t *mem_node = NULL;
	assert(!list_empty(&mem_list->list));
	mem_node = d_list_tail(&mem_list->list, struct mem_node_t, node);
	assert(mem_node_size(mem_node) > mem_node_len(mem_node));
	*buf = mem_node_buf(mem_node) + mem_node_len(mem_node);
	return mem_node_size(mem_node) - mem_node_len(mem_node);
}

void mem_list_append(struct mem_list_t *mem_list, const char *buf, size_t len)
{
	struct mem_node_t *mem_node = NULL;
	size_t ncopy = 0;
	assert(!list_empty(&mem_list->list));
	mem_node = d_list_tail(&mem_list->list, struct mem_node_t, node);
	if (buf == NULL) {
		mem_node_add_len(mem_node, len);
		if (mem_node_is_full(mem_node)) {
			mem_node = mem_node_alloc(PAGE_SIZE);
			list_add_tail(&mem_node->node, &mem_list->list);
		}
		mem_list->hight += len;
	} else {
		while (len > 0) {
			ncopy = mem_node_size(mem_node) - mem_node_len(mem_node);
			if (ncopy > len) {
				ncopy = len;
			}
			mem_node_append(mem_node, buf, ncopy);
			buf += ncopy;	
			len -= ncopy;
			if (mem_node_is_full(mem_node)) {
				mem_node = mem_node_alloc(PAGE_SIZE);
				list_add_tail(&mem_node->node, &mem_list->list);
			}
			mem_list->hight += ncopy;
		}
		assert(len == 0);
	}
}

void mem_list_free_to(struct mem_list_t *mem_list, int64_t offset)
{
	struct mem_node_t *mem_node = NULL;
	assert(!list_empty(&mem_list->list));
	assert(offset >= mem_list->low);
	while (!list_empty(&mem_list->list)) {
		mem_node = d_list_head(&mem_list->list, struct mem_node_t, node);
		if (mem_node_is_full(mem_node) && offset >= mem_list->low + mem_node_len(mem_node)) {
			mem_list->low += mem_node_len(mem_node);
			list_del(&mem_node->node);
			mem_node_free(mem_node);
		} else {
			break;
		}
	}
}

void mem_list_clean(struct mem_list_t *mem_list)
{
	struct mem_node_t *mem_node = NULL;
	while (!list_empty(&mem_list->list)) {
		mem_node = d_list_head(&mem_list->list, struct mem_node_t, node);
		list_del(&mem_node->node);
		mem_list->low += mem_node_len(mem_node);
		mem_node_free(mem_node);
	}
}

char *http_strdup(const char *s)
{
	char *str = NULL;
	int len = 0;
	if (s) {
		len = strlen(s);
		str = http_malloc(len + 1);
		memcpy(str, s, len);
		str[len] = 0;

	}
	return str;
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
	const char *str = NULL;
	http_request->http_major = hp->http_major;
	http_request->http_minor = hp->http_minor;
	http_request->method = hp->method;
	str = http_header_find(&http_request->header, "Content-Length");
	if (str) {
		http_request->content_length = atol(str);
	}
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
			LOG(LOG_DEBUG, "%s fd=%d wait for accept\n", epoll_thread->name, connection->fd);
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
	mem_list_init(&http_session->post_list);
	mem_list_init(&http_session->body_list);
	http_session->epoll_thread = epoll_thread;
	list_add_tail(&http_session->node, &epoll_thread->http_session_list);
	http_client_create(http_session, new_connection);
}

static void http_session_close(struct http_session_t *http_session)
{
	struct http_request_t *http_request = &http_session->http_request;
	assert(http_session->http_client == NULL);
	assert(http_session->http_server == NULL);
	list_del(&http_session->node);
	if (http_session->http_cache_client) {
		if (http_session->http_cache_client->busy) {
			LOG(LOG_DEBUG, "%s %s wait aio close\n", http_session->epoll_thread->name, string_buf(&http_request->url));
		} else {
			http_cache_client_close(http_session);
		}
	} else {
		LOG(LOG_DEBUG, "%s %s session free\n", http_session->epoll_thread->name, string_buf(&http_request->url));
		http_session_free(http_session);
	}
}

static void http_session_free(struct http_session_t *http_session)
{
	struct http_request_t *http_request = &http_session->http_request;
	assert(http_session->http_cache_client == NULL);
	string_clean(&http_request->url);
	http_header_clean(&http_request->header);
	if (http_request->range) {
		http_free(http_request->range);
	}
	mem_list_clean(&http_session->post_list);
	mem_list_clean(&http_session->body_list);
	http_free(http_session);
}

static void http_client_create(struct http_session_t *http_session, struct connection_t *connection)
{
	struct http_client_t *http_client = NULL;
	http_client = http_malloc(sizeof(struct http_client_t));
	memset(http_client, 0, sizeof(struct http_client_t));
	http_client->connection = connection;
	http_parser_init(&http_client->parser, HTTP_REQUEST);
	http_client->parser.data = &http_session->http_request;
	string_init_size(&http_client->reply_header, 1024);

	http_session->http_client = http_client;
	connection->arg = http_session;
	connection_read_enable(connection, http_client_read_header);
}

static void http_client_close(struct http_session_t *http_session, int error_code)
{
	struct http_request_t *http_request = &http_session->http_request;
	struct http_client_t *http_client = http_session->http_client;
	struct connection_t *connection = http_client->connection;
	int64_t header_send_size = 0;
	int64_t body_send_size = 0;
	if (http_client->reply_send_size > string_strlen(&http_client->reply_header)) {
		header_send_size = string_strlen(&http_client->reply_header);
	} else {
		header_send_size = http_client->reply_send_size;
	}
	body_send_size = http_client->reply_send_size - header_send_size;
	LOG(LOG_INFO, "%s %s fd=%d body_send_size=%"PRId64" body_expect_size=%"PRId64" body_offset=%"PRId64" error_code=%d\n",
			http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd,
			body_send_size , http_client->body_expect_size, http_client->body_offset, error_code);
	connection_close(connection, CONNECTION_FREE_DELAY);
	string_clean(&http_client->reply_header);
	http_free(http_client);
	http_session->http_client = NULL;
	if (http_session->http_server) {
		http_server_close(http_session, -1);
	} else {
		http_session_close(http_session);
	}
}


static void http_client_read_header(struct connection_t *connection)
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
			LOG(LOG_DEBUG, "%s %s fd=%d wait for read\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd);
			connection_read_done(connection);
			connection_read_enable(connection, http_client_read_header);
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
		connection_write_enable(connection, http_client_write);
		return;
	}
	if (http_request->parse_state < PARSER_HEADER_DONE) {
		connection_read_enable(connection, http_client_read_header);
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
				connection_write_enable(connection, http_client_write);
				return;
			}
		}
	}
	http_client_dump_header(http_session);
	if (http_client_process_header(http_session)) {
		http_client_build_error_reply(http_session, 400);
		connection_write_enable(connection, http_client_write);
		return;
	}
	if (nread > nparse) {
		mem_list_append(&http_session->post_list, buf + nparse, nread - nparse);
	}
	connection_read_enable(connection, http_client_read_body);
	http_cache_lookup(http_session);
}

static void http_client_read_body(struct connection_t *connection)
{
	struct http_session_t *http_session = connection->arg;
	struct http_request_t *http_request = &http_session->http_request;
	struct http_client_t *http_client = http_session->http_client;
	char *buf = NULL;
	size_t len = 0;
	ssize_t nread = 0;
	int loop = 0;
	int buf_full = 0;
	int error = 0;
	assert(connection == http_client->connection);
	assert(connection->epoll_thread == http_session->epoll_thread);
	do {
		loop++;
		len = mem_list_write_buf(&http_session->post_list, &buf);
		nread = http_recv(connection->fd, buf, len, 0);
		if (nread <= 0) {
			if (nread == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
				LOG(LOG_DEBUG, "%s %s fd=%d wait for read\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd);
				connection_read_done(connection);
			} else {
				LOG(LOG_DEBUG, "%s %s fd=%d nread=%d error:%s\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd, nread, strerror(errno));
				error = 1;
			}
			break;
		}
		LOG(LOG_DEBUG, "%s %s fd=%d nread=%d\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd, nread);
		mem_list_append(&http_session->post_list, NULL, nread);
		http_client->post_current_size += nread;
		buf_full = mem_list_size(&http_session->post_list) >= PAGE_LIST_MAX_SIZE? 1:0;
	} while (loop < MAX_LOOP && !buf_full);
	LOG(LOG_DEBUG, "%s %s fd=%d loop=%d\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd, loop);
	http_server_write_resume(http_session);
	if (error) {
		http_client_close(http_session, -1);
		return;
	}
	if (http_client->post_current_size >= http_client->post_expect_size) {
		LOG(LOG_DEBUG, "%s %s fd=%d read done\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd);
	}
	if (buf_full) {
		LOG(LOG_DEBUG, "%s %s fd=%d buffer full\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd);
		connection_read_disable(connection);
	} else {
		connection_read_enable(connection, http_client_read_body);
	}
}

static int http_client_process_header(struct http_session_t *http_session)
{
	struct http_request_t *http_request = &http_session->http_request;
	struct http_client_t *http_client = http_session->http_client;
	const char *str = NULL;
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

static void http_cache_lookup(struct http_session_t *http_session)
{
	struct http_request_t *http_request = &http_session->http_request;
	struct cache_t *cache = NULL;
	if (http_request_cacheable(http_request)) {
		cache_table_lock();
		cache = cache_table_lookup(string_buf(&http_request->url));
		if (cache == NULL) {
			cache = cache_alloc(string_buf(&http_request->url));
			cache->epoll_thread = http_session->epoll_thread;
			cache->lock++;
			cache_table_insert(cache);
			cache_table_unlock();
			http_cache_client_create(http_session, cache);
			http_server_create(http_session, http_request->range);
			return;
		} else {
			cache->lock++;
			if (cache->epoll_thread == NULL) {
				cache->epoll_thread = http_session->epoll_thread;
			}
			cache_table_unlock();
			http_cache_client_create(http_session, cache);
			if (cache->epoll_thread != http_session->epoll_thread) {
				http_client_dispatch(http_session);
			} else {
				http_cache_read_header(http_session);
			}
			return;
		}
	} else {
		http_server_create(http_session, http_request->range);
		return;
	}
}

static void http_cache_read_header(struct http_session_t *http_session)
{
}

static void http_cache_write_header(struct http_session_t *http_session)
{
}

static void http_cache_mark_release(struct http_session_t *http_session)
{
}

static void http_cache_unlock(struct http_session_t *http_session)
{
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
	string_strcat(&http_client->reply_header, "Via: http_cache\r\n");
	string_strcat(&http_client->reply_header, "\r\n");
	LOG(LOG_INFO, "%s %s reply=\n%s", http_session->epoll_thread->name, string_buf(&http_request->url), string_buf(&http_client->reply_header));
}

static void http_client_write(struct connection_t *connection)
{
	struct http_session_t *http_session = connection->arg;
	struct http_request_t *http_request = &http_session->http_request;
	struct http_client_t *http_client = http_session->http_client;
	char *buf = NULL;
	size_t len = 0;
	ssize_t nwrite = 0;
	int64_t body_send_size = -1;
	int loop = 0;
	int buf_empty = 0;
	int error = 0;
	assert(connection == http_client->connection);
	assert(connection->epoll_thread == http_session->epoll_thread);
	do {
		loop++;
		if (http_client->reply_send_size >= string_strlen(&http_client->reply_header)) {
			body_send_size = http_client->reply_send_size - string_strlen(&http_client->reply_header);
			len = mem_list_read_buf(&http_session->body_list, &buf, body_send_size + http_client->body_offset);
			if (body_send_size + len > http_client->body_expect_size) {
				len = (size_t)(http_client->body_expect_size - body_send_size);
			}
		} else {
			buf = string_buf(&http_client->reply_header) + http_client->reply_send_size;
			len = string_strlen(&http_client->reply_header) - http_client->reply_send_size;
		}
		nwrite = http_send(connection->fd, buf, len, 0);
		if (nwrite <= 0) {
			if (nwrite == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
				LOG(LOG_DEBUG, "%s %s fd=%d wait for send\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd);
				connection_write_done(connection);
			} else {
				LOG(LOG_DEBUG, "%s %s fd=%d send=%d error:%s\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd, nwrite, strerror(errno));
				error = 1;
			}
			break;
		}
		LOG(LOG_DEBUG, "%s %s fd=%d nwrite=%d\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd, nwrite);
		http_client->reply_send_size += nwrite;
		if (http_client->reply_send_size >= string_strlen(&http_client->reply_header)) {
			body_send_size = http_client->reply_send_size - string_strlen(&http_client->reply_header);
			mem_list_free_to(&http_session->body_list, body_send_size + http_client->body_offset);
			buf_empty = http_session->body_list.hight > (http_client->body_offset + body_send_size)? 0:1;
		}
	} while (loop < MAX_LOOP && !buf_empty);
	LOG(LOG_DEBUG, "%s %s fd=%d loop=%d\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd, loop);
	http_server_read_resume(http_session);
	if (error) {
		http_client_close(http_session, -1);
		return;
	}
	// body_send_size == -1 means header not send done
	if (body_send_size < http_client->body_expect_size) {
		// do not calculate http_session->body_list.hight > (http_client->body_offset + http_client->body_expect_size)
		if (buf_empty) {
			LOG(LOG_DEBUG, "%s %s fd=%d buffer empty\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd);
			connection_write_disable(connection);
		} else {
			connection_write_enable(connection, http_client_write);//read write next event loop
		}
	} else {
		LOG(LOG_DEBUG, "%s %s fd=%d reply write done\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd);
		http_client_close(http_session, 0);
	}
}

static void http_client_expect_chunk_size(struct http_session_t *http_session, int64_t expect_size)
{
	struct http_client_t *http_client = http_session->http_client;
	if (http_client) {
		assert(http_client->body_offset == 0 &&
				http_client->body_expect_size == INT64_MAX);
		http_client->body_expect_size = expect_size;
	}
}

static void http_client_read_resume(struct http_session_t *http_session)
{
	struct http_request_t *http_request = &http_session->http_request;
	struct http_client_t *http_client = http_session->http_client;
	if (http_client) {
		if (http_request->parse_state < PARSER_HEADER_DONE) {
			connection_read_enable(http_client->connection, http_client_read_header);
		} else if (http_client->post_current_size < http_client->post_expect_size &&
				mem_list_size(&http_session->post_list) < PAGE_LIST_MAX_SIZE / 2) {
			connection_read_enable(http_client->connection, http_client_read_body);
		}
	}
}

static void http_client_write_resume(struct http_session_t *http_session)
{
	struct http_client_t *http_client = http_session->http_client;
	int64_t body_send_size = -1;
	int buf_empty = 0;
	if (http_client) {
		if (http_client->reply_send_size >= string_strlen(&http_client->reply_header)) {
			body_send_size = http_client->reply_send_size - string_strlen(&http_client->reply_header);
			buf_empty = http_session->body_list.hight > (http_client->body_offset + body_send_size)? 0:1;
			if (!buf_empty) {
				connection_write_enable(http_client->connection, http_client_write);
			}
		}
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
			connection_write_enable(http_client->connection, http_client_write);
		} else {
			http_client_close(http_session, -1);
		}
		return;
	}
	http_server = http_malloc(sizeof(struct http_server_t));
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
	http_session->http_server = http_server;
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
	struct http_client_t *http_client = http_session->http_client;
	LOG(LOG_INFO, "%s %s fd=%d body_current_size=%"PRId64" body_expect_size=%"PRId64" body_offset=%"PRId64" error_code=%d\n",
			http_session->epoll_thread->name, string_buf(&http_request->url), connection? connection->fd:0,
			http_server->body_current_size, http_server->body_expect_size, http_server->body_offset, error_code);
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
	if (http_client) {
		int64_t body_send_size = 0;
		if (string_strlen(&http_client->reply_header) == 0) {
			if (error_code) {
				http_client_build_error_reply(http_session, error_code);
				connection_write_enable(http_client->connection, http_client_write);
			}
		} else  {
			body_send_size = http_client->reply_send_size - string_strlen(&http_client->reply_header);
			if (http_session->body_list.hight > http_client->body_offset + body_send_size) {
			} else {
				http_client_close(http_session, -1);
			}
		}
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
	int error;
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
	connection_read_enable(connection, http_server_read_header);
	connection_write_enable(connection, http_server_write);
}

static void http_server_write(struct connection_t *connection)
{
	struct http_session_t *http_session = connection->arg;
	struct http_request_t *http_request = &http_session->http_request;
	struct http_server_t *http_server = http_session->http_server;
	char *buf = NULL;
	size_t len = 0;
	ssize_t nwrite = 0;
	int64_t body_send_size = -1;
	int loop = 0;
	int buf_empty = 0;
	int error = 0;
	assert(connection == http_server->connection);
	assert(connection->epoll_thread == http_session->epoll_thread);
	do {
		loop++;
		if (http_server->request_send_size >= string_strlen(&http_server->request_header)) {
			body_send_size = http_server->request_send_size - string_strlen(&http_server->request_header);
			len = mem_list_read_buf(&http_session->post_list, &buf, body_send_size);
		} else {
			buf = string_buf(&http_server->request_header) + http_server->request_send_size;
			len= string_strlen(&http_server->request_header) - http_server->request_send_size;
		}
		nwrite = http_send(connection->fd, buf, len, 0);
		if (nwrite <= 0) {
			if (nwrite == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
				LOG(LOG_DEBUG, "%s %s fd=%d wait for send\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd);
				connection_write_done(connection);
			} else {
				LOG(LOG_DEBUG, "%s %s fd=%d send=%d error:%s\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd, nwrite, strerror(errno));
				error = 1;
			}
			break;
		}
		LOG(LOG_DEBUG, "%s %s fd=%d nwrite=%d\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd, nwrite);
		http_server->request_send_size += nwrite;
		if (http_server->request_send_size >= string_strlen(&http_server->request_header)) {
			body_send_size = http_server->request_send_size - string_strlen(&http_server->request_header);
			mem_list_free_to(&http_session->post_list, body_send_size);
			buf_empty = http_session->post_list.hight > body_send_size? 0:1;
		}
	} while (loop < MAX_LOOP && !buf_empty);
	LOG(LOG_DEBUG, "%s %s fd=%d loop=%d\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd, loop);
	http_client_read_resume(http_session);
	if (error) {
		http_server_close(http_session, 503);
		return;
	}
	//body_send_size == -1 means header not send done
	if (body_send_size < http_request->content_length) {
		if (buf_empty) {
			LOG(LOG_DEBUG, "%s %s fd=%d buffer empty\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd);
			connection_write_disable(connection);
		} else {
			connection_write_enable(connection, http_server_write);//read write next event loop
		}
	} else {
		LOG(LOG_DEBUG, "%s %s fd=%d request write done\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd);
		connection_write_disable(connection);
	}
}

static void http_server_read_header(struct connection_t *connection)
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
			LOG(LOG_DEBUG, "%s %s fd=%d wait for read\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd);
			connection_read_done(connection);
			connection_read_enable(connection, http_server_read_header);
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
	if (http_request->parse_state < PARSER_HEADER_DONE) {
		connection_read_enable(connection, http_server_read_header);
		return;
	}
	http_server_dump_header(http_session);
	if (http_server_process_header(http_session)) {
		http_server_close(http_session, 503);
		return;
	}
	mem_list_resize_first_node(&http_session->body_list, PAGE_SIZE - http_session->body_list.low % PAGE_SIZE);
	if (nread > nparse) {
		body_size = nread - nparse;
		LOG(LOG_DEBUG, "%s %s fd=%d body_size=%d\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd, body_size);
		mem_list_append(&http_session->body_list, buf + nparse, body_size);
		http_server->body_current_size += body_size;
		if (http_server->chunked) {
			if (http_server_parse_chunk(http_session, buf + nparse, body_size)) {
				http_server_close(http_session, 503);
				return;
			}
		}
	}
	if (http_server->body_current_size >= http_server->body_expect_size) {
		http_server_close(http_session, 0);
	} else {
		connection_read_enable(connection, http_server_read_body);
	}
}

static void http_server_read_body(struct connection_t *connection)
{
	struct http_session_t *http_session = connection->arg;
	struct http_request_t *http_request = &http_session->http_request;
	struct http_server_t *http_server = http_session->http_server;
	char *buf = NULL;
	size_t len = 0;
	ssize_t nread = 0;
	int loop = 0;
	int buf_full = 0;
	int error = 0;
	assert(connection == http_server->connection);
	assert(connection->epoll_thread == http_session->epoll_thread);
	do {
		loop++;
		len = mem_list_write_buf(&http_session->body_list, &buf);
		nread = http_recv(connection->fd, buf, len, 0);
		if (nread <= 0) {
			if (nread == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
				LOG(LOG_DEBUG, "%s %s fd=%d wait for read\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd);
				connection_read_done(connection);
			} else {
				LOG(LOG_DEBUG, "%s %s fd=%d nread=%d error:%s\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd, nread, strerror(errno));
				error = 1;
			}
			break;
		}
		LOG(LOG_DEBUG, "%s %s fd=%d nread=%d\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd, nread);
		http_server->body_current_size += nread;
		mem_list_append(&http_session->body_list, NULL, nread);
		buf_full = mem_list_size(&http_session->body_list) >= PAGE_LIST_MAX_SIZE? 1:0;
		if (http_server->chunked) {
			if (http_server_parse_chunk(http_session, buf, nread)) {
				error = 1;
				break;
			}
		}
	} while (loop < MAX_LOOP && !buf_full);
	LOG(LOG_DEBUG, "%s %s fd=%d loop=%d\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd, loop);
	http_client_write_resume(http_session);
	if (error) {
		http_server_close(http_session, 503);
		return;
	}
	if (http_server->body_current_size >= http_server->body_expect_size) {
		LOG(LOG_DEBUG, "%s %s fd=%d read done\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd);
		http_server_close(http_session, 0);
	} else {
		if (buf_full) {
			LOG(LOG_DEBUG, "%s %s fd=%d buffer full\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd);
			connection_read_disable(connection);
		} else {
			connection_read_enable(connection, http_server_read_body);// read when next event loop
		}
	}
}

static int http_server_process_header(struct http_session_t *http_session)
{
	struct http_request_t *http_request = &http_session->http_request;
	struct http_client_t *http_client = http_session->http_client;
	struct http_server_t *http_server = http_session->http_server;
	struct http_cache_client_t *http_cache_client = http_session->http_cache_client;
	struct connection_t *connection = http_server->connection;
	struct http_reply_t *http_reply = http_server->parser.data;
	struct cache_t *cache = NULL;
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
				mem_list_set_low(&http_session->body_list, content_range->start);
				http_server->body_offset = content_range->start;
				http_server->body_expect_size = content_range->end - content_range->start + 1;
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
		if (http_reply->status_code == 204 || http_reply->status_code == 304) {
			http_server->body_expect_size = 0;
		}
	}
	if (http_request->method == HTTP_HEAD) {
		http_server->body_expect_size = 0;
	}
	if (http_cache_client) {
		cache = http_cache_client->cache;
		if (http_reply_cacheable(http_reply)) {
			if (cache->http_reply) {
				if (cache->http_reply->content_length != http_reply->content_length) {
					LOG(LOG_ERROR, "%s %s fd=%d old content_length=%"PRId64" new content_length=%"PRId64"\n%s", http_session->epoll_thread->name, string_buf(&http_request->url),
							connection->fd, cache->http_reply->content_length, http_reply->content_length);
					http_cache_mark_release(http_session);
					http_cache_unlock(http_session);
				}
			} else {
				cache->http_reply = http_reply;
				http_server->parser.data = NULL;
				http_cache_write_header(http_session);
			}
		} else {
			LOG(LOG_DEBUG, "%s %s fd=%d http_reply_cacheable=0\n%s", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd);
			http_cache_unlock(http_session);
		}
	}
	if (http_client) {
		if (string_strlen(&http_client->reply_header) == 0) {
			http_client_build_reply(http_session, http_reply);
			connection_write_enable(http_client->connection, http_client_write);
		} else if (http_reply->status_code != 200) {
			LOG(LOG_ERROR, "%s %s fd=%d client need abort\n%s", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd);
			return -1;
		}
	}
	return 0;
}

static int http_server_parse_chunk(struct http_session_t *http_session, const char *buf, size_t len) 
{
	struct http_request_t *http_request = &http_session->http_request;
	struct http_server_t *http_server = http_session->http_server;
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
			http_server->body_expect_size = http_server->body_current_size;
			http_client_expect_chunk_size(http_session, http_server->body_current_size);
			break;
		}    
		if (rc == HTTP_AGAIN) {
			break;
		}    
		LOG(LOG_ERROR, "%s %s fd=%d error\n", http_session->epoll_thread->name, string_buf(&http_request->url), connection->fd);
		return -1;
	}
	return 0;
}

static void http_server_read_resume(struct http_session_t *http_session)
{
	//struct http_request_t *http_request = &http_session->http_request;
	struct http_server_t *http_server = http_session->http_server;
	struct http_reply_t *http_reply = NULL;
	if (http_server && http_server->connection) {
		http_reply = http_server->parser.data;
		if (http_reply && http_reply->parse_state < PARSER_HEADER_DONE) {
			connection_read_enable(http_server->connection, http_server_read_header);
		} else if (http_server->body_current_size < http_server->body_expect_size &&
				mem_list_size(&http_session->body_list) < PAGE_LIST_MAX_SIZE / 2) {
			connection_read_enable(http_server->connection, http_server_read_body);
		}
	}
}

static void http_server_write_resume(struct http_session_t *http_session)
{
	//struct http_request_t *http_request = &http_session->http_request;
	struct http_server_t *http_server = http_session->http_server;
	int64_t body_send_size = -1;
	int buf_empty = 0;
	if (http_server && http_server->connection) {
		if (http_server->request_send_size >= string_strlen(&http_server->request_header)) {
			body_send_size = http_server->request_send_size - string_strlen(&http_server->request_header);
			buf_empty = http_session->post_list.hight > body_send_size? 0:1;
			if (!buf_empty) {
				connection_write_enable(http_server->connection, http_server_write);
			}
		}
	}
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
	return 0;
}

static int http_reply_cacheable(struct http_reply_t *http_reply)
{
	switch (http_reply->status_code) {
		case 200:
		case 204:
			return 1;
			break;
		default:
			return 0;
			break;
	}
	return 0;
}

static void http_cache_client_create(struct http_session_t *http_session, struct cache_t *cache)
{
	struct http_cache_client_t *http_cache_client = NULL;
	http_cache_client = http_malloc(sizeof(struct http_cache_client_t));
	memset(http_cache_client, 0, sizeof(struct http_cache_client_t));
	http_cache_client->cache = cache;
	http_session->http_cache_client = http_cache_client;
}

static void http_cache_client_close(struct http_session_t *http_session)
{
	struct http_request_t *http_request = &http_session->http_request;
	http_free(http_session->http_cache_client);
	http_session->http_cache_client = NULL;
	if (http_session->http_client == NULL && http_session->http_server == NULL) {
		LOG(LOG_DEBUG, "%s %s session free\n", http_session->epoll_thread->name, string_buf(&http_request->url));
		http_session_free(http_session);
	}
}

void cache_table_init()
{
	memset(&cache_table, 0, sizeof(struct cache_table_t));
	pthread_mutex_init(&cache_table.mutex, NULL);
	cache_table.rb_root = RB_ROOT;
	INIT_LIST_HEAD(&cache_table.list);
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

static struct cache_t* cache_alloc(const char *key)
{
	struct cache_t *cache = NULL;
	cache = http_malloc(sizeof(struct cache_t));
	memset(cache, 0, sizeof(struct cache_t));
	cache->key = http_strdup(key);
	return cache;
}

static void cache_free(struct cache_t *cache)
{
	http_free(cache->key);
	http_free(cache);
}

void cache_table_clean()
{
	struct cache_t *cache = NULL;
	struct rb_node *node = NULL;
	while ((node = rb_first(&cache_table.rb_root))) {
		cache = rb_entry(node, struct cache_t, rb_node);
		cache_table_erase(cache);
		cache_free(cache);
	}
}
