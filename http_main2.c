#include "http.h"
#include "http_dns.h"
#include "http_header.h"

struct http_request_t {
	enum http_method method;
	int http_major;
	int http_minor;
	struct string_t uri;
	struct string_t url;
	struct http_parser_url parser_url;
	struct http_header_t header;
	struct http_range_t *range;
	struct http_cache_control_t *cache_control;
	time_t if_modified_since;
	const char *if_none_match;
	int keep_alive;
	int64_t content_length;
	enum parser_header_state parse_state;

	void *body_client;
	void *body_server;
	struct page_list_t page_list;
	int64_t body_offset;
	struct epoll_thread_t *epoll_thread;
	int link;
};

struct http_reply_t {
	int status_code;
	int http_major;
	int http_minor;
	struct http_header_t header;
	struct http_cache_control_t *cache_control;
	int chunked;
	int64_t content_length;
	enum parser_header_state parse_state;
};

struct cache_table_t {
	pthread_mutex_t mutex;
	struct rbtree_t rbtree;
	struct list_head_t list;
};

struct cache_t {
	struct rbtree_node_t rbtree_node;
	int link;
	struct epoll_thread_t *epoll_thread;

	struct {
		int cacheable:1;
	} flags;

	struct http_reply_t *reply;
	struct list_head_t client_list;// wait for reply
	struct list_head_t server_list;// wait for body
};

struct http_client_t {
	struct cache_t *cache;
	struct connection_t *connection;
	http_parser parser;
	struct http_request_t *http_request;
	int64_t range_current;
	int64_t range_expect;
	struct string_t reply_header; 
	int reply_header_send; 
	struct continuation_t continuation;
};

struct http_server_t {
	struct cache_t *cache;
	struct list_head_t node;
	struct connection_t *connection;
	int64_t range_start;
	int64_t range_current;
	int64_t range_expect;
	struct http_request_t *http_request;// link from client request
	struct http_range_t *http_range;
	struct string_t request_header;
	int request_header_send;
	int64_t body_send;
	http_parser parser;
	struct http_reply_t *reply;
	struct http_chunked_t http_chunked;
	struct page_list_t page_list;
	struct dns_info_t dns_info;
	struct list_head_t client_list;
	struct continuation_t continuation;
};

struct http_session_t {
	struct cace_t *cache;
};

struct epoll_thread_t *epoll_threads = NULL;
struct aio_thread_t *aio_threads = NULL;
int epoll_threads_num = 2;
int aio_threads_num = 4;
int want_exit = 0;

struct cache_table_t cache_table;

static void sig_int(int sig);
static void sig_pipe(int sig);
static void http_listen(const char *host, int port);
static int socket_listen(const char *host, uint16_t port, int family);
static void http_client_accept(struct connection_t *connection);
static struct http_client_t* http_client_create(struct connection_t *connection);
static void http_client_read_request(struct connection_t *connection);
static void http_client_process_request(struct http_client_t *http_client, char *buf, ssize_t len);
static void http_client_read_body(struct connection_t *connection);
static void http_client_read_next_request(struct connection_t *connection);
static void http_client_send_reply(struct connection_t *connection);
static void http_client_send_body(struct connection_t *connection);
static void http_client_handle_error(struct http_client_t *http_client, int error_type);
static void http_client_read_server(struct http_client_t *http_client, void *provider, char *buf, ssize_t len, int error);
static void http_client_write_done(struct connection_t *connection, const char *buf, ssize_t size, int error);
static void http_client_dump_request(struct http_client_t *http_client);
static int http_client_cacheable(struct http_client_t *http_client);
static struct http_request_t* http_request_create();
static struct http_request_t* http_request_link(struct http_request_t *http_request);
static void http_request_unlink(struct http_request_t *http_request);
static void http_client_close(struct http_client_t *http_client, int error_type);

static struct http_reply_t* http_reply_create();
static void http_reply_free(struct http_reply_t *http_reply);
static struct http_server_t *http_server_create(struct cache_t *cache, struct http_request_t *http_request, struct http_range_t *http_range);
static void http_server_free(struct http_server_t *http_server);
static void http_server_forward(struct http_server_t *http_server);
static void http_server_connect(void *data);
static void http_server_connect_check(struct connection_t *connection);
static void http_server_connect_done(struct http_server_t *http_server, int error);
static void http_server_build_request(struct http_server_t *http_server);
static void http_server_send_request(struct connection_t *connection);
static void http_server_send_body(struct connection_t *connection);
static void http_server_read_reply(struct connection_t *connection);
static void http_server_process_reply(struct http_server_t *http_server, char *buf, ssize_t len);
static void http_server_dump_reply(struct http_server_t *http_server);
static void http_server_read_body(struct connection_t *connection);
static void http_server_invoke_clients(struct http_server_t *http_server);
static void http_server_resum_read(struct http_server_t *http_server);
static void http_server_close(struct http_server_t *http_server, int error);

static int request_on_message_begin(http_parser *hp);
static int request_on_url(http_parser *hp, const char *at, size_t length);
static int request_on_header_field(http_parser *hp, const char *at, size_t length);
static int request_on_header_value(http_parser *hp, const char *at, size_t length);
static int request_on_headers_complete(http_parser *hp);
static int request_on_body(http_parser *hp, const char *at, size_t length);
static int request_on_message_complete(http_parser *hp);
static int http_request_parse_url(struct http_request_t *http_request);

static int reply_on_message_begin(http_parser *hp);
static int reply_on_status(http_parser *hp, const char *at, size_t length); 
static int reply_on_header_field(http_parser *hp, const char *at, size_t length); 
static int reply_on_header_value(http_parser *hp, const char *at, size_t length); 
static int reply_on_headers_complete(http_parser *hp); 
static int reply_on_body(http_parser *hp, const char *at, size_t length);
static int reply_on_message_complete(http_parser *hp);

static struct cache_t* http_cache_create(const char *key);
static struct cache_t* http_cache_link(struct cache_t *cache);
static void  http_cache_unlink(struct cache_t *cache);
static void http_cache_handle_reply(struct cache_t *cache, struct http_reply_t *http_reply);
static int cache_key_cmp(const void *key1, const void *key2);
static void cache_table_init();
static int cache_table_lock();
static int cache_table_unlock();
static void cache_table_clean();

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

static void sig_int(int sig)
{
	want_exit = 1;
}

static void sig_pipe(int sig)
{
}

void epoll_thread_init(struct epoll_thread_t *epoll_thread)
{
	int event_pipe[2];
	INIT_LIST_HEAD(&epoll_thread->listen_list);
	INIT_LIST_HEAD(&epoll_thread->read_ready_list);
	INIT_LIST_HEAD(&epoll_thread->write_ready_list);
	epoll_thread->epoll_fd = epoll_create(MAX_EPOLL_FD);
	if (epoll_thread->epoll_fd < 0) {
		LOG("%s epoll_create error:%s\n", epoll_thread->name, strerror(errno));
		assert(0);
	}
	if (pipe(event_pipe)) {
		LOG("%s pipe error:%s\n", epoll_thread->name, strerror(errno));
		assert(0);
	} 
	socket_non_block(event_pipe[0]);
	socket_non_block(event_pipe[1]);
	epoll_thread_dns_connection_init(epoll_thread);
}

void* epoll_thread_loop(void *arg)
{
	int i = 0;
	int nfds = 0;
	struct epoll_thread_t *epoll_thread = (struct epoll_thread_t *)arg;
	struct connection_t *connection;
	int wait_time;
	uint32_t events;
	struct list_head_t read_ready_list;
	struct list_head_t write_ready_list;
	struct epoll_event event_result[MAX_EPOLL_FD];
	while (!want_exit) {
		INIT_LIST_HEAD(&read_ready_list);
		INIT_LIST_HEAD(&write_ready_list);
		list_splice_init(&epoll_thread->read_ready_list, &read_ready_list);
		list_splice_init(&epoll_thread->write_ready_list, &write_ready_list);
		if (list_empty(&read_ready_list) && list_empty(&write_ready_list)) {
			wait_time = 100;
		} else {
			wait_time = 0;
		}
		nfds = epoll_wait(epoll_thread->epoll_fd, event_result, MAX_EPOLL_FD, wait_time);
		if (nfds < 0) {
			LOG("%s epoll_wait error: %s\n", epoll_thread->name, strerror(errno));
			continue;
		}
		for (i = 0; i < nfds; i++) {
			connection = event_result[i].data.ptr;
			events = event_result[i].events;
			if ((events & (EPOLLERR | EPOLLHUP)) && (events & (EPOLLIN | EPOLLOUT)) == 0) {
				events |= EPOLLIN | EPOLLOUT;
			}
			if (events & EPOLLIN) {
				connection->flags.read_trigger = 1;
				if (list_node_null(&connection->read_ready_node)) {
					list_add_tail(&connection->read_ready_node, &read_ready_list);
				}
			}    
			if (events & EPOLLOUT) {
				connection->flags.write_trigger = 1;
				if (list_node_null(&connection->write_ready_node)) {
					list_add_tail(&connection->write_ready_node, &write_ready_list);
				}
			}
		}
		while (!list_empty(&read_ready_list)) {
			connection = d_list_head(&read_ready_list, struct connection_t, read_ready_node);
			list_del(&connection->read_ready_node);
			if (connection->handle_read) {
				connection->handle_read(connection);
			}    
		}    
		while (!list_empty(&write_ready_list)) {
			connection = d_list_head(&write_ready_list, struct connection_t, write_ready_node);
			list_del(&connection->write_ready_node);
			if (connection->handle_write) {
				connection->handle_write(connection);
			}
		}
	}
	return NULL;
}

void epoll_thread_free(struct epoll_thread_t *epoll_thread)
{
	//epoll_thread_dns_connection_close(epoll_thread);
}

void aio_thread_init(struct aio_thread_t *aio_thread)
{
}

void* aio_thread_loop(void *arg)
{
	return NULL;
}

void aio_thread_free(struct aio_thread_t *aio_thread)
{
}

void page_list_init(struct page_list_t *page_list)
{
	page_list->low = 0;
	page_list->data_size = 0;
	INIT_LIST_HEAD(&page_list->data_list);
	INIT_LIST_HEAD(&page_list->free_list);
}

void page_list_clean(struct page_list_t *page_list)
{
	struct page_t *page = NULL;
	while (!list_empty(&page_list->data_list)) {
		page = d_list_head(&page_list->data_list, struct page_t, node);
		list_del(&page->node);
		http_free(page);
	}
	while (!list_empty(&page_list->free_list)) {
		page = d_list_head(&page_list->free_list, struct page_t, node);
		list_del(&page->node);
		http_free(page);
	}
	page_list->low = 0;
	page_list->data_size = 0;
}

void page_list_append_buf(struct page_list_t *page_list, int64_t offset, const char *buf, int len)
{
	struct iovec iovec[MAX_IOVEC];
	int i, n;
	n = page_list_readv(page_list, offset, len, iovec, MAX_IOVEC);
	for (i = 0; i < n; i++) {
		memcpy(iovec[i].iov_base, buf, iovec[i].iov_len);
		buf += iovec[i].iov_len;
		len -= iovec[i].iov_len;
	}
	assert(len == 0);
}

void page_list_fill_size(struct page_list_t *page_list, int64_t offset, int size)
{
	struct page_t *page = NULL;
	int extra_size = (int)(page_list->low + page_list->data_size - offset);
	if (extra_size > 0) {
		assert(extra_size < PAGE_SIZE);
		size -= MIN(size, extra_size);
	}
	while (size > 0) {
		page = d_list_head(&page_list->free_list, struct page_t, node);
		list_del(&page->node);
		list_add_tail(&page->node, &page_list->data_list);
		page_list->data_size += PAGE_SIZE;
		size -= MIN(size, PAGE_SIZE);
	}
}

void page_list_free_to(struct page_list_t *page_list, int64_t offset)
{
	struct page_t *page = NULL;
	assert(offset >= page_list->low && offset <= page_list->low + page_list->data_size);
	while (offset >= page_list->low + PAGE_SIZE) {
		page = d_list_head(&page_list->data_list, struct page_t, node);
		list_del(&page->node);
		http_free(page);
		page_list->low += PAGE_SIZE;
		page_list->data_size -= PAGE_SIZE;
	}
}

int page_list_readv(struct page_list_t *page_list, int64_t offset, int64_t max_size,
		struct iovec *iovec, int max_count)
{
	int i = 0;
	struct page_t *page = NULL;
	int extra_size = (int)(page_list->low + page_list->data_size - offset);
	if (extra_size > 0) {
		assert(extra_size < PAGE_SIZE);
		page = d_list_tail(&page_list->data_list, struct page_t, node);
		iovec[i].iov_base = page->buf + (PAGE_SIZE - extra_size);
		iovec[i].iov_len = MIN(max_size, extra_size);
		max_size -= iovec[i].iov_len;
		offset += iovec[i].iov_len;
		i++;
		if (max_size <= 0 || i >= max_count) {
			return i;
		}
	}
	if (!list_empty(&page_list->free_list)) {
		list_for_each_entry(page, &page_list->free_list, node) {
			iovec[i].iov_base = page->buf;
			iovec[i].iov_len = MIN(max_size, PAGE_SIZE);
			max_size -= iovec[i].iov_len;
			offset += iovec[i].iov_len;
			i++;
			if (max_size <= 0 || i >= max_count) {
				return i;
			}
		}
	}
	while (max_size > 0 && i < max_count) {
		page = http_malloc(sizeof(struct page_t));
		list_add_tail(&page->node, &page_list->free_list);
		iovec[i].iov_base = page->buf;
		iovec[i].iov_len = MIN(max_size, PAGE_SIZE);
		max_size -= iovec[i].iov_len;
		offset += iovec[i].iov_len;
		i++;
	}
	return i;
}

int page_list_writev(struct page_list_t *page_list, int64_t offset, int64_t max_size,
		struct iovec *iovec, int max_count)
{
	int i = 0;
	int off = 0;
	struct page_t *page = NULL;
	int64_t low = page_list->low;
	assert(offset >= page_list->low);
	if (list_empty(&page_list->data_list)) {
		return 0;
	}
	list_for_each_entry(page, &page_list->data_list, node) {
		if (low + PAGE_SIZE > offset) {
			off = (int)(offset - low);
			iovec[i].iov_base = page->buf + off;
			iovec[i].iov_len = MIN(max_size, PAGE_SIZE - off);
			max_size -= iovec[i].iov_len;
			offset += iovec[i].iov_len;
			i++;
			if (max_size <= 0 || i >= max_count) {
				return i;
			}
			assert(offset == low + PAGE_SIZE);
		}
		low += PAGE_SIZE;
	}
	return i;
}

void mem_node_init(struct mem_node_t *mem_node, int size)
{
	mem_node->buf = http_malloc(size);
	mem_node->size = size;
	mem_node->len = 0;
}

struct mem_node_t *mem_node_alloc(int size)
{
	struct mem_node_t *mem_node = NULL;
	mem_node = http_malloc(sizeof(struct mem_node_t));
	mem_node_init(mem_node, size);
	return mem_node;
}

void mem_node_clean(struct mem_node_t *mem_node)
{
	http_free(mem_node->buf);
}

void mem_node_free(struct mem_node_t *mem_node)
{
	mem_node_clean(mem_node);
	http_free(mem_node);
}

void mem_node_append(struct mem_node_t *mem_node, const char *buf, int len)
{
	struct mem_node_t *mem_node2 = NULL;
	int size2 = mem_node->size;
	if (mem_node->size - mem_node->len < len) {
		while (size2 < mem_node->len + len) size2 <<= 1;
		mem_node->buf = http_realloc(mem_node->buf, size2);
		mem_node->size = size2;
	}
	memcpy(mem_node->buf + mem_node->len, buf, len);
	mem_node->len += len;
}

void string_init_size(struct string_t *string, int size)
{
	struct mem_node_t *mem_node = &string->mem_node;
	assert(size > 0);
	mem_node_init(mem_node, size);
	mem_node->buf[0] = '\0';
	mem_node->len = 1;
}

void string_init_str(struct string_t *string, const char *src)
{
	struct mem_node_t *mem_node = &string->mem_node;
	int size = strlen(src) + 1;
	mem_node_init(mem_node, size);
	mem_node_append(mem_node, src, size);
}

void string_strcat(struct string_t *string, const char *src)
{
	struct mem_node_t *mem_node = &string->mem_node;
	assert(mem_node->len > 0);
	mem_node->len--;
	mem_node_append(mem_node, src, strlen(src) + 1);
}

void string_strncat(struct string_t *string, const char *src, int len)
{
	struct mem_node_t *mem_node = &string->mem_node;
	int size2 = mem_node->size;
	assert(mem_node->len > 0);
	mem_node->len--;
	if (mem_node->size - mem_node->len < len) {
		while (size2 < mem_node->len + len + 1) size2 <<= 1;
		mem_node->buf = http_realloc(mem_node->buf, size2);
		mem_node->size = size2;
	}
	mem_node_append(mem_node, src, len);
	mem_node->buf[mem_node->len] = '\0';
	mem_node->len++;
}

void string_strcat_printf(struct string_t *string, const char *format, ...)
{
	va_list ap;
	int n = 0;
	struct mem_node_t *mem_node = &string->mem_node;
	int size2 = mem_node->size;
	mem_node->len--;
	while (1) {
		va_start(ap, format);
		n = vsnprintf(mem_node->buf + mem_node->len, mem_node->size - mem_node->len, format, ap);
		va_end(ap);
		if (n > -1 && n < mem_node->size - mem_node->len) {
			mem_node->len += (n + 1);
			return;
		}
		if (n > -1) {
			while (size2 < mem_node->len + n + 1) size2 <<= 1; 
		} else {
			size2 <<= 1;
		}
		mem_node->buf = http_realloc(mem_node->buf, size2);
		mem_node->size = size2;
	}
}

int string_strlen(const struct string_t *string)
{
	const struct mem_node_t *mem_node = &string->mem_node;
	assert(mem_node->len > 0);
	return mem_node->len - 1;
}

void rbtree_init(struct rbtree_t *rbtree, int (*cmp)(const void *key1, const void *key2))
{
	rbtree->rb_root = RB_ROOT;
	rbtree->cmp = cmp;
}

int rbtree_insert(struct rbtree_t *rbtree, struct rbtree_node_t *rbtree_node)
{
	struct rb_node **p = &rbtree->rb_root.rb_node;
	struct rb_node *parent = NULL;
	struct rbtree_node_t *rbtree_node_tmp;
	int cmp;
	while (*p)
	{   
		parent = *p; 
		rbtree_node_tmp = rb_entry(parent, struct rbtree_node_t, rb_node);
		cmp = rbtree->cmp(rbtree_node->key, rbtree_node_tmp->key);
		if (cmp < 0)
			p = &(*p)->rb_left;
		else if (cmp > 0)
			p = &(*p)->rb_right;
		else
			return -1; 
	}   
	rb_link_node(&rbtree_node->rb_node, parent, p); 
	rb_insert_color(&rbtree_node->rb_node, &rbtree->rb_root);
	rbtree->count--;
	return 0;
}

void* rbtree_lookup(struct rbtree_t *rbtree, const void *key, size_t offset)
{
	struct rb_node *node = rbtree->rb_root.rb_node;
	struct rbtree_node_t *rbtree_node = NULL;
	int cmp;
	while (node)
	{   
		rbtree_node = rb_entry(node, struct rbtree_node_t, rb_node);
		cmp = rbtree->cmp(key, rbtree_node->key);
		if (cmp < 0)
			node = node->rb_left;
		else if (cmp > 0)
			node = node->rb_right;
		else
			return (char *)rbtree_node - offset;
	}   
	return NULL;
};

int rbtree_erase(struct rbtree_t *rbtree, struct rbtree_node_t *rbtree_node)
{
	rb_erase(&rbtree_node->rb_node, &rbtree->rb_root);
	rbtree->count--;
	return 0;
}

char* string_buf(const struct string_t *string)
{
	const struct mem_node_t *mem_node = &string->mem_node;
	assert(mem_node->len > 0);
	return mem_node->buf;
}

void string_clean(struct string_t *string)
{
	mem_node_clean(&string->mem_node);
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

static void http_listen(const char *host, int port)
{
	int fd = 0;
	struct connection_t *connection = NULL;
	struct sockaddr addr;
	socklen_t addr_len = sizeof(struct sockaddr);
	fd = socket_listen(host, port, AF_INET);
	if (fd < 0) {
		LOG("listen_socket %s:%d error:%s\n", host, port, strerror(errno));
		return;
	}
	socket_non_block(fd);
	connection = http_malloc(sizeof(struct connection_t));
	memset(connection, 0, sizeof(struct connection_t));
	connection->fd = fd;
	getsockname(connection->fd, &connection->local_addr, &addr_len);
	connection->handle_read = http_client_accept;
	connection->epoll_thread = &epoll_threads[0];
	connection_epoll_add(connection, EPOLLIN);
	list_add_tail(&connection->node, &connection->epoll_thread->listen_list);
}

static void http_client_accept(struct connection_t *connection)
{
	struct epoll_thread_t *epoll_thread = connection->epoll_thread;
	struct sockaddr local_addr = connection->local_addr;
	struct sockaddr peer_addr;
	socklen_t addr_len = sizeof(struct sockaddr);
	char ip_str[64] = {0};
	int fd = 0;
	fd = accept(connection->fd, (struct sockaddr*)&peer_addr, &addr_len);
	if (fd < 0 ) {
		LOG("%s accept fail:%s\n", epoll_thread->name, strerror(errno));
		return;
	}
	socket_non_block(fd);
	connection = http_malloc(sizeof(struct connection_t));
	memset(connection, 0, sizeof(struct connection_t));
	connection->local_addr = local_addr;
	connection->peer_addr = peer_addr;
	connection->fd = fd;
	connection->epoll_thread = epoll_thread;
	LOG("%s accept %s fd=%d\n", epoll_thread->name, sockaddr_to_string(&connection->peer_addr, ip_str, sizeof(ip_str)), connection->fd);
	http_client_create(connection);
}

static struct http_client_t* http_client_create(struct connection_t *connection)
{
	struct http_client_t *http_client = NULL;
	struct http_request_t *http_request = NULL;
	struct mem_node_t *mem_node = NULL;
	http_client = http_malloc(sizeof(struct http_client_t));
	memset(http_client, 0, sizeof(struct http_client_t));

	http_request = http_request_create();
	http_request->epoll_thread = connection->epoll_thread;
	http_client->http_request = http_request_link(http_request);

	http_client->connection = connection;
	http_parser_init(&http_client->parser, HTTP_REQUEST);
	http_client->parser.data = http_request;
	string_init_size(&http_client->reply_header, PAGE_SIZE);

	connection->arg = http_client;
	connection->handle_read = http_client_read_request;
	connection->handle_write = NULL;
	connection_read_enable(connection);
	return http_client;
}

static void http_client_read_request(struct connection_t *connection)
{
	struct http_client_t *http_client = connection->arg;
	struct http_request_t *http_request = http_client->http_request;
	struct epoll_thread_t *epoll_thread = http_request->epoll_thread;
	char buf[PAGE_SIZE];
	ssize_t len;
	const char *host = NULL;
	const char *str = NULL;
	int offset = 0;
	struct iovec iovec[MAX_IOVEC];
	int count;
	iovec[0].iov_base = buf;
	iovec[0].iov_len = sizeof(buf);
	count = 1;
	assert(connection == http_client->connection);
	len = connection_tcp_readv(connection, iovec, count);
	if (len < 0) {
		http_client_close(http_client, ERROR_READ);
		LOG("%s %s fd=%d len=%d error:%s\n", epoll_thread->name, string_buf(&http_request->url), connection->fd, len, strerror(errno));
		return;
	} else if (len == 0) {
		LOG("%s %s fd=%d wait for read\n", epoll_thread->name, string_buf(&http_request->url), connection->fd);
		return;
	}
	LOG("%s %s fd=%d len=%d\n", epoll_thread->name, string_buf(&http_request->url), connection->fd, len);
	assert(http_request->parse_state < PARSER_HEADER_DONE);
	offset = http_parser_execute(&http_client->parser, &request_parser_settings, buf, len);
	if (offset < len && http_request->parse_state < PARSER_HEADER_DONE) {
		LOG("%s http_parser_execute error\n", epoll_thread->name);
		http_client_handle_error(http_client, ERROR_REQUEST);
		return;
	}
	if (http_request->parse_state < PARSER_HEADER_DONE) {
		connection->handle_read = http_client_read_request;
		connection_read_enable(connection);
		return;
	}
	if ((http_request->method == HTTP_CONNECT) || strncmp(string_buf(&http_request->uri), "http://", sizeof("http://") - 1) == 0) {
		string_strcat(&http_request->url, string_buf(&http_request->uri));
	} else {
		host = http_header_find(&http_request->header, "Host");
		if (host) {
			string_strcat(&http_request->url, "http://");
			string_strcat(&http_request->url, host);
			string_strcat(&http_request->url, string_buf(&http_request->uri));
		} else {
			http_client_handle_error(http_client, ERROR_REQUEST);
			return;
		}
	}
	if (http_parser_parse_url(string_buf(&http_request->url), string_strlen(&http_request->url), http_request->method == HTTP_CONNECT, &http_request->parser_url)) {
		LOG("%s %s http_parser_parse_url error\n", epoll_thread->name, string_buf(&http_request->url));
		http_client_handle_error(http_client, ERROR_REQUEST);
		return;
	}
	http_client_dump_request(http_client);
	http_client->range_expect = INT64_MAX;
	str = http_header_find(&http_request->header, "Range");
	if (str) {
		http_request->range = http_range_parse(str, strlen(str));
		if (http_request->range == NULL) {
			LOG("%s %s range error\n", epoll_thread->name, string_buf(&http_request->url));
			http_client_handle_error(http_client, ERROR_RANGE);
			return;
		}
	}
	str = http_header_find(&http_request->header, "Cache-Control");
	if (str) {
		http_request->cache_control = http_cache_control_parse(str);
	}    
	str = http_header_find(&http_request->header, "Content-Length");
	if (str) {
		http_request->content_length = atol(str);
	}    
	str = http_header_find(&http_request->header, "If-Modified-Since");
	if (str) {
		http_request->if_modified_since = http_parse_time(str, strlen(str));
	}    
	http_request->if_none_match = http_header_find(&http_request->header, "If-None-Match");
	http_client_process_request(http_client, buf + offset, len - offset);
}

static void http_client_process_request(struct http_client_t *http_client, char *buf, ssize_t len)
{
	struct connection_t *connection = http_client->connection;
	struct http_request_t *http_request = http_client->http_request;
	struct epoll_thread_t *epoll_thread = http_request->epoll_thread;
	struct http_server_t *http_server = NULL;
	struct cache_t *cache = NULL;
	char *key = string_buf(&http_request->url);
	if (http_client_cacheable(http_client)) {
		cache_table_lock();
		cache = rbtree_lookup(&cache_table.rbtree, key, offsetof(struct cache_t, rbtree_node));
		if (cache == NULL) {
			cache = http_cache_create(key);
			cache->epoll_thread = epoll_thread;
			cache->flags.cacheable = 1;
			rbtree_insert(&cache_table.rbtree, &cache->rbtree_node);
		} else {
			assert(cache->flags.cacheable);
		}
		assert(cache->epoll_thread == epoll_thread);
		http_client->cache = http_cache_link(cache);
		cache_table_unlock();
	} else {
		cache = http_cache_create(key);
		cache->epoll_thread = epoll_thread;
		cache->flags.cacheable = 0;
		http_client->cache = http_cache_link(cache);
	}
	if (cache->reply) {
	}
	if (cache->reply == NULL) {
		http_client->continuation.callback_data = http_client;
		//http_client->continuation.callback = http_client_handle_server_reply;
		http_client->continuation.type = CONTINUATION_REPLY;
		http_client->continuation.buf = NULL;
		list_add_tail(&http_client->continuation.node, &cache->client_list);
		if (list_empty(&cache->server_list)) {
			http_server = http_server_create(cache, http_request, NULL);
			http_server_forward(http_server);
		}
	}

	assert(http_request->page_list.low == 0);
	if (len > 0) {
		page_list_append_buf(&http_request->page_list, 0, buf, len);
	}
	if (http_request->method == HTTP_POST || http_request->method == HTTP_PUT) {
		http_request->body_client = http_client;
		http_client->connection->handle_read = http_client_read_body;
	} else {
		http_client->connection->handle_read = http_client_read_next_request;
	}
	if (http_client->connection->flags.read_trigger) {
		http_client->connection->handle_read(http_client->connection);
	}
}

static void http_client_read_body(struct connection_t *connection)
{
	struct http_client_t *http_client = connection->arg;
	struct http_request_t *http_request = http_client->http_request;
	struct http_server_t *http_server = http_request->body_server;
	struct epoll_thread_t *epoll_thread = http_request->epoll_thread;
	ssize_t len;
	struct iovec iovec[MAX_IOVEC];
	int count;
	assert(connection == http_client->connection);
	count = page_list_readv(&http_request->page_list, http_request->body_offset, MAX_IOVEC * PAGE_SIZE, iovec, MAX_IOVEC);
	assert(count > 0 && count <= MAX_IOVEC);
	len = connection_tcp_readv(connection, iovec, count);
	if (len < 0) {
		http_client_close(http_client, ERROR_READ);
		LOG("%s %s fd=%d len=%d error:%s\n", epoll_thread->name, string_buf(&http_request->url), connection->fd, len, strerror(errno));
		return;
	} else if (len == 0) {
		LOG("%s %s fd=%d wait for read\n", epoll_thread->name, string_buf(&http_request->url), connection->fd);
		return;
	}
	LOG("%s %s fd=%d len=%d\n", epoll_thread->name, string_buf(&http_request->url), connection->fd, len);
	page_list_fill_size(&http_request->page_list, http_request->body_offset, len);
	http_request->body_offset += len;
	if (http_server && http_server->connection) {
		connection_write_enable(http_server->connection);
	}
	if (http_request->body_offset >= http_request->content_length) {
		http_client->connection->handle_read = http_client_read_next_request;
	}
	if (http_request->page_list.data_size < PAGE_LIST_MAX_SIZE) {
		connection_read_enable(connection);
	} else {
		connection_read_disable(connection);
	}
}

static void http_client_read_next_request(struct connection_t *connection)
{
	struct http_client_t *http_client = connection->arg;
	struct http_request_t *http_request = http_client->http_request;
	struct epoll_thread_t *epoll_thread = http_request->epoll_thread;
	LOG("%s %s fd=%d\n", epoll_thread->name, string_buf(&http_request->url), connection->fd);
}

static void http_client_send_reply(struct connection_t *connection)
{
	struct http_client_t *http_client = connection->arg;
	struct http_request_t *http_request = http_client->http_request;
	struct epoll_thread_t *epoll_thread = http_request->epoll_thread;
	ssize_t len = 0;
	struct iovec iovec[MAX_IOVEC];
	int count;
	assert(connection == http_client->connection);
	if (http_client->reply_header_send < string_strlen(&http_client->reply_header)) {
		iovec[0].iov_base = string_buf(&http_client->reply_header) + http_client->reply_header_send;
		iovec[0].iov_len = string_strlen(&http_client->reply_header) - http_client->reply_header_send;
		count = 1;
	}
	len = connection_tcp_writev(connection, iovec, count);
	if (len < 0) {
		LOG("%s %s fd=%d len=%d error:%s\n", epoll_thread->name, string_buf(&http_request->url), connection->fd, len, strerror(errno));
		http_client_close(http_client, -1);
		return;
	} else if (len == 0) {
		LOG("%s %s fd=%d wait for send\n", epoll_thread->name, string_buf(&http_request->url), connection->fd);
		return;
	}
	LOG("%s %s fd=%d len=%d\n", epoll_thread->name, string_buf(&http_request->url), connection->fd, len);
	http_client->reply_header_send += len;

	if (http_client->reply_header_send >= string_strlen(&http_client->reply_header)) {
		connection->handle_write = http_client_send_body;
		if (connection->flags.write_trigger) {
			connection->handle_write(connection);
		}
	}
}

static void http_client_send_body(struct connection_t *connection)
{
	struct http_client_t *http_client = connection->arg;
	struct http_request_t *http_request = http_client->http_request;
	struct epoll_thread_t *epoll_thread = http_request->epoll_thread;
	struct http_server_t *http_server = http_client->continuation.buf;
	ssize_t len = 0;
	struct iovec iovec[MAX_IOVEC];
	int count;
	assert(connection == http_client->connection);
	if (http_client->range_current >= http_server->range_current) {
		connection_write_disable(connection);
		LOG("%s %s fd=%d no data to send\n", epoll_thread->name, string_buf(&http_request->url), connection->fd);
		return;
	}
	count = page_list_writev(&http_server->page_list, http_client->range_current,
			http_server->range_current - http_client->range_current, iovec, MAX_IOVEC);
	assert(count > 0 && count <= MAX_IOVEC);
	len = connection_tcp_writev(connection, iovec, count);
	if (len < 0) {
		LOG("%s %s fd=%d len=%d %s\n", epoll_thread->name, string_buf(&http_request->url), connection->fd, len, strerror(errno));
		http_client_close(http_client, -1);
		return;
	} else if (len == 0) {
		LOG("%s %s fd=%d wait for send\n", epoll_thread->name, string_buf(&http_request->url), connection->fd);
		return;
	}
	LOG("%s %s fd=%d len=%d\n", epoll_thread->name, string_buf(&http_request->url), connection->fd, len);
	http_client->range_current += len;
	if (http_client->range_current >= http_server->range_current) {
		connection_write_disable(connection);
		LOG("%s %s fd=%d no data to send\n", epoll_thread->name, string_buf(&http_request->url), connection->fd);
	} else {
		connection_write_enable(connection);
	}
	http_server_resum_read(http_server);
}

static void http_client_cache_hit(void *data)
{
}

static void http_client_build_reply(void *data)
{
	struct http_client_t *http_client = data;
	struct connection_t *connection = http_client->connection;
	struct http_request_t *http_request = http_client->http_request;
	struct epoll_thread_t *epoll_thread = http_request->epoll_thread;
	struct http_header_entry_t *header_entry = NULL;
	struct http_reply_t *http_reply = http_client->continuation.buf;
	assert(http_client->continuation.type == CONTINUATION_REPLY);
	assert(string_strlen(&http_client->reply_header) == 0);
	if (http_reply) {
		string_strcat_printf(&http_client->reply_header, "HTTP/%d.%d %s\r\n",
				http_reply->http_major, http_reply->http_minor, http_status_reasons_get(http_reply->status_code));
		list_for_each_entry(header_entry, &http_reply->header.header_list, header_entry_node) {
			string_strcat(&http_client->reply_header, string_buf(&header_entry->field_string));
			string_strcat(&http_client->reply_header, ": ");
			string_strcat(&http_client->reply_header, string_buf(&header_entry->value_string));
			string_strcat(&http_client->reply_header, "\r\n");
		}
	} else {
		string_strcat_printf(&http_client->reply_header, "HTTP/%d.%d %s\r\n",
				1, 1, http_status_reasons_get(503));
	}
	string_strcat(&http_client->reply_header, "via: http_server\r\n"); 
	string_strcat(&http_client->reply_header, "\r\n"); 
	LOG("%s %s reply=\n%s", epoll_thread->name, string_buf(&http_request->url), string_buf(&http_client->reply_header));
	connection->handle_write = http_client_send_reply;
	connection_write_enable(connection);
}

static void http_client_handle_ims(struct http_client_t *http_client)
{
}

static void http_client_handle_error(struct http_client_t *http_client, int error_type)
{
	int http_code = 0;
	struct http_header_t header_out;
	http_header_init(&header_out);
	if (string_strlen(&http_client->reply_header) > 0) {
		return;
	}
	switch (error_type) {
		case ERROR_REQUEST:
			http_code = 400;
			break;
		case ERROR_RANGE:
			http_code = 416;
			break;
		default:
			http_code = 0;
	}
	http_header_add(&header_out, "via", "http_server");
}

static int http_client_cacheable(struct http_client_t *http_client)
{
	return 0;
}

static void http_client_dump_request(struct http_client_t *http_client)
{
	struct http_request_t *http_request = http_client->http_request;
	struct epoll_thread_t *epoll_thread = http_request->epoll_thread;
	struct http_header_entry_t *header_entry;
	struct string_t string;
	string_init_size(&string, PAGE_SIZE);
	string_strcat_printf(&string, "%s %s HTTP/%d.%d\r\n", http_method_str(http_request->method),
			string_buf(&http_request->uri), http_request->http_major, http_request->http_minor);
	list_for_each_entry(header_entry, &http_request->header.header_list, header_entry_node) {
		string_strcat(&string, string_buf(&header_entry->field_string));
		string_strcat(&string, ": ");
		string_strcat(&string, string_buf(&header_entry->value_string));
		string_strcat(&string, "\r\n");
	}
	string_strcat(&string, "\r\n"); 
	LOG("%s %s request=\n%s", epoll_thread->name, string_buf(&http_request->url), string_buf(&string));
	string_clean(&string);
}

static struct http_request_t* http_request_create()
{
	struct http_request_t *http_request = NULL;
	http_request = http_malloc(sizeof(struct http_request_t));
	memset(http_request, 0, sizeof(struct http_request_t));
	http_header_init(&http_request->header);
	string_init_size(&http_request->uri, 1024);
	string_init_size(&http_request->url, 1024);
	page_list_init(&http_request->page_list);
	return http_request;
}

static struct http_request_t* http_request_link(struct http_request_t *http_request)
{
	http_request->link++;
	return http_request;
}

static void http_request_unlink(struct http_request_t *http_request)
{
	if (--http_request->link > 0) {
		return;
	}
	string_clean(&http_request->uri);
	string_clean(&http_request->url);
	http_header_clean(&http_request->header);
	if (http_request->range) {
		http_free(http_request->range);
		http_request->range = NULL;
	}
	if (http_request->cache_control) {
		http_free(http_request->cache_control);
		http_request->cache_control = NULL;
	}
	assert(http_request->body_client == NULL);
	assert(http_request->body_server == NULL);
	page_list_clean(&http_request->page_list);
}

static void http_client_close(struct http_client_t *http_client, int error_type)
{
	struct http_request_t *http_request = http_client->http_request;
	struct connection_t *connection = http_client->connection;
	struct epoll_thread_t *epoll_thread = http_request->epoll_thread;
	//LOG("%s %s close fd=%d total_size=%lld\n", epoll_thread->name, string_buf(&http_request->url), connection->fd, http_client->range_current - http_client->range_start);
	connection_close(connection);
	string_clean(&http_client->reply_header);
	http_request->body_client = NULL;
	http_request_unlink(http_request);
	http_free(http_client);
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
	if (http_reply->cache_control) {
		http_free(http_reply->cache_control);
	}
	http_free(http_reply);
}

static struct http_server_t *http_server_create(struct cache_t *cache, struct http_request_t *http_request, struct http_range_t *http_range)
{
	struct http_server_t *http_server = NULL;
	http_server = http_malloc(sizeof(struct http_server_t));
	memset(http_server, 0, sizeof(struct http_server_t));
	cache_table_lock();
	http_server->cache = http_cache_link(cache);
	cache_table_unlock();
	if (http_range) {
		http_server->http_range = http_malloc(sizeof(struct http_range_t));
		http_server->http_range->offset = http_range->offset;
		http_server->http_range->length = http_range->length;
	}
	if (http_request->body_client) {
		assert(http_request->body_server == NULL);
		http_request->body_server = http_server;
	}
	http_server->http_request = http_request_link(http_request);
	string_init_size(&http_server->request_header, PAGE_SIZE);
	http_server->request_header_send = 0;
	http_server->reply = http_reply_create();
	http_parser_init(&http_server->parser, HTTP_RESPONSE);
	http_server->parser.data = http_server->reply;
	page_list_init(&http_server->page_list);
	INIT_LIST_HEAD(&http_server->client_list);
	list_add_tail(&http_server->node, &cache->server_list);
	return http_server;
}

static void http_server_free(struct http_server_t *http_server)
{
	assert(http_server->connection == NULL);
	list_del(&http_server->node);
	http_cache_unlink(http_server->cache);
	if (http_server->http_range) {
		http_free(http_server->http_range);
	}
	string_clean(&http_server->request_header);
	page_list_clean(&http_server->page_list);
	assert(list_empty(&http_server->client_list));
	http_reply_free(http_server->reply);
	http_free(http_server);
}

static void http_server_forward(struct http_server_t *http_server)
{
	struct http_request_t *http_request = http_server->http_request;
	struct epoll_thread_t *epoll_thread = http_request->epoll_thread;
	struct string_t host;
	string_init_size(&host, 1024);
	string_strncat(&host, string_buf(&http_request->url) + http_request->parser_url.field_data[UF_HOST].off, http_request->parser_url.field_data[UF_HOST].len);
	http_server->continuation.callback_data = http_server;
	http_server->continuation.callback = http_server_connect;
	http_server->continuation.buf = &http_server->dns_info;
	epoll_thread_dns_connection_query(epoll_thread, string_buf(&host), &http_server->continuation);
	string_clean(&host); 
}

static void http_server_connect(void *data)
{
	struct http_server_t *http_server = data;
	struct http_request_t *http_request = http_server->http_request;
	struct epoll_thread_t *epoll_thread = http_request->epoll_thread;
	struct connection_t *connection = NULL;
	socklen_t addr_len = sizeof(struct sockaddr);
	int fd;
	char ip_str[64] = {0};
	uint16_t port = 80;
	int i, r;
	for (i = 0; i < http_server->dns_info.ipv4_num; i++) {
		inet_ntop(AF_INET, &http_server->dns_info.sin_addrs[i], ip_str, sizeof(ip_str));
		LOG("%s ipv4[%d]=%s\n", epoll_thread->name, i, ip_str);
	}
	for (i = 0; i < http_server->dns_info.ipv6_num; i++) {
		inet_ntop(AF_INET6, &http_server->dns_info.sin6_addrs[i], ip_str, sizeof(ip_str));
		LOG("%s ipv6[%d]=%s\n", epoll_thread->name, i, ip_str);
	}
	if (http_request->parser_url.field_set & (1 << UF_PORT)) {
		port = http_request->parser_url.port;
	}
	fd = socket(AF_INET , SOCK_STREAM, 0);
	if (fd < 0) {
		LOG("%s socket fd=%d error:%s\n", epoll_thread->name, fd, strerror(errno));
		http_server_close(http_server, -1);
		return;
	}
	connection = http_malloc(sizeof(struct connection_t));
	memset(connection, 0, sizeof(struct connection_t));
	connection->fd = fd;
	if (http_server->dns_info.ipv4_num > 0) {
		((struct sockaddr_in *)&connection->peer_addr)->sin_family = AF_INET;
		((struct sockaddr_in *)&connection->peer_addr)->sin_port = htons(port);
		((struct sockaddr_in *)&connection->peer_addr)->sin_addr.s_addr = http_server->dns_info.sin_addrs[0].s_addr;
	}
	getsockname(connection->fd, &connection->local_addr, &addr_len);
	socket_non_block(connection->fd);
	connection->handle_write = http_server_connect_check;
	connection->handle_read = http_server_read_reply;
	connection->arg = http_server;
	connection->epoll_thread = epoll_thread;
	http_server->connection = connection;
	r = connect(connection->fd, &connection->peer_addr, sizeof(struct sockaddr));
	if (r == 0) {
		http_server_connect_done(http_server, 0);
	} else if (errno == EINPROGRESS) {
		connection_write_enable(connection);
	} else {
		http_server_connect_done(http_server, -1);
	}
}

static void http_server_connect_check(struct connection_t *connection)
{
	struct http_server_t *http_server = connection->arg;
	ssize_t len = 0;
	char ip_str[64] = {0};
	assert(connection == http_server->connection);
	len = connection_tcp_connect(connection);
	if (len == 0) {
		http_server_connect_done(http_server, 0);
	} else {
		http_server_connect_done(http_server, -1);
	}
}

static void http_server_connect_done(struct http_server_t *http_server, int error)
{
	struct http_request_t *http_request = http_server->http_request;
	struct connection_t *connection = http_server->connection;
	struct epoll_thread_t *epoll_thread = http_request->epoll_thread;
	char ip_str[64] = {0};
	uint16_t port = ntohs(((struct sockaddr_in *)&connection->peer_addr)->sin_port);
	sockaddr_to_string(&connection->peer_addr, ip_str, sizeof(ip_str));
	if (error) {
		LOG("%s %s fd=%d connect to %s:%d fail\n", epoll_thread->name, string_buf(&http_request->url), connection->fd, ip_str, port);
		http_server_close(http_server, -1);
		return;
	}
	LOG("%s %s fd=%d connect to %s:%d ok\n", epoll_thread->name, string_buf(&http_request->url), connection->fd, ip_str, port);
	connection->handle_write = http_server_send_request;
	http_server_build_request(http_server);
	if (connection->flags.write_trigger) {
		connection->handle_write(connection);
	} else {
		connection_write_enable(connection);
	}
	connection_read_enable(connection);
}

static void http_server_build_request(struct http_server_t *http_server)
{
	struct http_request_t *http_request = http_server->http_request;
	struct epoll_thread_t *epoll_thread = http_request->epoll_thread;
	struct http_range_t *http_range = http_server->http_range;
	struct http_header_entry_t *header_entry;
	char str[256];
	char *path = "/";
	if (http_request->parser_url.field_set & (1 << UF_PATH)) {
		path = string_buf(&http_request->url) + http_request->parser_url.field_data[UF_PATH].off;
	}
	string_strcat_printf(&http_server->request_header, "%s %s HTTP/%d.%d\r\n", http_method_str(http_request->method),
			path, http_request->http_major, http_request->http_minor);
	list_for_each_entry(header_entry, &http_request->header.header_list, header_entry_node) {
		if (strcasecmp(string_buf(&header_entry->field_string), "Proxy-Connection") == 0) {
			continue;
		} else if (http_range && strcasecmp(string_buf(&header_entry->field_string), "Range") == 0) {
			continue;
		}
		string_strcat(&http_server->request_header, string_buf(&header_entry->field_string));
		string_strcat(&http_server->request_header, ": ");
		string_strcat(&http_server->request_header, string_buf(&header_entry->value_string));
		string_strcat(&http_server->request_header, "\r\n");
	}
	if (http_range) {
		snprintf(str, sizeof(str), "Range: %lld-%lld\r\n", http_range->offset, http_range->offset + http_range->length - 1);
		string_strcat(&http_server->request_header, str);
	}
	string_strcat(&http_server->request_header, "\r\n"); 
	LOG("%s %s request=\n%s\n", epoll_thread->name, string_buf(&http_request->url), string_buf(&http_server->request_header));
}

static void http_server_send_request(struct connection_t *connection)
{
	struct http_server_t *http_server = connection->arg;
	struct http_request_t *http_request = http_server->http_request;
	struct epoll_thread_t *epoll_thread = http_request->epoll_thread;
	ssize_t len = 0;
	struct iovec iovec[MAX_IOVEC];
	int count;
	assert(connection == http_server->connection);
	if (http_server->request_header_send < string_strlen(&http_server->request_header)) {
		iovec[0].iov_base = string_buf(&http_server->request_header) + http_server->request_header_send;
		iovec[0].iov_len = string_strlen(&http_server->request_header) - http_server->request_header_send;
		count = 1;
	}
	len = connection_tcp_writev(connection, iovec, count);
	if (len < 0) {
		LOG("%s %s fd=%d len=%d error:%s\n", epoll_thread->name, string_buf(&http_request->url), connection->fd, len, strerror(errno));
		http_server_close(http_server, -1);
		return;
	} else if (len == 0) {
		LOG("%s %s fd=%d wait for send\n", epoll_thread->name, string_buf(&http_request->url), connection->fd);
		return;
	}
	LOG("%s %s fd=%d len=%d\n", epoll_thread->name, string_buf(&http_request->url), connection->fd, len);
	http_server->request_header_send += len;
	if (http_server->request_header_send < string_strlen(&http_server->request_header)) {
		connection_write_enable(connection);
	} else if (http_request->body_client) {
		connection->handle_write = http_server_send_body;
		if (connection->flags.write_trigger) {
			connection->handle_write(connection);
		}
	} else {
		connection->handle_write = NULL;
		connection_write_disable(connection);
	}
}

static void http_server_send_body(struct connection_t *connection)
{
	struct http_server_t *http_server = connection->arg;
	struct http_request_t *http_request = http_server->http_request;
	struct http_client_t *http_client = http_request->body_client;
	struct epoll_thread_t *epoll_thread = http_request->epoll_thread;
	ssize_t len;
	struct iovec iovec[MAX_IOVEC];
	int count;
	if (http_server->body_send >= http_request->body_offset) {
		connection_write_disable(connection);
		LOG("%s %s fd=%d no data to send\n", epoll_thread->name, string_buf(&http_request->url), connection->fd);
		return;
	}
	count = page_list_writev(&http_request->page_list, http_server->body_send,
			http_request->body_offset - http_server->body_send, iovec, MAX_IOVEC);
	assert(count > 0 && count <= MAX_IOVEC);
	len = connection_tcp_writev(connection, iovec, count);
	if (len < 0) {
		LOG("%s %s fd=%d len=%d %s\n", epoll_thread->name, string_buf(&http_request->url), connection->fd, len, strerror(errno));
		http_server_close(http_server, -1);
		return;
	} else if (len == 0) {
		LOG("%s %s fd=%d wait for send\n", epoll_thread->name, string_buf(&http_request->url), connection->fd);
		return;
	}
	LOG("%s %s fd=%d len=%d\n", epoll_thread->name, string_buf(&http_request->url), connection->fd, len);
	http_server->body_send += len;
	page_list_free_to(&http_request->page_list, http_server->body_send);
	if (http_server->body_send >= http_request->body_offset) {
		connection_write_disable(connection);
		LOG("%s %s fd=%d no data to send\n", epoll_thread->name, string_buf(&http_request->url), connection->fd);
	}
	if (http_client) {
		if (http_client->connection && http_request->page_list.data_size < PAGE_LIST_MAX_SIZE) {
			connection_read_enable(http_client->connection);
		}
	}
}

static void http_server_read_reply(struct connection_t *connection)
{
	struct http_server_t *http_server = connection->arg;
	struct http_request_t *http_request = http_server->http_request;
	struct epoll_thread_t *epoll_thread = http_request->epoll_thread;
	struct http_reply_t *http_reply = http_server->reply;
	char buf[PAGE_SIZE];
	struct iovec iovec[MAX_IOVEC];
	int count;
	ssize_t len;
	const char *str = NULL;
	struct http_content_range_t *content_range = NULL;
	size_t offset = 0;
	assert(connection == http_server->connection);
	iovec[0].iov_base = buf;
	iovec[0].iov_len = sizeof(buf);
	count = 1;
	len = connection_tcp_readv(connection, iovec, count);
	if (len < 0) {
		http_server_close(http_server, ERROR_READ);
		LOG("%s %s fd=%d len=%d %s\n", epoll_thread->name, string_buf(&http_request->url), connection->fd, len, strerror(errno));
		return;
	} else if (len == 0) {
		LOG("%s %s fd=%d wait for head\n", epoll_thread->name, string_buf(&http_request->url), connection->fd);
		return;
	}
	LOG("%s %s fd=%d len=%d\n", epoll_thread->name, string_buf(&http_request->url), connection->fd, len);
	assert(http_reply->parse_state < PARSER_HEADER_DONE);
	offset = http_parser_execute(&http_server->parser, &reply_parser_settings, buf, len);
	LOG("%s %s fd=%d len=%d parsed=%d\n", epoll_thread->name, string_buf(&http_request->url), connection->fd, len, offset);

	if (offset < len && http_reply->parse_state < PARSER_HEADER_DONE) {
		LOG("%s http_parser_execute error\n", epoll_thread->name);
		http_server_close(http_server, ERROR_REPLY);
		return;
	}
	if (http_reply->parse_state < PARSER_HEADER_DONE) {
		LOG("%s %s fd=%d wait for head\n", epoll_thread->name, string_buf(&http_request->url), connection->fd);
		connection_read_enable(connection);
		return;
	}
	http_server_dump_reply(http_server);
	if ((str = http_header_find(&http_reply->header, "Transfer-Encoding")) && strcasecmp(str, "chunked") == 0) {
		http_reply->chunked = 1;
		http_server->range_expect = INT64_MAX;
	} else if (http_reply->status_code == 206) {
		if ((str = http_header_find(&http_reply->header, "Cache-Range")) && (content_range = http_content_range_parse(str))) {
			http_server->range_start = content_range->start;
			http_server->range_current = http_server->range_start;
			http_server->range_expect = content_range->end;
			http_free(content_range);
		} else {
			http_server_close(http_server, ERROR_RANGE);
			return;
		}
	} else {
		http_server->range_start = 0;
		http_server->range_current = http_server->range_start;
		if ((str = http_header_find(&http_reply->header, "Content-Length"))) {
			http_reply->content_length = atoll(str);
		}
		http_server->range_expect = http_reply->content_length;
		if (http_request->method == HTTP_HEAD || http_reply->status_code == 204 || http_reply->status_code == 304) {
			http_server->range_expect = 0;
		}
	}
	if ((str = http_header_find(&http_reply->header, "Cache-Control"))) {
		http_reply->cache_control = http_cache_control_parse(str);
	}
	http_server->page_list.low = http_server->range_current / PAGE_SIZE * PAGE_SIZE;
	http_server_process_reply(http_server, buf + offset, len - offset);
}

static ssize_t http_server_parse_chunk(struct http_server_t *http_server, char *buf, ssize_t len)
{
	struct http_request_t *http_request = http_server->http_request;
	struct connection_t *connection = http_server->connection;
	struct epoll_thread_t *epoll_thread = http_request->epoll_thread;
	struct http_reply_t *http_reply = http_server->reply;
	int rc;
	int buf_pos;
	char *ptr = NULL;
	int ptr_len = 0; 
	size_t nparsed = 0; 
	while (1) {
		ptr = (uint8_t*)buf + nparsed;
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
			LOG("%s %s fd=%d done\n", epoll_thread->name, string_buf(&http_request->url), connection->fd);
			http_server->range_expect = http_server->range_current + nparsed;
			break;
		}    
		if (rc == HTTP_AGAIN) {
			break;
		}
		LOG("%s %s fd=%d error\n", epoll_thread->name, string_buf(&http_request->url), connection->fd);
		break;
	}
	return nparsed;
}

static void http_server_process_reply(struct http_server_t *http_server, char *buf, ssize_t len)
{
	struct http_request_t *http_request = http_server->http_request;
	struct connection_t *connection = http_server->connection;
	struct epoll_thread_t *epoll_thread = http_request->epoll_thread;
	struct http_reply_t *http_reply = http_server->reply;
	ssize_t chunk_len;
	LOG("%s %s fd=%d len=%d\n", epoll_thread->name, string_buf(&http_request->url), connection->fd, len);
	if (len > 0) {
		page_list_append_buf(&http_server->page_list, http_server->range_current, buf, len);
		if (http_reply->chunked) {
			chunk_len = http_server_parse_chunk(http_server, buf, len);
			page_list_fill_size(&http_server->page_list, http_server->range_current, chunk_len);
			http_server->range_current += chunk_len;
			if (chunk_len < len) {
				http_server_close(http_server, ERROR_CHUNK);
				return;
			}
		} else {
			page_list_fill_size(&http_server->page_list, http_server->range_current, len);
			http_server->range_current += len;
		}
	}
	if (http_server->range_current >= http_server->range_expect) {
		LOG("%s %s fd=%d size=%lld\n", epoll_thread->name, string_buf(&http_request->url), connection->fd, http_server->range_current - http_server->range_start);
		http_server_close(http_server, ERROR_NONE);
		return;
	} else {
		http_server_invoke_clients(http_server);
		connection->handle_read = http_server_read_body;
		if (connection->flags.read_trigger) {
			connection->handle_read(connection);
		}
	}
}

static void http_server_read_body(struct connection_t *connection)
{
	struct http_server_t *http_server = connection->arg;
	struct http_request_t *http_request = http_server->http_request;
	struct http_reply_t *http_reply = http_server->reply;
	struct epoll_thread_t *epoll_thread = http_request->epoll_thread;
	ssize_t len;
	char buf[PAGE_SIZE];
	struct iovec iovec[MAX_IOVEC];
	int count;
	count = page_list_readv(&http_server->page_list, http_server->range_current, MAX_IOVEC * PAGE_SIZE, iovec, MAX_IOVEC);
	assert(count > 0 && count <= MAX_IOVEC);
	len = connection_tcp_readv(connection, iovec, count);
	if (len < 0) {
		http_server_close(http_server, ERROR_READ);
		LOG("%s %s fd=%d len=%d %s\n", epoll_thread->name, string_buf(&http_request->url), connection->fd, len, strerror(errno));
		return;
	} else if (len == 0) {
		LOG("%s %s fd=%d wait for read\n", epoll_thread->name, string_buf(&http_request->url), connection->fd);
		return;
	}
	LOG("%s %s fd=%d len=%d\n", epoll_thread->name, string_buf(&http_request->url), connection->fd, len);
	if (http_reply->chunked) {
		int i = 0;
		ssize_t tmp_len = len;
		ssize_t chunk_len;
		size_t iov_len;
		while (tmp_len > 0) {
			iov_len = MIN(iovec[i].iov_len, tmp_len);
			chunk_len = http_server_parse_chunk(http_server, iovec[i].iov_base, iov_len);
			page_list_fill_size(&http_server->page_list, http_server->range_current, chunk_len);
			http_server->range_current += chunk_len;
			if (chunk_len < iov_len) {
				http_server_close(http_server, ERROR_CHUNK);
				return;
			}
			i++;
			tmp_len -= iov_len;
		}
	} else {
		page_list_fill_size(&http_server->page_list, http_server->range_current, len);
		http_server->range_current += len;
	}
	if (http_server->range_current >= http_server->range_expect) {
		http_server_close(http_server, ERROR_NONE);
		return;
	} else if (http_server->page_list.data_size < PAGE_LIST_MAX_SIZE) {
		connection_read_enable(http_server->connection);
	} else {
		connection_read_disable(http_server->connection);
	}
	http_server_invoke_clients(http_server);
}

static void continuation_attach_http_server(struct continuation_t *continuation, struct http_server_t *http_server)
{
	list_add_tail(&continuation->node, &http_server->client_list);
	continuation->type = CONTINUATION_SERVER;
	continuation->buf = http_server;
}

static void continuation_detach_http_server(struct continuation_t *continuation, struct http_server_t *http_server)
{
	assert(continuation->type == CONTINUATION_SERVER);
	assert(continuation->buf == http_server);
	if (list_empty(&http_server->client_list) && http_server->connection == NULL) {
		http_server_free(http_server);
	} else {
		http_server_resum_read(http_server);
	}
}

static void continuation_detach(struct continuation_t *continuation)
{
	struct http_server_t *http_server = NULL;
	assert(!list_node_null(&continuation->node));
	list_del(&continuation->node);
	if (continuation->type == CONTINUATION_SERVER) {
		http_server = continuation->buf;
		continuation_detach_http_server(continuation, http_server);
	}
	continuation->type = CONTINUATION_NONE;
	continuation->buf = NULL;
}

static void http_server_invoke_clients(struct http_server_t *http_server)
{
	struct continuation_t *continuation = NULL;
	struct continuation_t *continuation_tmp = NULL;
	list_for_each_entry_safe(continuation, continuation_tmp, &http_server->client_list, node) {
		if (continuation->wait) {
			continuation->callback(continuation->callback_data);
		}
	}
}

static void http_server_resum_read(struct http_server_t *http_server)
{
	struct continuation_t *continuation = NULL;
	struct http_client_t *http_client = NULL;
	int64_t offset = http_server->range_current;
	list_for_each_entry(continuation, &http_server->client_list, node) {
		http_client = continuation->callback_data;
		if (http_client->range_current < offset) {
			offset = http_client->range_current;
		}
	}
	page_list_free_to(&http_server->page_list, offset);
	if (http_server->connection && http_server->page_list.data_size < PAGE_LIST_MAX_SIZE) {
		connection_read_enable(http_server->connection);
	}
}

static void http_server_close(struct http_server_t *http_server, int error)
{
	struct http_request_t *http_request = http_server->http_request;
	struct connection_t *connection = http_server->connection;
	struct epoll_thread_t *epoll_thread = http_request->epoll_thread;
	LOG("%s %s close fd=%d total_size=%lld\n", epoll_thread->name, string_buf(&http_request->url), connection->fd, http_server->range_current - http_server->range_start);
	connection_close(connection);
	http_server->connection = NULL;
	http_server_invoke_clients(http_server);
}

static void http_server_dump_reply(struct http_server_t *http_server)
{
	struct http_request_t *http_request = http_server->http_request;
	struct epoll_thread_t *epoll_thread = http_request->epoll_thread;
	struct http_reply_t *http_reply = http_server->reply;
	struct http_header_entry_t *header_entry;
	struct string_t string;
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
	LOG("%s %s reply=\n%s", epoll_thread->name, string_buf(&http_request->url), string_buf(&string));
	string_clean(&string);
}

int connection_epoll_add(struct connection_t *connection, uint32_t event)
{
	int r;
	struct epoll_thread_t *epoll_thread = connection->epoll_thread;
	struct epoll_event ev = {0};
	ev.data.ptr = connection;
	ev.events = event | EPOLLET;
	r = epoll_ctl(epoll_thread->epoll_fd, EPOLL_CTL_ADD, connection->fd, &ev);
	if (r) {
		LOG("fail epoll_fd=%d fd=%d: %s\n", epoll_thread->epoll_fd, connection->fd, strerror(errno));
	} else {
		connection->event = event;
	}
	return r;
}

int connection_epoll_mod(struct connection_t *connection, uint32_t event)
{
	int r;
	struct epoll_thread_t *epoll_thread = connection->epoll_thread;
	struct epoll_event ev = {0};
	if (connection->event == event) {
		//return 0;
	}
	ev.data.ptr = connection;
	ev.events = event | EPOLLET;
	r = epoll_ctl(epoll_thread->epoll_fd, EPOLL_CTL_MOD, connection->fd, &ev);
	if (r) {
		LOG("fail epoll_fd=%d fd=%d: %s\n", epoll_thread->epoll_fd, connection->fd, strerror(errno));
	} else {
		connection->event = event;
	}
	return r;
}

int connection_epoll_del(struct connection_t *connection)
{
	int r;
	struct epoll_thread_t *epoll_thread = connection->epoll_thread;
	struct epoll_event ev = {0};
	r = epoll_ctl(epoll_thread->epoll_fd, EPOLL_CTL_DEL, connection->fd, &ev);
	if (r) {
		LOG("fail epoll_fd=%d fd=%d: %s\n", epoll_thread->epoll_fd, connection->fd, strerror(errno));
	} else {
		connection->event = 0;
	}
	return r;
}

void connection_read_enable(struct connection_t *connection)
{
	struct epoll_thread_t *epoll_thread = connection->epoll_thread;
	if (connection->flags.read_trigger) {
		if (list_node_null(&connection->read_ready_node)) {
			list_add_tail(&connection->read_ready_node, &epoll_thread->read_ready_list);
		}
	} else if (connection->event == 0) {
		connection_epoll_add(connection, EPOLLIN);
	} else if ((connection->event & EPOLLIN) == 0) {
		connection_epoll_mod(connection, connection->event | EPOLLIN);
	}
}

void connection_read_disable(struct connection_t *connection)
{
	if (connection->flags.read_trigger) {
		if (!list_node_null(&connection->read_ready_node)) {
			list_del(&connection->read_ready_node);
		}
		connection->flags.read_trigger = 0;
	}
	if ((connection->event & (~EPOLLIN)) == 0) {
		connection_epoll_del(connection);
	} else {
		connection_epoll_mod(connection, connection->event & (~EPOLLIN));
	}
}

void connection_write_enable(struct connection_t *connection)
{
	struct epoll_thread_t *epoll_thread = connection->epoll_thread;
	if (connection->flags.write_trigger) {
		if (list_node_null(&connection->write_ready_node)) {
			list_add_tail(&connection->write_ready_node, &epoll_thread->write_ready_list);
		}
	} else if (connection->event == 0) {
		connection_epoll_add(connection, EPOLLOUT);
	} else if ((connection->event & EPOLLOUT) == 0) {
		connection_epoll_mod(connection, connection->event | EPOLLOUT);
	}
}

void connection_write_disable(struct connection_t *connection)
{
	if (connection->flags.write_trigger) {
		if (!list_node_null(&connection->write_ready_node)) {
			list_del(&connection->write_ready_node);
		}
		connection->flags.write_trigger = 0;
	}
	if ((connection->event & (~EPOLLOUT)) == 0) {
		connection_epoll_del(connection);
	} else {
		connection_epoll_mod(connection, connection->event & (~EPOLLOUT));
	}
}

void connection_close(struct connection_t *connection)
{
	if (!list_node_null(&connection->read_ready_node)) {
		list_del(&connection->read_ready_node);
	}
	if (!list_node_null(&connection->write_ready_node)) {
		list_del(&connection->write_ready_node);
	}
	if (connection->event) {
		connection_epoll_del(connection);
	}
	close(connection->fd);
	http_free(connection);
}

ssize_t connection_tcp_readv(struct connection_t *connection, const struct iovec *vector, int count)
{
	ssize_t nread = 0;
	nread = readv(connection->fd, vector, count);
	if (nread == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
		connection->flags.read_trigger = 0;
		nread = 0;
	}
	return nread;
}

ssize_t connection_tcp_writev(struct connection_t *connection, const struct iovec *vector, int count)
{
	ssize_t nwrite = 0;
	nwrite = writev(connection->fd, vector, count);
	if (nwrite == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
		connection->flags.write_trigger = 0;
		nwrite = 0;
	}
	return nwrite;
}

ssize_t connection_tcp_connect(struct connection_t *connection)
{
	socklen_t len = sizeof(int); 
	int error;
	if (getsockopt(connection->fd, SOL_SOCKET, SO_ERROR, &error, &len) || error) {
		connection->flags.write_trigger = 0;
		return -1;
	} else {
		connection->flags.write_trigger = 1;
		return 0;
	} 
}

static int socket_listen(const char *host, uint16_t port, int family)
{
	struct addrinfo hints;
	int fd = -1;
	int r;
	char service[10];
	snprintf(service, sizeof(service), "%u", port);
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
#ifdef AI_ADDRCONFIG
	hints.ai_flags |= AI_ADDRCONFIG;
#endif // AI_ADDRCONFIG
	struct addrinfo *res, *rp;
	const char* host_str;
	if(host == NULL) {
		host_str = 0;
	} else {
		host_str = host;
	}
	r = getaddrinfo(host_str, service, &hints, &res);
	if(r != 0) {
		LOG("getaddrinfo:%s\n", gai_strerror(r));
		return -1;
	}
	for(rp = res; rp; rp = rp->ai_next) {
		fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if(fd == -1) {
			continue;
		}
		int val = 1;
		if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) == -1) {
			close(fd);
			continue;
		}
#ifdef IPV6_V6ONLY
		if(family == AF_INET6) {
			if(setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof(val)) == -1) {
				close(fd);
				continue;
			}
		}
#endif // IPV6_V6ONLY
		if(bind(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
			break;
		}
		close(fd);
	}
	freeaddrinfo(res);
	if(rp == 0) {
		return -1;
	} else {
		if(listen(fd, 100) == -1) {
			close(fd);
			return -1;
		} else {
			return fd;
		}
	}
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
	string_strncat(&http_request->uri, at, length);
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
	const struct string_t *if_modified_since_string = NULL;

	http_request->http_major = hp->http_major;
	http_request->http_minor = hp->http_minor;
	http_request->method = hp->method;

	str = http_header_find(&http_request->header, "Cache-Control");
	if (str) {
		http_request->cache_control = http_cache_control_parse(str);
	}
	str = http_header_find(&http_request->header, "Content-Length");
	if (str) {
		http_request->content_length = atol(str);
	}
	if_modified_since_string = http_header_find_string(&http_request->header, "If-Modified-Since");
	if (if_modified_since_string) {
		http_request->if_modified_since = http_parse_time(string_buf(if_modified_since_string), string_strlen(if_modified_since_string));
	}
	str = http_header_find(&http_request->header, "Proxy-Connection");
	if (http_request->http_minor >= 1) {
		http_request->keep_alive = 1;
		if (str && strcasecmp(str, "Close") == 0) {
			http_request->keep_alive = 0;
		}
	} else {
		http_request->keep_alive = 0;
		if (str && strcasecmp(str, "Keep-Alive") == 0) {
			http_request->keep_alive = 1;
		}
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
	struct http_reply_t *http_reply = hp->data;
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

static int cache_key_cmp(const void *key1, const void *key2)
{
	return strcmp((const char *)key1, (const char *)key2);
}

static struct cache_t* http_cache_create(const char *key)
{
	struct cache_t *cache = NULL;
	cache = http_malloc(sizeof(struct cache_t));
	memset(cache, 0, sizeof(struct cache_t));
	cache->rbtree_node.key = http_strdup(key);
	INIT_LIST_HEAD(&cache->client_list);
	INIT_LIST_HEAD(&cache->server_list);
	return cache;
}

static struct cache_t* http_cache_link(struct cache_t *cache)
{
	++cache->link;
	return cache;
}

static void http_cache_unlink(struct cache_t *cache)
{
	if (--cache->link > 0) {
		return;
	}
}

static void http_cache_handle_reply(struct cache_t *cache, struct http_reply_t *http_reply)
{
}

static void cache_table_init()
{
	memset(&cache_table, 0, sizeof(struct cache_table_t));
	pthread_mutex_init(&cache_table.mutex, NULL);
	rbtree_init(&cache_table.rbtree, cache_key_cmp);
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

static void cache_table_clean()
{
}

void log_printf(const char *file, int line, const char *function, const char *fmt, ...)
{
	va_list argptr;
	time_t current;
	struct tm tm;
	char timespan[64];
	current = time(NULL);
	localtime_r(&current, &tm);
	//strftime(timespan, sizeof(timespan), "%Y/%m/%d %H:%M:%S", &tm);
	snprintf(timespan, sizeof(timespan), "%d/%02d/%02d %02d:%02d:%02d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
	fprintf(stdout, "%s %s|%d|%s: ", timespan, file, line, function);
	va_start(argptr, fmt);
	vfprintf(stdout, fmt, argptr);
	va_end(argptr);
}

int main()
{
	int i = 0;
	if (signal(SIGINT, sig_int) == SIG_ERR) {
		LOG("regist SIGINT error\n");
	}
	if (signal(SIGPIPE, sig_pipe) == SIG_ERR) {
		LOG("regist SIGPIPE error\n");
	}

	dns_table_init();
	cache_table_init();

	epoll_threads = http_malloc(sizeof(struct epoll_thread_t) * epoll_threads_num);
	aio_threads = http_malloc(sizeof(struct aio_thread_t) * aio_threads_num);

	for (i = 0; i < epoll_threads_num; i++) {
		snprintf(epoll_threads[i].name, sizeof(epoll_threads[i].name), "net[%d]", i);
		epoll_thread_init(&epoll_threads[i]);
	}
	for (i = 0; i < aio_threads_num; i++) {
		snprintf(aio_threads[i].name, sizeof(aio_threads[i].name), "aio[%d]", i);
		aio_thread_init(&aio_threads[i]);
	}

	http_listen("0.0.0.0", 8888);

	for (i = 0; i < epoll_threads_num; i++) {
		if (pthread_create(&epoll_threads[i].tid, NULL, epoll_thread_loop, &epoll_threads[i])) {
			LOG("%s pthread_create error\n", epoll_threads[i].name);
			assert(0);
		}
	}
	for (i = 0; i < aio_threads_num; i++) {
		if (pthread_create(&aio_threads[i].tid, NULL, aio_thread_loop, &aio_threads[i])) {
			LOG("%s pthread_create error\n", aio_threads[i].name);
			assert(0);
		}
	}

	for (i = 0; i < epoll_threads_num; i++) {
		pthread_join(epoll_threads[i].tid, NULL);
	}
	for (i = 0; i < aio_threads_num; i++) {
		pthread_join(aio_threads[i].tid, NULL);
	}

	for (i = 0; i < epoll_threads_num; i++) {
		epoll_thread_free(&epoll_threads[i]);
	}
	for (i = 0; i < aio_threads_num; i++) {
		aio_thread_free(&aio_threads[i]);
	}

	http_free(epoll_threads);
	http_free(aio_threads);

	cache_table_clean();
	dns_table_clean();
	return 0;
}
