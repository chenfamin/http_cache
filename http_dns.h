#ifndef HTTP_DNS_H
#define HTTP_DNS_H

#include "http.h"


#define MAX_DNS_BUFFER 1460

struct dns_cache_table_t {
	struct rb_root rb_root;
	pthread_mutex_t mutex;
	int64_t count;
};

struct dns_info_t {
	int ipv4_num;
	int ipv6_num;
	int cname_num;
	int ttl;
	struct in_addr *sin_addrs;
	struct in6_addr *sin6_addrs;
};

struct dns_cache_t {
	char *key;
	struct rb_node rb_node;
	struct dns_info_t dns_info;
};

struct dns_session_t {
	struct connection_t *connection;
	uint16_t id;
	struct list_head_t write_list;
	struct list_head_t wait_list;
	struct epoll_thread_t *epoll_thread;
};

struct dns_query_t {
	char *host;
	uint16_t id;

	struct dns_info_t dns_info;
	char buf[MAX_DNS_BUFFER];
	int buf_len;
	struct list_head_t client_list;
	struct list_head_t node;
};

void dns_cache_table_init();
void dns_cache_table_clean();

void dns_info_copy(struct dns_info_t *dest, const struct dns_info_t *src);
void dns_info_clean(struct dns_info_t *dns_info);

struct dns_session_t* dns_session_create(struct epoll_thread_t *epoll_thread);
void dns_session_query(struct dns_session_t *dns_session, const char *host, struct continuation_t *continuation);
void dns_session_close(struct dns_session_t *dns_session);

#endif
