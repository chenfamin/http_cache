#ifndef HTTP_DNS_H
#define HTTP_DNS_H

#include "http_util.h"
#include "http_connection.h"

#define MAX_DNS_BUFFER 1460

#define RFC1035_TYPE_A 1
#define RFC1035_TYPE_AAAA 28
#define RFC1035_TYPE_CNAME 5
#define RFC1035_TYPE_PTR 12
#define RFC1035_CLASS_IN 1
#define DNS_EXPIRE_TIME (60 * 1000)

#define RFC1035_MAXHOSTNAMESZ 256
#define RFC1035_MAXLABELSZ 63
#define rfc1035_unpack_error 15

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

struct rfc1035_query_t {
	char name[RFC1035_MAXHOSTNAMESZ];
	unsigned short qtype;
	unsigned short qclass;
};

struct rfc1035_rr_t {
	char name[RFC1035_MAXHOSTNAMESZ];
	unsigned short type;
	unsigned short class;
	unsigned int ttl;
	unsigned short rdlength;
	char *rdata;
};

struct rfc1035_message_t {
	unsigned short id;
	unsigned int qr:1;
	unsigned int opcode:4;
	unsigned int aa:1;
	unsigned int tc:1;
	unsigned int rd:1;
	unsigned int ra:1;
	unsigned int rcode:4;
	unsigned short qdcount;
	unsigned short ancount;
	unsigned short nscount;
	unsigned short arcount;
	struct rfc1035_query_t *query;
	struct rfc1035_rr_t *answer;
};


void dns_cache_table_create();
void dns_cache_table_free();

void dns_info_copy(struct dns_info_t *dest, const struct dns_info_t *src);
void dns_info_clean(struct dns_info_t *dns_info);

struct dns_session_t* dns_session_create(struct epoll_thread_t *epoll_thread);
void dns_session_query(struct dns_session_t *dns_session, const char *host, struct continuation_t *continuation);
void dns_session_close(struct dns_session_t *dns_session);

#endif
