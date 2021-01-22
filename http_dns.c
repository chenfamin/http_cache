#include "http_util.h"
#include "http_log.h"
#include "http_dns.h"

static struct dns_cache_table_t dns_cache_table;

static int dns_cache_table_lock();
static int dns_cache_table_unlock();
static struct dns_cache_t* dns_cache_table_lookup(const void *key);
static int dns_cache_table_insert(struct dns_cache_t *dns_cache);
static int dns_cache_table_erase(struct dns_cache_t *dns_cache);
static struct dns_cache_t* dns_cache_alloc(const char *key);
static void dns_cache_free(struct dns_cache_t *dns_cache);

static void dns_query_read(struct connection_t *connection);
static void dns_query_parse_data(struct dns_query_t *dns_query, struct rfc1035_rr_t *answers, int n);
static void dns_query_write(struct connection_t *connection);
static void dns_query_create(struct dns_session_t *dns_session, const char *host, struct continuation_t *continuation);
static void dns_query_free(struct dns_query_t *dns_query);
static int rfc1035NamePack(char *buf, size_t sz, const char *name);
static int rfc1035LabelPack(char *buf, size_t sz, const char *label);
static int rfc1035MessageUnpack(const char *buf, size_t sz, struct rfc1035_message_t **answer);
static int rfc1035HeaderUnpack(const char *buf, size_t sz, int *off, struct rfc1035_message_t *h);
static int rfc1035QueryUnpack(const char *buf, size_t sz, int *off, struct rfc1035_query_t *query);
static int rfc1035RRUnpack(const char *buf, size_t sz, int *off, struct rfc1035_rr_t *RR);
static int rfc1035NameUnpack(const char *buf, size_t sz, int *off, unsigned short *rdlength, char *name, size_t ns, int rdepth);
static void rfc1035RRDestroy(struct rfc1035_rr_t * rr, int n);
static void rfc1035MessageDestroy(struct rfc1035_message_t *msg);
#if 0
static int rfc1035QueryCompare(const struct rfc1035_query_t *a, const struct rfc1035_query_t *b);
#endif

static const char* rfc1035MessageErrno(int rfc1035_errno);

void dns_cache_table_create()
{
	memset(&dns_cache_table, 0, sizeof(struct dns_cache_table_t));
	pthread_mutex_init(&dns_cache_table.mutex, NULL);
	dns_cache_table.rb_root = RB_ROOT;
}

void dns_cache_table_free()
{
	struct dns_cache_t *dns_cache = NULL;
	struct rb_node *node = NULL;
	while ((node = rb_first(&dns_cache_table.rb_root))) {
		dns_cache = rb_entry(node, struct dns_cache_t, rb_node);
		dns_cache_table_erase(dns_cache);
		dns_cache_free(dns_cache);
	}
	pthread_mutex_destroy(&dns_cache_table.mutex);
	memset(&dns_cache_table, 0, sizeof(struct dns_cache_table_t));
}

static int dns_cache_table_lock()
{
	return pthread_mutex_lock(&dns_cache_table.mutex);
}

static int dns_cache_table_unlock()
{
	return pthread_mutex_unlock(&dns_cache_table.mutex);
}

static struct dns_cache_t* dns_cache_table_lookup(const void *key)
{
	struct rb_node *node = dns_cache_table.rb_root.rb_node;
	struct dns_cache_t *dns_cache = NULL;
	int cmp = 0;
	while (node)
	{   
		dns_cache = (struct dns_cache_t *)rb_entry(node, struct dns_cache_t, rb_node);
		cmp = strcmp(key, dns_cache->key);
		if (cmp < 0)
			node = node->rb_left;
		else if (cmp > 0)
			node = node->rb_right;
		else
			return dns_cache;
	} 
	return NULL;
};

static int dns_cache_table_insert(struct dns_cache_t *dns_cache)
{
	struct rb_node **p = &dns_cache_table.rb_root.rb_node;
	struct rb_node *parent = NULL;
	struct dns_cache_t *dns_cache_tmp = NULL;
	int cmp;
	while (*p)
	{   
		parent = *p; 
		dns_cache_tmp = rb_entry(parent, struct dns_cache_t, rb_node);
		cmp = strcmp(dns_cache->key, dns_cache_tmp->key);
		if (cmp < 0)
			p = &(*p)->rb_left;
		else if (cmp > 0)
			p = &(*p)->rb_right;
		else
			return -1; 
	}   
	rb_link_node(&dns_cache->rb_node, parent, p); 
	rb_insert_color(&dns_cache->rb_node, &dns_cache_table.rb_root);
	dns_cache_table.count--;
	return 0;
}

static int dns_cache_table_erase(struct dns_cache_t *dns_cache)
{
	rb_erase(&dns_cache->rb_node, &dns_cache_table.rb_root);
	dns_cache_table.count--;
	return 0;
}

static struct dns_cache_t* dns_cache_alloc(const char *key)
{
	struct dns_cache_t *dns_cache = NULL;
	dns_cache = http_malloc(sizeof(struct dns_cache_t));
	memset(dns_cache, 0, sizeof(struct dns_cache_t));
	dns_cache->key = http_strdup(key);
	return dns_cache;
}

static void dns_cache_free(struct dns_cache_t *dns_cache)
{
	http_free(dns_cache->key);
	dns_info_clean(&dns_cache->dns_info);
	http_free(dns_cache);
}

void dns_info_copy(struct dns_info_t *dest, const struct dns_info_t *src)
{
	dest->ipv4_num = src->ipv4_num;
	dest->ipv6_num = src->ipv6_num;
	dest->cname_num = src->cname_num;
	dest->ttl = src->ttl;
	dest->sin_addrs = NULL;
	if (dest->ipv4_num > 0) {
		dest->sin_addrs = http_malloc(dest->ipv4_num * sizeof(struct in_addr));
		memcpy(dest->sin_addrs, src->sin_addrs, dest->ipv4_num * sizeof(struct in_addr));
	}
	dest->sin6_addrs = NULL;
	if (dest->ipv6_num > 0) {
		dest->sin6_addrs = http_malloc(dest->ipv6_num * sizeof(struct in6_addr));
		memcpy(dest->sin6_addrs, src->sin6_addrs, dest->ipv6_num * sizeof(struct in6_addr));
	}
}

void dns_info_clean(struct dns_info_t *dns_info)
{
	if (dns_info->sin_addrs) {
		http_free(dns_info->sin_addrs);
	}
	if (dns_info->sin6_addrs) {
		http_free(dns_info->sin6_addrs);
	}
	memset(dns_info, 0, sizeof(struct dns_info_t));
}

static void dns_query_read(struct connection_t *connection)
{
	struct dns_session_t *dns_session = connection->arg;
	struct dns_query_t *dns_query = NULL;
	struct dns_query_t *dns_query_tmp = NULL;
	struct rfc1035_message_t *message = NULL;
	struct sockaddr peer_addr;
	char buf[1460];
	ssize_t nread = 0; 
	int n = 0;
	socklen_t socklen = sizeof(struct sockaddr);
	nread = recvfrom(connection->fd, buf, sizeof(buf), 0, &peer_addr, &socklen);
	if (nread <= 0) {
		if (nread == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			LOG(LOG_DEBUG, "%s fd=%d wait for read\n", dns_session->epoll_thread->name, connection->fd);
			connection_read_done(connection);
			connection_read_enable(connection, dns_query_read);
		} else {
			LOG(LOG_ERROR, "%s fd=%d nread=%d %s\n", dns_session->epoll_thread->name, connection->fd, nread, strerror(errno));
		}
		return;
	}
	n = rfc1035MessageUnpack(buf, nread, &message);
	if (message) {
		LOG(LOG_DEBUG, "%s fd=%d nread=%d dns tc=%d %s\n", dns_session->epoll_thread->name, connection->fd, nread, message->tc, rfc1035MessageErrno(-n));
		list_for_each_entry(dns_query_tmp, &dns_session->wait_list, node) {
			if (dns_query_tmp->id == message->id) {
				dns_query = dns_query_tmp;
				break;
			}
		}
		if (dns_query) {
			dns_query_parse_data(dns_query, message->answer, n);
		} else {
			LOG(LOG_WARNING, "%s fd=%d nread=%d dns late response\n", dns_session->epoll_thread->name, connection->fd, nread);
		}
		rfc1035MessageDestroy(message);
		dns_query_free(dns_query);
	} else {
		LOG(LOG_ERROR, "%s fd=%d nread=%d error dns response\n", dns_session->epoll_thread->name, connection->fd, nread);
	}
	connection_read_enable(connection, dns_query_read);
}

static void dns_query_write(struct connection_t *connection)
{
	struct dns_session_t *dns_session = connection->arg;
	struct dns_query_t *dns_query = NULL;
	ssize_t nwrite = 0; 
	socklen_t socklen = sizeof(struct sockaddr);
	dns_query = d_list_head(&dns_session->write_list, struct dns_query_t, node);
	nwrite = sendto(connection->fd, dns_query->buf, dns_query->buf_len, 0, &connection->peer_addr, socklen);
	if (nwrite <= 0) {
		if (nwrite == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			LOG(LOG_DEBUG, "%s fd=%d wait for send\n", dns_session->epoll_thread->name, connection->fd);
			connection_write_done(connection);
			connection_write_enable(connection, dns_query_write);
		} else {
			LOG(LOG_ERROR, "%s %s fd=%d nwrite=%d error:%s\n", dns_session->epoll_thread->name, dns_query->host, connection->fd, nwrite, strerror(errno));
		}
		return;
	}
	LOG(LOG_DEBUG, "%s %s fd=%d nwrite=%d\n", dns_session->epoll_thread->name, dns_query->host, connection->fd, nwrite);
	list_del(&dns_query->node);
	list_add_tail(&dns_query->node, &dns_session->wait_list);
	if (list_empty(&dns_session->write_list)) {
		connection_write_disable(connection);
	} else {
		connection_write_enable(connection, dns_query_write);
	}
}

static void dns_query_parse_data(struct dns_query_t *dns_query, struct rfc1035_rr_t *answers, int n)
{
	int i;
	int ipv4_num = 0;
	int ipv6_num = 0;
	int cname_num = 0;
	//char cname[256];
	int ttl = 0;
	char ip_str[64];
	struct continuation_t *continuation = NULL;
	struct dns_cache_t *dns_cache = NULL;
	for (i = 0; i < n; i++) {
		if (answers[i].class != RFC1035_CLASS_IN) {
			continue;
		}
		if (answers[i].type == RFC1035_TYPE_A) {
			if (answers[i].rdlength != sizeof(struct in_addr)) {
				continue;
			}
			ipv4_num++;
		}
		if (answers[i].type == RFC1035_TYPE_AAAA) {
			if (answers[i].rdlength != sizeof(struct in6_addr)) {
				continue;
			}
			ipv6_num++;
		}
		if (answers[i].type == RFC1035_TYPE_CNAME) {
			cname_num++;
		}
	}
	dns_query->dns_info.sin_addrs = http_malloc(ipv4_num * sizeof(struct in_addr));
	dns_query->dns_info.sin6_addrs = http_malloc(ipv6_num * sizeof(struct in6_addr));
	for (i = 0; i < n; i++) {
		if (answers[i].class != RFC1035_CLASS_IN) {
			continue;
		}
		if (answers[i].type == RFC1035_TYPE_A) {
			if (answers[i].rdlength != sizeof(struct in_addr)) {
				continue;
			}
			memcpy(&dns_query->dns_info.sin_addrs[dns_query->dns_info.ipv4_num], answers[i].rdata, sizeof(struct in_addr));
			inet_ntop(AF_INET, &dns_query->dns_info.sin_addrs[dns_query->dns_info.ipv4_num], ip_str, sizeof(ip_str));
			dns_query->dns_info.ipv4_num++;
			LOG(LOG_DEBUG, "ipv4=%s\n", ip_str);
		}
		if (answers[i].type == RFC1035_TYPE_AAAA) {
			if (answers[i].rdlength != sizeof(struct in6_addr)) {
				continue;
			}
			memcpy(&dns_query->dns_info.sin6_addrs[dns_query->dns_info.ipv6_num], answers[i].rdata, sizeof(struct in6_addr));
			inet_ntop(AF_INET6, &dns_query->dns_info.sin_addrs[dns_query->dns_info.ipv6_num], ip_str, sizeof(ip_str));
			dns_query->dns_info.ipv6_num++;
			LOG(LOG_DEBUG, "ipv6=%s\n", ip_str);
		}
		if (answers[i].type == RFC1035_TYPE_CNAME) {
			dns_query->dns_info.cname_num++;
			//strncpy(cname, answers[i].rdata, answers[i].rdlength);
			//LOG("cname=%s\n", cname);
		}
		LOG(LOG_DEBUG, "ttl=%d\n", answers[i].ttl);
		if (ttl == 0 || ttl > answers[i].ttl) {
			ttl = answers[i].ttl;
		}
	}
	dns_query->dns_info.ttl = MAX(ttl, 60);
	while (!list_empty(&dns_query->client_list)) {
		continuation = d_list_head(&dns_query->client_list, struct continuation_t, node);
		list_del(&continuation->node);
		dns_info_copy((struct dns_info_t *)continuation->buf, &dns_query->dns_info);
		continuation->callback(continuation->callback_data);
	}
	dns_cache_table_lock();
	dns_cache = dns_cache_table_lookup(dns_query->host);
	if (dns_cache == NULL) {
		dns_cache = dns_cache_alloc(dns_query->host);
		dns_cache_table_insert(dns_cache);
	} else {
		dns_info_clean(&dns_cache->dns_info);
	}
	dns_info_copy(&dns_cache->dns_info, &dns_query->dns_info);
	dns_cache_table_unlock();
}

struct dns_session_t* dns_session_create(struct epoll_thread_t *epoll_thread)
{
	struct connection_t *connection = NULL;
	struct dns_session_t *dns_session = NULL;
	int fd = -1;
	socklen_t addr_len = sizeof(struct sockaddr);
	fd = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP);
	if (fd < 0) {
		LOG(LOG_ERROR, "%s dns socket fd=%d error:%s\n", epoll_thread->name, fd, strerror(errno));
		assert(0);
		return NULL;
	}
	dns_session = http_malloc(sizeof(struct dns_session_t));
	memset(dns_session, 0, sizeof(struct dns_session_t));
	INIT_LIST_HEAD(&dns_session->write_list);
	INIT_LIST_HEAD(&dns_session->wait_list);

	connection = http_malloc(sizeof(struct connection_t));
	memset(connection, 0, sizeof(struct connection_t));
	connection->fd = fd;
	getsockname(connection->fd, &connection->local_addr, &addr_len);
	socket_non_block(connection->fd);
	((struct sockaddr_in *)&connection->peer_addr)->sin_family = AF_INET;
	((struct sockaddr_in *)&connection->peer_addr)->sin_port = htons(53);
	((struct sockaddr_in *)&connection->peer_addr)->sin_addr.s_addr = inet_addr("114.114.114.114");
	connection->arg = dns_session;
	connection->epoll_thread = epoll_thread;
	connection_read_enable(connection, dns_query_read);

	dns_session->epoll_thread = epoll_thread;
	dns_session->connection = connection;
	return dns_session;
}

void dns_session_query(struct dns_session_t *dns_session, const char *host, struct continuation_t *continuation)
{
	struct dns_query_t *dns_query = NULL;
	struct dns_cache_t *dns_cache = NULL;
	struct dns_info_t dns_info = {0};
	struct in_addr sin_addr;
	struct in6_addr sin6_addr;
	if (inet_pton(AF_INET, host, &sin_addr) > 0) {
		dns_info.ipv4_num = 1;
		dns_info.sin_addrs = &sin_addr;
		dns_info_copy((struct dns_info_t *)continuation->buf, &dns_info);
		continuation->callback(continuation->callback_data);
		return;
	}
	if (inet_pton(AF_INET6, host, &sin6_addr) > 0) {
		dns_info.ipv6_num = 1;
		dns_info.sin6_addrs = &sin6_addr;
		dns_info_copy((struct dns_info_t *)continuation->buf, &dns_info);
		continuation->callback(continuation->callback_data);
		return;
	}

	dns_cache_table_lock();
	dns_cache = dns_cache_table_lookup(host);
	if (dns_cache) {
		dns_info_copy((struct dns_info_t *)continuation->buf, &dns_cache->dns_info);
		dns_cache_table_unlock();
		continuation->callback(continuation->callback_data);
		return;
	}
	dns_cache_table_unlock();

	list_for_each_entry(dns_query, &dns_session->write_list, node) {
		if (strcmp(host, dns_query->host) == 0) {
			list_add_tail(&continuation->node, &dns_query->client_list);
			return;
		}
	}
	list_for_each_entry(dns_query, &dns_session->wait_list, node) {
		if (strcmp(host, dns_query->host) == 0) {
			list_add_tail(&continuation->node, &dns_query->client_list);
			return;
		}
	}
	dns_query_create(dns_session, host, continuation);
}

void dns_session_close(struct dns_session_t *dns_session)
{
	struct dns_query_t *dns_query = NULL;
	while (!list_empty(&dns_session->write_list)) {
		dns_query = d_list_head(&dns_session->write_list, struct dns_query_t, node);
		dns_query_free(dns_query);
	}
	while (!list_empty(&dns_session->wait_list)) {
		dns_query = d_list_head(&dns_session->wait_list, struct dns_query_t, node);
		dns_query_free(dns_query);
	}
	connection_close(dns_session->connection, CONNECTION_FREE_NOW);
	http_free(dns_session);
}

static void dns_query_create(struct dns_session_t *dns_session, const char *host, struct continuation_t *continuation)
{
	struct dns_query_t *dns_query = NULL;
	char *buf = NULL;
	int size = 1460;
	int off = 0;
	uint16_t s;
	uint16_t t;
	dns_query = http_malloc(sizeof(struct dns_query_t));
	memset(dns_query, 0, sizeof(struct dns_query_t));
	dns_query->host = http_strdup(host);
	dns_query->id = dns_session->id++;
	buf = dns_query->buf;

	s = htons(dns_query->id);
	memcpy(buf + off, &s, sizeof(s));
	off += sizeof(s);
	t = 0;
	t |= (0 << 15);//qr
	t |= (0 << 11);//opcode
	t |= (0 << 10);//aa
	t |= (0 << 9);//tc
	t |= (1 << 8);//rd
	t |= (0 << 7);//ra
	t |= 0;//rcode
	s = htons(t);
	memcpy(buf + off, &s, sizeof(s));
	off += sizeof(s);
	s = htons(1);//qdcount
	memcpy(buf + off, &s, sizeof(s));
	off += sizeof(s);
	s = htons(0);//ancount
	memcpy(buf + off, &s, sizeof(s));
	off += sizeof(s);
	s = htons(0);//nscount
	memcpy(buf + off, &s, sizeof(s));
	off += sizeof(s);
	s = htons(0);//arcount
	memcpy(buf + off, &s, sizeof(s));
	off += sizeof(s);
	off += rfc1035NamePack(buf + off, size - off, host);
	s = htons(RFC1035_TYPE_A);
	memcpy(buf + off, &s, sizeof(s));
	off += sizeof(s);
	s = htons(RFC1035_CLASS_IN);
	memcpy(buf + off, &s, sizeof(s));
	off += sizeof(s);

	dns_query->buf_len = off;
	INIT_LIST_HEAD(&dns_query->client_list);
	list_add_tail(&continuation->node, &dns_query->client_list);
	list_add_tail(&dns_query->node, &dns_session->write_list);
	connection_write_enable(dns_session->connection, dns_query_write);
}

static void dns_query_free(struct dns_query_t *dns_query)
{
	list_del(&dns_query->node);
	http_free(dns_query->host);
	dns_info_clean(&dns_query->dns_info);
	http_free(dns_query);
}

static int rfc1035NamePack(char *buf, size_t sz, const char *name)
{
	int off = 0;
	char *copy = http_strdup(name);
	char *t;
	char *saveptr = NULL;
	/*
	 * NOTE: use of strtok here makes names like foo....com valid.
	 */
	for (t = strtok_r(copy, ".", &saveptr); t; t = strtok_r(NULL, ".", &saveptr))
		off += rfc1035LabelPack(buf + off, sz - off, t);
	http_free(copy);
	off += rfc1035LabelPack(buf + off, sz - off, NULL);
	/* never happen */
	//assert(off <= sz);
	return off;
}

static int rfc1035LabelPack(char *buf, size_t sz, const char *label)
{
	int off = 0;
	size_t len = label ? strlen(label) : 0;
	if (label) {
		if (strchr(label, '.')) {
			return 0;
		}
	}
	if (len > RFC1035_MAXLABELSZ)
		len = RFC1035_MAXLABELSZ;
	if (sz < len + 1) {
		return 0;
	}
	*(buf + off) = (char) len;
	off++;
	memcpy(buf + off, label, len);
	off += len;
	return off;
}

static int rfc1035MessageUnpack(const char *buf, size_t sz, struct rfc1035_message_t **answer)
{
	int off = 0;
	int i;
	int nr = 0;
	struct rfc1035_message_t *msg;
	struct rfc1035_rr_t *recs;
	struct rfc1035_query_t *querys;
	msg = http_malloc(sizeof(struct rfc1035_message_t));
	memset(msg, 0, sizeof(struct rfc1035_message_t));
	if (rfc1035HeaderUnpack(buf + off, sz - off, &off, msg)) {
		http_free(msg);
		return -rfc1035_unpack_error;
	}
	i = (int) msg->qdcount;
	if (i != 1) {
		/* This can not be an answer to our queries.. */
		http_free(msg);
		return -rfc1035_unpack_error;
	}
	querys = msg->query = http_malloc((int)msg->qdcount * sizeof(struct rfc1035_query_t));
	memset(querys, 0, (int)msg->qdcount * sizeof(struct rfc1035_query_t));
	for (i = 0; i < (int) msg->qdcount; i++) {
		if (rfc1035QueryUnpack(buf, sz, &off, &querys[i])) {
			rfc1035MessageDestroy(msg);
			return -rfc1035_unpack_error;
		}
	}
	*answer = msg;
	if (msg->rcode) {
		return -(int) msg->rcode;
	}
	if (msg->ancount == 0)
		return 0;
	recs = msg->answer = http_malloc((int)msg->ancount * sizeof(struct rfc1035_rr_t));
	memset(recs, 0, (int)msg->ancount * sizeof(struct rfc1035_rr_t));
	for (i = 0; i < (int) msg->ancount; i++) {
		if (off >= sz) {		/* corrupt packet */
			break;
		}
		if (rfc1035RRUnpack(buf, sz, &off, &recs[i])) {	/* corrupt RR */
			break;
		}
		nr++;
	}
	if (nr == 0) {
		/*
		 * we expected to unpack some answers (ancount != 0), but
		 * didn't actually get any.
		 */
		rfc1035MessageDestroy(msg);
		*answer = NULL;
		return -rfc1035_unpack_error;
	}
	return nr;
}

static int rfc1035HeaderUnpack(const char *buf, size_t sz, int *off, struct rfc1035_message_t *h)
{
	unsigned short s;
	unsigned short t;
	if (*off) {
		return 1;
	}
	/*
	 * The header is 12 octets.  This is a bogus message if the size
	 * is less than that.
	 */
	if (sz < 12)
		return 1;
	memcpy(&s, buf + (*off), sizeof(s));
	(*off) += sizeof(s);
	h->id = ntohs(s);
	memcpy(&s, buf + (*off), sizeof(s));
	(*off) += sizeof(s);
	t = ntohs(s);
	h->qr = (t >> 15) & 0x01;
	h->opcode = (t >> 11) & 0x0F;
	h->aa = (t >> 10) & 0x01;
	h->tc = (t >> 9) & 0x01;
	h->rd = (t >> 8) & 0x01;
	h->ra = (t >> 7) & 0x01;
	/*
	 * We might want to check that the reserved 'Z' bits (6-4) are
	 * all zero as per RFC 1035.  If not the message should be
	 * rejected.
	 */
	h->rcode = t & 0x0F;
	memcpy(&s, buf + (*off), sizeof(s));
	(*off) += sizeof(s);
	h->qdcount = ntohs(s);
	memcpy(&s, buf + (*off), sizeof(s));
	(*off) += sizeof(s);
	h->ancount = ntohs(s);
	memcpy(&s, buf + (*off), sizeof(s));
	(*off) += sizeof(s);
	h->nscount = ntohs(s);
	memcpy(&s, buf + (*off), sizeof(s));
	(*off) += sizeof(s);
	h->arcount = ntohs(s);
	return 0;
}

static int rfc1035QueryUnpack(const char *buf, size_t sz, int *off, struct rfc1035_query_t *query)
{
	unsigned short s;
	if (rfc1035NameUnpack(buf, sz, off, NULL, query->name, RFC1035_MAXHOSTNAMESZ, 0)) {
		memset(query, '\0', sizeof(*query));
		return 1;
	}
	if (*off + 4 > sz) {
		memset(query, '\0', sizeof(*query));
		return 1;
	}
	memcpy(&s, buf + *off, 2);
	*off += 2;
	query->qtype = ntohs(s);
	memcpy(&s, buf + *off, 2);
	*off += 2;
	query->qclass = ntohs(s);
	return 0;
}

static int rfc1035RRUnpack(const char *buf, size_t sz, int *off, struct rfc1035_rr_t *RR)
{
	unsigned short s;
	unsigned int i;
	unsigned short rdlength;
	int rdata_off;
	if (rfc1035NameUnpack(buf, sz, off, NULL, RR->name, RFC1035_MAXHOSTNAMESZ, 0)) {
		memset(RR, '\0', sizeof(*RR));
		return 1;
	}
	/*
	 * Make sure the remaining message has enough octets for the
	 * rest of the RR fields.
	 */
	if ((*off) + 10 > sz) {
		memset(RR, '\0', sizeof(*RR));
		return 1;
	}
	memcpy(&s, buf + (*off), sizeof(s));
	(*off) += sizeof(s);
	RR->type = ntohs(s);
	memcpy(&s, buf + (*off), sizeof(s));
	(*off) += sizeof(s);
	RR->class = ntohs(s);
	memcpy(&i, buf + (*off), sizeof(i));
	(*off) += sizeof(i);
	RR->ttl = ntohl(i);
	memcpy(&s, buf + (*off), sizeof(s));
	(*off) += sizeof(s);
	rdlength = ntohs(s);
	if ((*off) + rdlength > sz) {
		/*
		 * We got a truncated packet.  'dnscache' truncates UDP
		 * replies at 512 octets, as per RFC 1035.
		 */
		memset(RR, '\0', sizeof(*RR));
		return 1;
	}
	RR->rdlength = rdlength;
	switch (RR->type) {
		case RFC1035_TYPE_PTR:
			RR->rdata = http_malloc(RFC1035_MAXHOSTNAMESZ);
			rdata_off = *off;
			RR->rdlength = 0;		/* Filled in by rfc1035NameUnpack */
			if (rfc1035NameUnpack(buf, sz, &rdata_off, &RR->rdlength, RR->rdata, RFC1035_MAXHOSTNAMESZ, 0))
				return 1;
			if (rdata_off > ((*off) + rdlength)) {
				/*
				 * This probably doesn't happen for valid packets, but
				 * I want to make sure that NameUnpack doesn't go beyond
				 * the RDATA area.
				 */
				http_free(RR->rdata);
				memset(RR, '\0', sizeof(*RR));
				return 1;
			}
			break;
		case RFC1035_TYPE_A:
		default:
			RR->rdata = http_malloc(rdlength);
			memcpy(RR->rdata, buf + (*off), rdlength);
			break;
	}
	(*off) += rdlength;
	if ((*off) > sz) {
		return 1;
	}
	return 0;
}

static int rfc1035NameUnpack(const char *buf, size_t sz, int *off, unsigned short *rdlength, char *name, size_t ns, int rdepth)
{
	int no = 0;
	unsigned char c;
	size_t len;
	if (ns <= 0) {
		return 1;
	}
	do {
		if ((*off) >= sz) {
			return 1;
		}
		c = *(buf + (*off));
		if (c > 191) {
			/* blasted compression */
			unsigned short s;
			int ptr;
			if (rdepth > 64)	/* infinite pointer loop */
				return 1;
			memcpy(&s, buf + (*off), sizeof(s));
			s = ntohs(s);
			(*off) += sizeof(s);
			/* Sanity check */
			if ((*off) >= sz)
				return 1;
			ptr = s & 0x3FFF;
			/* Make sure the pointer is inside this message */
			if (ptr >= sz)
				return 1;
			return rfc1035NameUnpack(buf, sz, &ptr, rdlength, name + no, ns - no, rdepth + 1);
		} else if (c > RFC1035_MAXLABELSZ) {
			/*
			 * "(The 10 and 01 combinations are reserved for future use.)"
			 */
			return 1;
		} else {
			(*off)++;
			len = (size_t) c;
			if (len == 0)
				break;
			if (len > (ns - no - 1))	/* label won't fit */
				return 1;
			if ((*off) + len >= sz)	/* message is too short */
				return 1;
			memcpy(name + no, buf + (*off), len);
			(*off) += len;
			no += len;
			*(name + (no++)) = '.';
			if (rdlength)
				*rdlength += len + 1;
		}
	} while (c > 0 && no < ns);
	if (no)
		*(name + no - 1) = '\0';
	else
		*name = '\0';
	/* make sure we didn't allow someone to overflow the name buffer */
	/* never happen, no has been judged before copy */
	//assert(no <= ns);
	return 0;
}

static void rfc1035RRDestroy(struct rfc1035_rr_t * rr, int n)
{
	if (rr == NULL)
		return;
	if (n > 0) {
		while (n--) {
			if (rr[n].rdata)
				http_free(rr[n].rdata);
		}
	}
	http_free(rr);
}

static void rfc1035MessageDestroy(struct rfc1035_message_t *msg)
{
	if (!msg)
		return;
	if (msg->query)
		http_free(msg->query);
	if (msg->answer)
		rfc1035RRDestroy(msg->answer, msg->ancount);
	http_free(msg);
}

#if 0
static int rfc1035QueryCompare(const struct rfc1035_query_t *a, const struct rfc1035_query_t *b)
{
	size_t la, lb;
	if (a->qtype != b->qtype)
		return 1;
	if (a->qclass != b->qclass)
		return 1;
	la = strlen(a->name);
	lb = strlen(b->name);
	if (la != lb) {
		/* Trim root label(s) */
		while (la > 0 && a->name[la - 1] == '.')
			la--;
		while (lb > 0 && b->name[lb - 1] == '.')
			lb--;
	}
	if (la != lb)
		return 1;

	return strncasecmp(a->name, b->name, la);
}
#endif 

static const char* rfc1035MessageErrno(int rfc1035_errno)
{
	char *rfc1035_error_message = NULL;
	switch (rfc1035_errno) {
		case 0:
			rfc1035_error_message = "No error condition";
			break;
		case 1:
			rfc1035_error_message = "Format Error: The name server was " "unable to interpret the query.";
			break;
		case 2:
			rfc1035_error_message = "Server Failure: The name server was " "unable to process this query.";
			break;
		case 3:
			rfc1035_error_message = "Name Error: The domain name does " "not exist.";
			break;
		case 4:
			rfc1035_error_message = "Not Implemented: The name server does " "not support the requested kind of query.";
			break;
		case 5:
			rfc1035_error_message = "Refused: The name server refuses to " "perform the specified operation.";
			break;
		case rfc1035_unpack_error:
			rfc1035_error_message = "The DNS reply message is corrupt or could " "not be safely parsed.";
			break;
		default:
			rfc1035_error_message = "Unknown Error";
			break;
	}
	return rfc1035_error_message;
}
