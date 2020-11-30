#ifndef HTTP_HEADER_H
#define HTTP_HEADER_H

#include "http.h"
#include "http_parser.h"

#define bit_set(mask, bit) ((void)((mask) |= ((1L<<(bit)))))
#define bit_test(mask, bit) ((mask) & ((1L<<(bit))))

#define HTTP_MAX_OFF_T_VALUE 0x0fffffff

#define LF     (uint8_t) '\n'
#define CR     (uint8_t) '\r'
#define CRLF   "\r\n"

#define  HTTP_OK          0
#define  HTTP_ERROR      -1
#define  HTTP_AGAIN      -2
#define  HTTP_BUSY       -3
#define  HTTP_DONE       -4
#define  HTTP_DECLINED   -5
#define  HTTP_ABORT      -6

enum parser_header_state {
	PARSER_HEADER_NONE,
	PARSER_HEADER_FIELD,
	PARSER_HEADER_VALUE,
	PARSER_HEADER_DONE,
	PARSER_BODY,
	PARSER_DONE,
};

enum http_cache_control_type_t {
	CACHE_CONTROL_PUBLIC,
	CACHE_CONTROL_PRIVATE,
	CACHE_CONTROL_NO_CACHE,
	CACHE_CONTROL_NO_STORE,
	CACHE_CONTROL_NO_TRANSFORM,
	CACHE_CONTROL_MUST_REVALIDATE,
	CACHE_CONTROL_PROXY_REVALIDATE,
	CACHE_CONTROL_MAX_AGE,
	CACHE_CONTROL_S_MAXAGE,
	CACHE_CONTROL_MAX_STALE,
	CACHE_CONTROL_MIN_FRESH,
	CACHE_CONTROL_ONLY_IF_CACHED,
	CACHE_CONTROL_OTHER
};

struct http_header_entry_t {
	struct string_t field_string;
	struct string_t value_string;
	struct list_head_t header_entry_node;
};

struct http_header_t {
	struct list_head_t header_list;
};

struct http_range_t {
	int64_t offset;
	int64_t length;
};

struct http_content_range_t {
	int64_t start;
	int64_t end;
	int64_t entity_length;
};

struct http_cache_control_t {
	int mask;

	int max_stale;
	int min_fresh;

	int max_age;
	int s_maxage;
};

struct http_chunked_t {
	uint32_t state;
	int64_t  size;
	int64_t  length;
};

const char* http_status_reasons_get(int status_code);

void http_header_init(struct http_header_t *header);
void http_header_clean(struct http_header_t *header);
void http_header_add(struct http_header_t *header, const char *field, const char *value);
void http_header_replace(struct http_header_t *header, const char *field, const char *value);
void http_header_add_entry(struct http_header_t *header, struct http_header_entry_t *header_entry);
void http_header_copy(struct http_header_t *header_dest, struct http_header_t *header_src);
void http_header_del(struct http_header_t *header, const char *field);
const char* http_header_find(struct http_header_t *header, const char *field);
const struct string_t* http_header_find_string(struct http_header_t *header, const char *field);
struct http_header_entry_t* http_header_entry_tail(struct http_header_t *header);

struct http_cache_control_t* http_cache_control_parse(const char *hdr);
int64_t http_parse_time(const char *hdr, size_t len);
struct http_content_range_t* http_content_range_parse(const char *hdr);
struct http_range_t* http_range_parse(const char *field, int flen);
int http_parse_chunked(const char *buf, size_t buf_len, size_t *buf_pos, struct http_chunked_t *ctx);
#endif
