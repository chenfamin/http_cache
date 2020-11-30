#include "http.h"
#include "http_log.h"
#include "http_header.h"

#define ISDIGIT(c)           ((c) >= '0' && (c) <= '9')

const char *http_reasons[] = {
	"100 Continue",
	"101 Switching Protocols",
	"200 OK",
	"201 Created",
	"202 Accepted",
	"203 Non-Authoritative Information",
	"204 No Content",
	"205 Reset Content",
	"206 Partial Content",
	"226 IM Used",
	"300 Multiple Choices",
	"301 Moved Permanently",
	"302 Moved Temporarily",
	"303 See Other",
	"304 Not Modified",
	"305 Use Proxy",
	"307 Temporary Redirect",
	"400 Bad Request",
	"401 Unauthorized",
	"402 Payment Required",
	"403 Forbidden",
	"404 Not Found",
	"405 Method Not Allowed",
	"406 Not Acceptable",
	"407 Proxy Authentication Required",
	"408 Request Time-out",
	"409 Conflict",
	"410 Gone",
	"411 Length Required",
	"412 Precondition Failed",
	"413 Request Entity Too Large",
	"414 Request-URI Too Large",
	"415 Unsupported Media Type",
	"416 Requested Range Not Satisfiable",
	"417 Expectation failed",
	"500 Internal Server Error",
	"501 Not Implemented",
	"502 Bad Gateway",
	"503 Service Unavailable",
	"504 Gateway Time-out",
	"505 HTTP Version not supported"
};

static int skip_lws(const char *string);

const char* http_status_reasons_get(int status_code)
{
	unsigned int i;
	for(i = 0; i < sizeof(http_reasons)/sizeof(const char*); i++) {
		if (atoi(http_reasons[i]) == status_code) {
			return http_reasons[i];
		}
	}
	return "Unknown";
}


void http_header_init(struct http_header_t *header)
{
	INIT_LIST_HEAD(&header->header_list);
}

void http_header_clean(struct http_header_t *header)
{
	struct http_header_entry_t *header_entry;
	while (!list_empty(&header->header_list)) {
		header_entry = d_list_head(&header->header_list, struct http_header_entry_t, header_entry_node);
		list_del(&header_entry->header_entry_node);
		string_clean(&header_entry->field_string);
		string_clean(&header_entry->value_string);
		http_free(header_entry);
	}
	INIT_LIST_HEAD(&header->header_list);
}

void http_header_add(struct http_header_t *header, const char *field, const char *value)
{
	struct http_header_entry_t *header_entry;
	header_entry = http_malloc(sizeof(struct http_header_entry_t));
	string_init_str(&header_entry->field_string, field);
	string_init_str(&header_entry->value_string, value);
	list_add_tail(&header_entry->header_entry_node, &header->header_list);
}

void http_header_replace(struct http_header_t *header, const char *field, const char *value)
{
	int found = 0;
	struct http_header_entry_t *header_entry;
	list_for_each_entry(header_entry, &header->header_list, header_entry_node) {
		if (strcasecmp(string_buf(&header_entry->field_string), field) == 0) {
			found = 1;
			string_clean(&header_entry->value_string);
			string_init_str(&header_entry->value_string, value);
		}
	}
	if (found == 0) {
		http_header_add(header, field, value);
	}
}

void http_header_add_entry(struct http_header_t *header, struct http_header_entry_t *header_entry)
{
	list_add_tail(&header_entry->header_entry_node, &header->header_list);
}

void http_header_copy(struct http_header_t *header_dest, struct http_header_t *header_src)
{
	struct http_header_entry_t *header_entry;
	list_for_each_entry(header_entry, &header_src->header_list, header_entry_node) {
		http_header_add(header_dest, string_buf(&header_entry->field_string), string_buf(&header_entry->value_string));
	}
}

void http_header_del(struct http_header_t *header, const char *field)
{
	struct http_header_entry_t *header_entry;
	struct http_header_entry_t *header_entry_tmp;
	list_for_each_entry_safe(header_entry, header_entry_tmp, &header->header_list, header_entry_node) {
		if (strcasecmp(string_buf(&header_entry->field_string), field) == 0) {
			list_del(&header_entry->header_entry_node);
			string_clean(&header_entry->field_string);
			string_clean(&header_entry->value_string);
			http_free(header_entry);
		}
	}
}

const char* http_header_find(struct http_header_t *header, const char *field)
{
	struct http_header_entry_t *header_entry;
	list_for_each_entry(header_entry, &header->header_list, header_entry_node) {
		if (strcasecmp(string_buf(&header_entry->field_string), field) == 0) {
			return string_buf(&header_entry->value_string);
		}
	}
	return NULL;
}

const struct string_t* http_header_find_string(struct http_header_t *header, const char *field)
{
	struct http_header_entry_t *header_entry;
	list_for_each_entry(header_entry, &header->header_list, header_entry_node) {
		if (strcasecmp(string_buf(&header_entry->field_string), field) == 0) {
			return &header_entry->value_string;
		}
	}
	return NULL;
}

struct http_header_entry_t* http_header_entry_tail(struct http_header_t *header)
{
	return d_list_tail(&header->header_list, struct http_header_entry_t, header_entry_node);
}

int parse_string_to_value(const char *str)
{
	while (*str && *str == ' ') str++;
	if (*str == '=') {
		str++;
		return atoi(str);
	} else {
		return -1;
	}
}

struct http_cache_control_t* http_cache_control_parse(const char *hdr)
{
	struct http_cache_control_t *cache_control = NULL;
	char *str = http_strdup(hdr);
	char *pos = str;
	char *result;
	cache_control = http_malloc(sizeof(struct http_cache_control_t));
	memset(cache_control, 0, sizeof(struct http_cache_control_t));
	while (pos) {
		result = strsep(&pos, ",");
		if (result) {
			while (*result && *result == ' ') result++;
			if (strncmp(result, "public", sizeof("public") - 1) == 0) {
				bit_set(cache_control->mask, CACHE_CONTROL_PUBLIC);
			} else if (strncmp(result, "private", sizeof("private") - 1) == 0) {
				bit_set(cache_control->mask, CACHE_CONTROL_PRIVATE);
			} else if (strncmp(result, "no-cache", sizeof("no-cache") - 1) == 0) {
				bit_set(cache_control->mask, CACHE_CONTROL_NO_CACHE);
			} else if (strncmp(result, "no-store", sizeof("no-store") - 1) == 0) {
				bit_set(cache_control->mask, CACHE_CONTROL_NO_STORE);
			} else if (strncmp(result, "no-transform", sizeof("no-transform") - 1) == 0) {
				bit_set(cache_control->mask, CACHE_CONTROL_NO_TRANSFORM);
			} else if (strncmp(result, "must-revalidate", sizeof("must-revalidate") - 1) == 0) {
				bit_set(cache_control->mask, CACHE_CONTROL_MUST_REVALIDATE);
			} else if (strncmp(result, "proxy-revalidate", sizeof("proxy-revalidate") - 1) == 0) {
				bit_set(cache_control->mask, CACHE_CONTROL_PROXY_REVALIDATE);
			} else if (strncmp(result, "max-age", sizeof("max-age") - 1) == 0) {
				bit_set(cache_control->mask, CACHE_CONTROL_MAX_AGE);
				cache_control->max_age = parse_string_to_value(result + sizeof("max-age") - 1);
			} else if (strncmp(result, "s-maxage", sizeof("s-maxage") - 1) == 0) {
				bit_set(cache_control->mask, CACHE_CONTROL_S_MAXAGE);
				cache_control->s_maxage = parse_string_to_value(result + sizeof("s-maxage") - 1);
			} else if (strncmp(result, "max-stale", sizeof("max-stale") - 1) == 0) {
				bit_set(cache_control->mask, CACHE_CONTROL_MAX_STALE);
				cache_control->max_stale = parse_string_to_value(result + sizeof("max-stale") - 1);
			} else if (strncmp(result, "min-fresh", sizeof("min-fresh") - 1) == 0) {
				bit_set(cache_control->mask, CACHE_CONTROL_MIN_FRESH);
				cache_control->min_fresh = parse_string_to_value(result + sizeof("min-fresh") - 1);
			} else if (strncmp(result, "only-if-cached", sizeof("only-if-cached") - 1) == 0) {
				bit_set(cache_control->mask, CACHE_CONTROL_ONLY_IF_CACHED);
			}
		}
	}
	http_free(str);
	return cache_control;
}

int64_t http_parse_time(const char *hdr, size_t len)
{
	const char      *p, *end;
	int32_t    month = 0;
	uint32_t   day = 0, year = 0, hour = 0, min = 0, sec = 0;
	uint64_t     time;
	static uint32_t  mday[] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
	enum {
		no = 0,
		rfc822,   /* Tue, 10 Nov 2002 23:50:13   */
		rfc850,   /* Tuesday, 10-Dec-02 23:50:13 */
		isoc      /* Tue Dec 10 23:50:13 2002    */
	} fmt;

	fmt = 0;
	end = hdr + len;

	for (p = hdr; p < end; p++) {
		if (*p == ',') {
			break;
		}

		if (*p == ' ') {
			fmt = isoc;
			break;
		}
	}

	for (p++; p < end; p++)
		if (*p != ' ') {
			break;
		}

	if (end - p < 18) {
		return -1;
	}

	if (fmt != isoc) {
		if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9') {
			return -1;
		}

		day = (*p - '0') * 10 + *(p + 1) - '0';
		p += 2;

		if (*p == ' ') {
			if (end - p < 18) {
				return -1;
			}
			fmt = rfc822;

		} else if (*p == '-') {
			fmt = rfc850;

		} else {
			return -1;
		}

		p++;
	}

	switch (*p) {

		case 'J':
			month = *(p + 1) == 'a' ? 0 : *(p + 2) == 'n' ? 5 : 6;
			break;

		case 'F':
			month = 1;
			break;

		case 'M':
			month = *(p + 2) == 'r' ? 2 : 4;
			break;

		case 'A':
			month = *(p + 1) == 'p' ? 3 : 7;
			break;

		case 'S':
			month = 8;
			break;

		case 'O':
			month = 9;
			break;

		case 'N':
			month = 10;
			break;

		case 'D':
			month = 11;
			break;

		default:
			return -1;
	}

	p += 3;

	if ((fmt == rfc822 && *p != ' ') || (fmt == rfc850 && *p != '-')) {
		return -1;
	}

	p++;

	if (fmt == rfc822) {
		if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9'
				|| *(p + 2) < '0' || *(p + 2) > '9'
				|| *(p + 3) < '0' || *(p + 3) > '9')
		{
			return -1;
		}

		year = (*p - '0') * 1000 + (*(p + 1) - '0') * 100
			+ (*(p + 2) - '0') * 10 + *(p + 3) - '0';
		p += 4;

	} else if (fmt == rfc850) {
		if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9') {
			return -1;
		}

		year = (*p - '0') * 10 + *(p + 1) - '0';
		year += (year < 70) ? 2000 : 1900;
		p += 2;
	}

	if (fmt == isoc) {
		if (*p == ' ') {
			p++;
		}

		if (*p < '0' || *p > '9') {
			return -1;
		}

		day = *p++ - '0';

		if (*p != ' ') {
			if (*p < '0' || *p > '9') {
				return -1;
			}

			day = day * 10 + *p++ - '0';
		}

		if (end - p < 14) {
			return -1;
		}
	}

	if (*p++ != ' ') {
		return -1;
	}

	if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9') {
		return -1;
	}

	hour = (*p - '0') * 10 + *(p + 1) - '0';
	p += 2;

	if (*p++ != ':') {
		return -1;
	}

	if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9') {
		return -1;
	}

	min = (*p - '0') * 10 + *(p + 1) - '0';
	p += 2;

	if (*p++ != ':') {
		return -1;
	}

	if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9') {
		return -1;
	}

	sec = (*p - '0') * 10 + *(p + 1) - '0';

	if (fmt == isoc) {
		p += 2;

		if (*p++ != ' ') {
			return -1;
		}

		if (*p < '0' || *p > '9' || *(p + 1) < '0' || *(p + 1) > '9'
				|| *(p + 2) < '0' || *(p + 2) > '9'
				|| *(p + 3) < '0' || *(p + 3) > '9')
		{
			return -1;
		}

		year = (*p - '0') * 1000 + (*(p + 1) - '0') * 100
			+ (*(p + 2) - '0') * 10 + *(p + 3) - '0';
	}

	if (hour > 23 || min > 59 || sec > 59) {
		return -1;
	}

	if (day == 29 && month == 1) {
		if ((year & 3) || ((year % 100 == 0) && (year % 400) != 0)) {
			return -1;
		}

	} else if (day > mday[month]) {
		return -1;
	}

	/*
	 * shift new year to March 1 and start months from 1 (not 0),
	 * it is needed for Gauss' formula
	 */

	if (--month <= 0) {
		month += 12;
		year -= 1;
	}

	/* Gauss' formula for Gregorian days since March 1, 1 BC */

	time = (uint64_t) (
			/* days in years including leap years since March 1, 1 BC */

			365 * year + year / 4 - year / 100 + year / 400

			/* days before the month */

			+ 367 * month / 12 - 30

			/* days before the day */

			+ day - 1

			/*
			 * 719527 days were between March 1, 1 BC and March 1, 1970,
			 * 31 and 28 days were in January and February 1970
			 */

			- 719527 + 31 + 28) * 86400 + hour * 3600 + min * 60 + sec;

	return time;
}

static int skip_lws(const char *string)
{
	const char *p = string;

	while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
		++p;
	return p - string;
}

struct http_content_range_t* http_content_range_parse(const char *hdr)
{
	int64_t num;
	int64_t first_byte_pos = -1;
	int64_t last_byte_pos = -1;
	int64_t entity_length = -1;
	struct http_content_range_t* content_range = NULL;
	/* Certain versions of Nutscape proxy server send out
	   `Content-Length' without "bytes" specifier, which is a breach of
	   RFC2068 (as well as the HTTP/1.1 draft which was current at the
	   time).  But hell, I must support it...  */
	if (!strncasecmp (hdr, "bytes", 5))
	{
		hdr += 5;
		hdr += skip_lws (hdr);
		if (!*hdr)
			return NULL;
	}
	if (!ISDIGIT (*hdr))
		return 0;
	for (num = 0; ISDIGIT (*hdr); hdr++)
		num = 10 * num + (*hdr - '0');
	if (*hdr != '-' || !ISDIGIT (*(hdr + 1)))
		return NULL;
	first_byte_pos = num;
	++hdr;
	for (num = 0; ISDIGIT (*hdr); hdr++)
		num = 10 * num + (*hdr - '0');
	if (*hdr != '/' || !ISDIGIT (*(hdr + 1)))
		return NULL;
	last_byte_pos = num;
	++hdr;
	for (num = 0; ISDIGIT (*hdr); hdr++)
		num = 10 * num + (*hdr - '0');
	entity_length = num;

	if (last_byte_pos - first_byte_pos + 1 > entity_length) {
		return NULL;
	}
	content_range = http_malloc(sizeof(struct http_content_range_t));
	content_range->start = first_byte_pos;
	content_range->end = last_byte_pos;
	content_range->entity_length = entity_length;
	return content_range;
}

struct http_range_t* http_range_parse(const char *field, int flen)
{
	struct http_range_t *http_range = NULL;
	int64_t offset = -1;
	int64_t length = -1;
	int64_t last_pos;
	const char *p = NULL;
	char *end = NULL;
	if (strncasecmp(field, "bytes=", 6) == 0) {
		field += 6;
		flen -= 6;
	} else {
		return NULL;
	}
	if (flen < 2) {
		return NULL;
	}
	if (*field == '-') {
		p = field + 1;
		length = strtoll(p, &end, 10);
		if (p == end) {
			return NULL;
		}
	} else if (!((p = strchr(field, '-')) || (p - field >= flen))) {
		LOG(LOG_ERROR, "ignoring invalid (missing '-') range-spec near: '%s'\n", field);
		return NULL;
	} else {
		offset = strtoll(field, &end, 10);
		if (field == end) {
			return NULL;
		}
		p++;
		if (p - field < flen) {
			last_pos = strtoll(p, &end, 10);
			if (p == end || offset > last_pos) {
				return NULL;
			}
			length = last_pos + 1 - offset;
		}
	}
	http_range = http_malloc(sizeof(struct http_range_t));
	http_range->offset = offset;
	http_range->length = length;
	return http_range;
}

int http_parse_chunked(const char *buf, size_t buf_len, size_t *buf_pos, struct http_chunked_t *ctx)
{
	const char *pos;
	char ch, c;
	int   rc;
	*buf_pos = 0;
	enum {
		sw_chunk_start = 0,
		sw_chunk_size,
		sw_chunk_extension,
		sw_chunk_extension_almost_done,
		sw_chunk_data,
		sw_after_data,
		sw_after_data_almost_done,
		sw_last_chunk_extension,
		sw_last_chunk_extension_almost_done,
		sw_trailer,
		sw_trailer_almost_done,
		sw_trailer_header,
		sw_trailer_header_almost_done
	} state;

	state = ctx->state;

	if (state == sw_chunk_data && ctx->size == 0) {
		state = sw_after_data;
	}

	rc = HTTP_AGAIN;

	for (pos = buf; pos < buf + buf_len; pos++) {

		ch = *pos;

		//LOG("http chunked byte: %02Xd s:%d\n", ch, state);

		switch (state) {

			case sw_chunk_start:
				if (ch >= '0' && ch <= '9') {
					state = sw_chunk_size;
					ctx->size = ch - '0';
					break;
				}

				c = ch | 0x20;

				if (c >= 'a' && c <= 'f') {
					state = sw_chunk_size;
					ctx->size = c - 'a' + 10;
					break;
				}

				goto invalid;

			case sw_chunk_size:
				if (ctx->size > HTTP_MAX_OFF_T_VALUE / 16) {
					goto invalid;
				}

				if (ch >= '0' && ch <= '9') {
					ctx->size = ctx->size * 16 + (ch - '0');
					break;
				}

				c = ch | 0x20;

				if (c >= 'a' && c <= 'f') {
					ctx->size = ctx->size * 16 + (c - 'a' + 10);
					break;
				}

				if (ctx->size == 0) {

					switch (ch) {
						case CR:
							state = sw_last_chunk_extension_almost_done;
							break;
						case LF:
							state = sw_trailer;
							break;
						case ';':
						case ' ':
						case '\t':
							state = sw_last_chunk_extension;
							break;
						default:
							goto invalid;
					}

					break;
				}

				switch (ch) {
					case CR:
						state = sw_chunk_extension_almost_done;
						break;
					case LF:
						state = sw_chunk_data;
						break;
					case ';':
					case ' ':
					case '\t':
						state = sw_chunk_extension;
						break;
					default:
						goto invalid;
				}

				break;

			case sw_chunk_extension:
				switch (ch) {
					case CR:
						state = sw_chunk_extension_almost_done;
						break;
					case LF:
						state = sw_chunk_data;
				}
				break;

			case sw_chunk_extension_almost_done:
				if (ch == LF) {
					state = sw_chunk_data;
					break;
				}
				goto invalid;

			case sw_chunk_data:
				rc = HTTP_OK;
				goto data;

			case sw_after_data:
				switch (ch) {
					case CR:
						state = sw_after_data_almost_done;
						break;
					case LF:
						state = sw_chunk_start;
				}
				break;

			case sw_after_data_almost_done:
				if (ch == LF) {
					state = sw_chunk_start;
					break;
				}
				goto invalid;

			case sw_last_chunk_extension:
				switch (ch) {
					case CR:
						state = sw_last_chunk_extension_almost_done;
						break;
					case LF:
						state = sw_trailer;
				}
				break;

			case sw_last_chunk_extension_almost_done:
				if (ch == LF) {
					state = sw_trailer;
					break;
				}
				goto invalid;

			case sw_trailer:
				switch (ch) {
					case CR:
						state = sw_trailer_almost_done;
						break;
					case LF:
						goto done;
					default:
						state = sw_trailer_header;
				}
				break;

			case sw_trailer_almost_done:
				if (ch == LF) {
					goto done;
				}
				goto invalid;

			case sw_trailer_header:
				switch (ch) {
					case CR:
						state = sw_trailer_header_almost_done;
						break;
					case LF:
						state = sw_trailer;
				}
				break;

			case sw_trailer_header_almost_done:
				if (ch == LF) {
					state = sw_trailer;
					break;
				}
				goto invalid;

		}
	}

data:

	ctx->state = state;
	*buf_pos = pos - buf;

	if (ctx->size > HTTP_MAX_OFF_T_VALUE - 5) {
		goto invalid;
	}

	switch (state) {

		case sw_chunk_start:
			ctx->length = 3 /* "0" LF LF */;
			break;
		case sw_chunk_size:
			ctx->length = 1 /* LF */
				+ (ctx->size ? ctx->size + 4 /* LF "0" LF LF */
						: 1 /* LF */);
			break;
		case sw_chunk_extension:
		case sw_chunk_extension_almost_done:
			ctx->length = 1 /* LF */ + ctx->size + 4 /* LF "0" LF LF */;
			break;
		case sw_chunk_data:
			ctx->length = ctx->size + 4 /* LF "0" LF LF */;
			break;
		case sw_after_data:
		case sw_after_data_almost_done:
			ctx->length = 4 /* LF "0" LF LF */;
			break;
		case sw_last_chunk_extension:
		case sw_last_chunk_extension_almost_done:
			ctx->length = 2 /* LF LF */;
			break;
		case sw_trailer:
		case sw_trailer_almost_done:
			ctx->length = 1 /* LF */;
			break;
		case sw_trailer_header:
		case sw_trailer_header_almost_done:
			ctx->length = 2 /* LF LF */;
			break;

	}

	return rc;

done:

	ctx->state = 0;
	*buf_pos = pos - buf + 1;

	return HTTP_DONE;

invalid:

	return HTTP_ERROR;
}
