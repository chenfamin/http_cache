#include <stdio.h>
#include <stdint.h>
#include <time.h>
struct cache_index_t {
	unsigned char key[16];//放第一项，方便匹配
	int64_t file_number;//目录和文件编号，可以转换目录和文件名
	time_t create_time;
	time_t lastref_time;
	int64_t file_size;//缓存文件大小，chunked未完整前记录-1，有cl的记录cl
	int header_size;// cache头部大小
	uint32_t flags;//缓存标志，是否缓存完整，是否永久缓存都用此标志
	unsigned char url[256];//放最后一项，未使用完的字符可以做其他用途,长度不够截短
};

struct cache_header_t {
	unsigned char key[16];
	int url_size;
	char url[url_size];
	int http_header_size;
	char http_header[http_header_size];
};

struct cache_t {
	unsigned char key[16];//放第一项，方便匹配
	int64_t file_number;//目录和文件编号，可以转换目录和文件名
	time_t create_time;
	time_t lastref_time;
	int ref_count;//访问次数
	int64_t file_size;//缓存文件大小，chunked未完整前记录-1，有cl的记录cl
	int header_size;// cache头部大小
	uint32_t flags;//缓存标志，是否缓存完整，是否永久缓存都用此标志
	char *url;

	void *reply_header;//保存解析后的响应头等信息
	void *mem_obj;//内存缓存相关
	void *io_stat;// io 打开 读写 关闭等
	void *lru;//lru链表 区分普通缓存和永久缓存

};

int main()
{
	printf("size=%d\n", sizeof(struct cache_index_t));
	return 0;
}

