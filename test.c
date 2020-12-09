#include <stdio.h>
#include <stdint.h>
#include <time.h>
/*
   1 如果纯粹内存索引，即启动的时候将缓存索引全部读到内存中，那么以file_number * sizeof(struct cache_index_t)计算位置
   2 如果以btree- 和 key作为磁盘索引，那么可以不一次将索引信息都加载到内存，每次内存查找不到需要做磁盘查找，性能较低，复杂度较高
     
*/

struct cache_index_t {
	unsigned char key[16];//放第一项，方便匹配
	int64_t file_number;//目录和文件编号，可以转换目录和文件名
	time_t create_time;
	time_t lastref_time;
	int64_t file_size;//缓存文件大小，chunked未完整前记录-1，有cl的记录cl
	int header_size;// cache头部大小
	uint32_t flags;//缓存标志，是否缓存完整，是否永久缓存都用此标志
	unsigned char url[256];//放最后一项，未使用完的字符可以做其他用途,长度不够截短
	int64 expand;//扩展选项，可选
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
	char *url;//完整url

	void *reply_header;//保存解析后的响应头等信息
	void *mem_obj;//内存缓存相关，包含分段缓存的位图信息，以及是否缓存完整等
	void *io_stat;// io 打开 读写 关闭等
	void *lru;//lru链表 区分普通缓存和永久缓存
};

int main()
{
	printf("size=%d\n", sizeof(struct cache_index_t));
	return 0;
}

