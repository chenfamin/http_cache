#include "http_util.h"

#define likely(x)    __builtin_expect(!!(x), 1)
#define unlikely(x)  __builtin_expect(!!(x), 0)
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

static int fls_map[512] = {
	3, /* 8 */ 
	4, /* 16 */ 
	5, /* 24 */ 
	5, /* 32 */ 
	6, /* 40 */ 
	6, /* 48 */ 
	6, /* 56 */ 
	6, /* 64 */ 
	7, /* 72 */ 
	7, /* 80 */ 
	7, /* 88 */ 
	7, /* 96 */ 
	7, /* 104 */ 
	7, /* 112 */ 
	7, /* 120 */ 
	7, /* 128 */ 
	8, /* 136 */ 
	8, /* 144 */ 
	8, /* 152 */ 
	8, /* 160 */ 
	8, /* 168 */ 
	8, /* 176 */ 
	8, /* 184 */ 
	8, /* 192 */ 
	8, /* 200 */ 
	8, /* 208 */ 
	8, /* 216 */ 
	8, /* 224 */ 
	8, /* 232 */ 
	8, /* 240 */ 
	8, /* 248 */ 
	8, /* 256 */ 
	9, /* 264 */ 
	9, /* 272 */ 
	9, /* 280 */ 
	9, /* 288 */ 
	9, /* 296 */ 
	9, /* 304 */ 
	9, /* 312 */ 
	9, /* 320 */ 
	9, /* 328 */ 
	9, /* 336 */ 
	9, /* 344 */ 
	9, /* 352 */ 
	9, /* 360 */ 
	9, /* 368 */ 
	9, /* 376 */ 
	9, /* 384 */ 
	9, /* 392 */ 
	9, /* 400 */ 
	9, /* 408 */ 
	9, /* 416 */ 
	9, /* 424 */ 
	9, /* 432 */ 
	9, /* 440 */ 
	9, /* 448 */ 
	9, /* 456 */ 
	9, /* 464 */ 
	9, /* 472 */ 
	9, /* 480 */ 
	9, /* 488 */ 
	9, /* 496 */ 
	9, /* 504 */ 
	9, /* 512 */ 
	10, /* 520 */ 
	10, /* 528 */ 
	10, /* 536 */ 
	10, /* 544 */ 
	10, /* 552 */ 
	10, /* 560 */ 
	10, /* 568 */ 
	10, /* 576 */ 
	10, /* 584 */ 
	10, /* 592 */ 
	10, /* 600 */ 
	10, /* 608 */ 
	10, /* 616 */ 
	10, /* 624 */ 
	10, /* 632 */ 
	10, /* 640 */ 
	10, /* 648 */ 
	10, /* 656 */ 
	10, /* 664 */ 
	10, /* 672 */ 
	10, /* 680 */ 
	10, /* 688 */ 
	10, /* 696 */ 
	10, /* 704 */ 
	10, /* 712 */ 
	10, /* 720 */ 
	10, /* 728 */ 
	10, /* 736 */ 
	10, /* 744 */ 
	10, /* 752 */ 
	10, /* 760 */ 
	10, /* 768 */ 
	10, /* 776 */ 
	10, /* 784 */ 
	10, /* 792 */ 
	10, /* 800 */ 
	10, /* 808 */ 
	10, /* 816 */ 
	10, /* 824 */ 
	10, /* 832 */ 
	10, /* 840 */ 
	10, /* 848 */ 
	10, /* 856 */ 
	10, /* 864 */ 
	10, /* 872 */ 
	10, /* 880 */ 
	10, /* 888 */ 
	10, /* 896 */ 
	10, /* 904 */ 
	10, /* 912 */ 
	10, /* 920 */ 
	10, /* 928 */ 
	10, /* 936 */ 
	10, /* 944 */ 
	10, /* 952 */ 
	10, /* 960 */ 
	10, /* 968 */ 
	10, /* 976 */ 
	10, /* 984 */ 
	10, /* 992 */ 
	10, /* 1000 */ 
	10, /* 1008 */ 
	10, /* 1016 */ 
	10, /* 1024 */ 
	11, /* 1032 */ 
	11, /* 1040 */ 
	11, /* 1048 */ 
	11, /* 1056 */ 
	11, /* 1064 */ 
	11, /* 1072 */ 
	11, /* 1080 */ 
	11, /* 1088 */ 
	11, /* 1096 */ 
	11, /* 1104 */ 
	11, /* 1112 */ 
	11, /* 1120 */ 
	11, /* 1128 */ 
	11, /* 1136 */ 
	11, /* 1144 */ 
	11, /* 1152 */ 
	11, /* 1160 */ 
	11, /* 1168 */ 
	11, /* 1176 */ 
	11, /* 1184 */ 
	11, /* 1192 */ 
	11, /* 1200 */ 
	11, /* 1208 */ 
	11, /* 1216 */ 
	11, /* 1224 */ 
	11, /* 1232 */ 
	11, /* 1240 */ 
	11, /* 1248 */ 
	11, /* 1256 */ 
	11, /* 1264 */ 
	11, /* 1272 */ 
	11, /* 1280 */ 
	11, /* 1288 */ 
	11, /* 1296 */ 
	11, /* 1304 */ 
	11, /* 1312 */ 
	11, /* 1320 */ 
	11, /* 1328 */ 
	11, /* 1336 */ 
	11, /* 1344 */ 
	11, /* 1352 */ 
	11, /* 1360 */ 
	11, /* 1368 */ 
	11, /* 1376 */ 
	11, /* 1384 */ 
	11, /* 1392 */ 
	11, /* 1400 */ 
	11, /* 1408 */ 
	11, /* 1416 */ 
	11, /* 1424 */ 
	11, /* 1432 */ 
	11, /* 1440 */ 
	11, /* 1448 */ 
	11, /* 1456 */ 
	11, /* 1464 */ 
	11, /* 1472 */ 
	11, /* 1480 */ 
	11, /* 1488 */ 
	11, /* 1496 */ 
	11, /* 1504 */ 
	11, /* 1512 */ 
	11, /* 1520 */ 
	11, /* 1528 */ 
	11, /* 1536 */ 
	11, /* 1544 */ 
	11, /* 1552 */ 
	11, /* 1560 */ 
	11, /* 1568 */ 
	11, /* 1576 */ 
	11, /* 1584 */ 
	11, /* 1592 */ 
	11, /* 1600 */ 
	11, /* 1608 */ 
	11, /* 1616 */ 
	11, /* 1624 */ 
	11, /* 1632 */ 
	11, /* 1640 */ 
	11, /* 1648 */ 
	11, /* 1656 */ 
	11, /* 1664 */ 
	11, /* 1672 */ 
	11, /* 1680 */ 
	11, /* 1688 */ 
	11, /* 1696 */ 
	11, /* 1704 */ 
	11, /* 1712 */ 
	11, /* 1720 */ 
	11, /* 1728 */ 
	11, /* 1736 */ 
	11, /* 1744 */ 
	11, /* 1752 */ 
	11, /* 1760 */ 
	11, /* 1768 */ 
	11, /* 1776 */ 
	11, /* 1784 */ 
	11, /* 1792 */ 
	11, /* 1800 */ 
	11, /* 1808 */ 
	11, /* 1816 */ 
	11, /* 1824 */ 
	11, /* 1832 */ 
	11, /* 1840 */ 
	11, /* 1848 */ 
	11, /* 1856 */ 
	11, /* 1864 */ 
	11, /* 1872 */ 
	11, /* 1880 */ 
	11, /* 1888 */ 
	11, /* 1896 */ 
	11, /* 1904 */ 
	11, /* 1912 */ 
	11, /* 1920 */ 
	11, /* 1928 */ 
	11, /* 1936 */ 
	11, /* 1944 */ 
	11, /* 1952 */ 
	11, /* 1960 */ 
	11, /* 1968 */ 
	11, /* 1976 */ 
	11, /* 1984 */ 
	11, /* 1992 */ 
	11, /* 2000 */ 
	11, /* 2008 */ 
	11, /* 2016 */ 
	11, /* 2024 */ 
	11, /* 2032 */ 
	11, /* 2040 */ 
	11, /* 2048 */ 
	12, /* 2056 */ 
	12, /* 2064 */ 
	12, /* 2072 */ 
	12, /* 2080 */ 
	12, /* 2088 */ 
	12, /* 2096 */ 
	12, /* 2104 */ 
	12, /* 2112 */ 
	12, /* 2120 */ 
	12, /* 2128 */ 
	12, /* 2136 */ 
	12, /* 2144 */ 
	12, /* 2152 */ 
	12, /* 2160 */ 
	12, /* 2168 */ 
	12, /* 2176 */ 
	12, /* 2184 */ 
	12, /* 2192 */ 
	12, /* 2200 */ 
	12, /* 2208 */ 
	12, /* 2216 */ 
	12, /* 2224 */ 
	12, /* 2232 */ 
	12, /* 2240 */ 
	12, /* 2248 */ 
	12, /* 2256 */ 
	12, /* 2264 */ 
	12, /* 2272 */ 
	12, /* 2280 */ 
	12, /* 2288 */ 
	12, /* 2296 */ 
	12, /* 2304 */ 
	12, /* 2312 */ 
	12, /* 2320 */ 
	12, /* 2328 */ 
	12, /* 2336 */ 
	12, /* 2344 */ 
	12, /* 2352 */ 
	12, /* 2360 */ 
	12, /* 2368 */ 
	12, /* 2376 */ 
	12, /* 2384 */ 
	12, /* 2392 */ 
	12, /* 2400 */ 
	12, /* 2408 */ 
	12, /* 2416 */ 
	12, /* 2424 */ 
	12, /* 2432 */ 
	12, /* 2440 */ 
	12, /* 2448 */ 
	12, /* 2456 */ 
	12, /* 2464 */ 
	12, /* 2472 */ 
	12, /* 2480 */ 
	12, /* 2488 */ 
	12, /* 2496 */ 
	12, /* 2504 */ 
	12, /* 2512 */ 
	12, /* 2520 */ 
	12, /* 2528 */ 
	12, /* 2536 */ 
	12, /* 2544 */ 
	12, /* 2552 */ 
	12, /* 2560 */ 
	12, /* 2568 */ 
	12, /* 2576 */ 
	12, /* 2584 */ 
	12, /* 2592 */ 
	12, /* 2600 */ 
	12, /* 2608 */ 
	12, /* 2616 */ 
	12, /* 2624 */ 
	12, /* 2632 */ 
	12, /* 2640 */ 
	12, /* 2648 */ 
	12, /* 2656 */ 
	12, /* 2664 */ 
	12, /* 2672 */ 
	12, /* 2680 */ 
	12, /* 2688 */ 
	12, /* 2696 */ 
	12, /* 2704 */ 
	12, /* 2712 */ 
	12, /* 2720 */ 
	12, /* 2728 */ 
	12, /* 2736 */ 
	12, /* 2744 */ 
	12, /* 2752 */ 
	12, /* 2760 */ 
	12, /* 2768 */ 
	12, /* 2776 */ 
	12, /* 2784 */ 
	12, /* 2792 */ 
	12, /* 2800 */ 
	12, /* 2808 */ 
	12, /* 2816 */ 
	12, /* 2824 */ 
	12, /* 2832 */ 
	12, /* 2840 */ 
	12, /* 2848 */ 
	12, /* 2856 */ 
	12, /* 2864 */ 
	12, /* 2872 */ 
	12, /* 2880 */ 
	12, /* 2888 */ 
	12, /* 2896 */ 
	12, /* 2904 */ 
	12, /* 2912 */ 
	12, /* 2920 */ 
	12, /* 2928 */ 
	12, /* 2936 */ 
	12, /* 2944 */ 
	12, /* 2952 */ 
	12, /* 2960 */ 
	12, /* 2968 */ 
	12, /* 2976 */ 
	12, /* 2984 */ 
	12, /* 2992 */ 
	12, /* 3000 */ 
	12, /* 3008 */ 
	12, /* 3016 */ 
	12, /* 3024 */ 
	12, /* 3032 */ 
	12, /* 3040 */ 
	12, /* 3048 */ 
	12, /* 3056 */ 
	12, /* 3064 */ 
	12, /* 3072 */ 
	12, /* 3080 */ 
	12, /* 3088 */ 
	12, /* 3096 */ 
	12, /* 3104 */ 
	12, /* 3112 */ 
	12, /* 3120 */ 
	12, /* 3128 */ 
	12, /* 3136 */ 
	12, /* 3144 */ 
	12, /* 3152 */ 
	12, /* 3160 */ 
	12, /* 3168 */ 
	12, /* 3176 */ 
	12, /* 3184 */ 
	12, /* 3192 */ 
	12, /* 3200 */ 
	12, /* 3208 */ 
	12, /* 3216 */ 
	12, /* 3224 */ 
	12, /* 3232 */ 
	12, /* 3240 */ 
	12, /* 3248 */ 
	12, /* 3256 */ 
	12, /* 3264 */ 
	12, /* 3272 */ 
	12, /* 3280 */ 
	12, /* 3288 */ 
	12, /* 3296 */ 
	12, /* 3304 */ 
	12, /* 3312 */ 
	12, /* 3320 */ 
	12, /* 3328 */ 
	12, /* 3336 */ 
	12, /* 3344 */ 
	12, /* 3352 */ 
	12, /* 3360 */ 
	12, /* 3368 */ 
	12, /* 3376 */ 
	12, /* 3384 */ 
	12, /* 3392 */ 
	12, /* 3400 */ 
	12, /* 3408 */ 
	12, /* 3416 */ 
	12, /* 3424 */ 
	12, /* 3432 */ 
	12, /* 3440 */ 
	12, /* 3448 */ 
	12, /* 3456 */ 
	12, /* 3464 */ 
	12, /* 3472 */ 
	12, /* 3480 */ 
	12, /* 3488 */ 
	12, /* 3496 */ 
	12, /* 3504 */ 
	12, /* 3512 */ 
	12, /* 3520 */ 
	12, /* 3528 */ 
	12, /* 3536 */ 
	12, /* 3544 */ 
	12, /* 3552 */ 
	12, /* 3560 */ 
	12, /* 3568 */ 
	12, /* 3576 */ 
	12, /* 3584 */ 
	12, /* 3592 */ 
	12, /* 3600 */ 
	12, /* 3608 */ 
	12, /* 3616 */ 
	12, /* 3624 */ 
	12, /* 3632 */ 
	12, /* 3640 */ 
	12, /* 3648 */ 
	12, /* 3656 */ 
	12, /* 3664 */ 
	12, /* 3672 */ 
	12, /* 3680 */ 
	12, /* 3688 */ 
	12, /* 3696 */ 
	12, /* 3704 */ 
	12, /* 3712 */ 
	12, /* 3720 */ 
	12, /* 3728 */ 
	12, /* 3736 */ 
	12, /* 3744 */ 
	12, /* 3752 */ 
	12, /* 3760 */ 
	12, /* 3768 */ 
	12, /* 3776 */ 
	12, /* 3784 */ 
	12, /* 3792 */ 
	12, /* 3800 */ 
	12, /* 3808 */ 
	12, /* 3816 */ 
	12, /* 3824 */ 
	12, /* 3832 */ 
	12, /* 3840 */ 
	12, /* 3848 */ 
	12, /* 3856 */ 
	12, /* 3864 */ 
	12, /* 3872 */ 
	12, /* 3880 */ 
	12, /* 3888 */ 
	12, /* 3896 */ 
	12, /* 3904 */ 
	12, /* 3912 */ 
	12, /* 3920 */ 
	12, /* 3928 */ 
	12, /* 3936 */ 
	12, /* 3944 */ 
	12, /* 3952 */ 
	12, /* 3960 */ 
	12, /* 3968 */ 
	12, /* 3976 */ 
	12, /* 3984 */ 
	12, /* 3992 */ 
	12, /* 4000 */ 
	12, /* 4008 */ 
	12, /* 4016 */ 
	12, /* 4024 */ 
	12, /* 4032 */ 
	12, /* 4040 */ 
	12, /* 4048 */ 
	12, /* 4056 */ 
	12, /* 4064 */ 
	12, /* 4072 */ 
	12, /* 4080 */ 
	12, /* 4088 */ 
	12, /* 4096 */ 
};

struct mem_pool_t {
	pthread_mutex_t pool_mutex;
	struct list_head_t list;
	int mem_size;
	int mem_alloc_size;

	int  pool_size;
	int64_t alloc_count;
	int64_t free_count;
};

struct mem_node_t {
	int alloc_size;
	struct list_head_t node;
	struct mem_pool_t *mem_pool;
};

static struct mem_pool_t mem_pools[20];

static __always_inline int fls(int x);
static void mem_pool_init(struct mem_pool_t *mem_pool, int size);
static struct mem_node_t* mem_pool_alloc(struct mem_pool_t *mem_pool);
static void mem_pool_free(struct mem_pool_t *mem_pool, struct mem_node_t *mem_node);
static void mem_pool_destroy(struct mem_pool_t *mem_pool);
static void size_to_str(char *buf, int buf_size, int64_t size);
static int64_t mem_pool_report(struct mem_pool_t *mem_pool, int mem_pool_id, char *buf, size_t size);

static __always_inline int fls(int x)
{
	int r = 32;

	if (!x)
		return 0;
	if (!(x & 0xffff0000u)) {
		x <<= 16;
		r -= 16;
	}
	if (!(x & 0xff000000u)) {
		x <<= 8;
		r -= 8;
	}
	if (!(x & 0xf0000000u)) {
		x <<= 4;
		r -= 4;
	}
	if (!(x & 0xc0000000u)) {
		x <<= 2;
		r -= 2;
	}
	if (!(x & 0x80000000u)) {
		x <<= 1;
		r -= 1;
	}
	return r;
}

void mem_pools_init()
{
	int i = 0;
	for (i = 0; i < ARRAY_SIZE(mem_pools); i++) {
		mem_pool_init(mem_pools + i, 1 << i);
	}
}

static void mem_pool_init(struct mem_pool_t *mem_pool, int size)
{
	memset(mem_pool, 0, sizeof(struct mem_pool_t));
	pthread_mutex_init(&mem_pool->pool_mutex, NULL);
	INIT_LIST_HEAD(&mem_pool->list);
	mem_pool->mem_size = size;
	mem_pool->mem_alloc_size = sizeof(struct mem_node_t) + mem_pool->mem_size;
}

static struct mem_node_t* mem_pool_alloc(struct mem_pool_t *mem_pool)
{
	struct mem_node_t *mem_node = NULL;
	pthread_mutex_lock(&mem_pool->pool_mutex);
	if (!list_empty(&mem_pool->list)) {
		mem_node = d_list_head(&mem_pool->list, struct mem_node_t, node);
		list_del(&mem_node->node);
	} else {
		mem_pool->pool_size++;
	}
	mem_pool->alloc_count++;
	pthread_mutex_unlock(&mem_pool->pool_mutex);
	if (mem_node == NULL) {
		mem_node = malloc(mem_pool->mem_alloc_size);
		mem_node->mem_pool = mem_pool; 
	}
	return mem_node;
}

static void mem_pool_free(struct mem_pool_t *mem_pool, struct mem_node_t *mem_node)
{
	pthread_mutex_lock(&mem_pool->pool_mutex);
	list_add(&mem_node->node, &mem_pool->list);
	mem_pool->free_count++;
	pthread_mutex_unlock(&mem_pool->pool_mutex);
}

static void mem_pool_destroy(struct mem_pool_t *mem_pool)
{
	struct mem_node_t *mem_node = NULL;
	while (!list_empty(&mem_pool->list)) {
		mem_node = d_list_head(&mem_pool->list, struct mem_node_t, node);
		list_del(&mem_node->node);
		free(mem_node);
	}
	pthread_mutex_destroy(&mem_pool->pool_mutex);
}

void mem_pools_report(char *buf, size_t size)
{
	int i = 0;
	int64_t pool_size = 0;
	static char pool_size_buf[256];
	snprintf(buf, size, "%-20s %-20s %-20s %-20s %-20s %-20s %-20s\n", "id", "mem_size", "pool_count", "pool_size", "alloc_count", "free_count", "inuse_count");
	for (i = 0; i < ARRAY_SIZE(mem_pools); i++) {
		pool_size += mem_pool_report(mem_pools + i, i, buf + strlen(buf), size - strlen(buf));
	}
	size_to_str(pool_size_buf, sizeof(pool_size_buf), pool_size);
	snprintf(buf + strlen(buf), size - strlen(buf), "\n%-20s %-20s\n", "all_size", pool_size_buf);
}

static void size_to_str(char *buf, int buf_size, int64_t size)
{
	double d_size = 0.0;
	char *uint = "";
	if (size > (1 << 30)) {
		d_size = (double)size / (1 << 30);
		uint = "GB";
	} else if (size > (1 << 20)) {
		d_size = (double)size / (1 << 20);
		uint = "MB";
	} else if (size > (1 << 10)) {
		d_size = (double)size / (1 << 10);
		uint = "KB";
	} else {
		d_size = size;
		uint = "";
	}
	snprintf(buf, buf_size - 1, "%.3f %s", d_size, uint);
}

static int64_t mem_pool_report(struct mem_pool_t *mem_pool, int mem_pool_id, char *buf, size_t size)
{
	char pool_size_buf[256];
	int64_t pool_size = 0;
	pthread_mutex_lock(&mem_pool->pool_mutex);
	pool_size = mem_pool->pool_size * mem_pool->mem_alloc_size;
	size_to_str(pool_size_buf, sizeof(pool_size_buf), pool_size);
	snprintf(buf, size, "%-20d %-20d %-20d %-20s %-20"PRId64" %-20"PRId64" %-20"PRId64"\n",
			mem_pool_id, mem_pool->mem_size, mem_pool->pool_size, pool_size_buf,
			mem_pool->alloc_count, mem_pool->free_count, mem_pool->alloc_count - mem_pool->free_count);
	pthread_mutex_unlock(&mem_pool->pool_mutex);
	return pool_size;
}

void mem_pools_destroy()
{
	int i = 0;
	for (i = 0; i < ARRAY_SIZE(mem_pools); i++) {
		mem_pool_destroy(mem_pools + i);
	}
}

void* mem_malloc(size_t size)
{
	size_t mem_pool_id = 0;
	struct mem_pool_t *mem_pool = NULL;
	struct mem_node_t *mem_node = NULL;
	mem_pool_id = size <= 4096? fls_map[(size - 1) >> 3]: fls(size - 1);
	mem_pool = mem_pool_id < ARRAY_SIZE(mem_pools) ? mem_pools + mem_pool_id : NULL;
	if (likely(mem_pool)) {
		mem_node = mem_pool_alloc(mem_pool);
	} else {
		mem_node = malloc(sizeof(struct mem_node_t) + size);
		mem_node->mem_pool = NULL;
	}
	mem_node->alloc_size = size;
	return (void*)mem_node + sizeof(struct mem_node_t);
}

void *mem_realloc(void *ptr, size_t size)
{
	void *ptr_new = NULL;
	struct mem_node_t *mem_node = (struct mem_node_t *)(ptr - sizeof(struct mem_node_t));
	if (likely(mem_node->mem_pool) && mem_node->mem_pool->mem_size >= size) {
		mem_node->alloc_size = size;
		return ptr;
	}
	ptr_new = mem_malloc(size);
	memcpy(ptr_new, ptr, mem_node->alloc_size);
	if (likely(mem_node->mem_pool)) {
		mem_pool_free(mem_node->mem_pool, mem_node);
	} else {
		free(mem_node);
	}
	return ptr_new;
}

void mem_free(void *ptr)
{
	struct mem_node_t *mem_node = (struct mem_node_t *)(ptr - sizeof(struct mem_node_t));
	assert(mem_node->alloc_size > 0);
	mem_node->alloc_size = 0;
	if (likely(mem_node->mem_pool)) {
		mem_pool_free(mem_node->mem_pool, mem_node);
	} else {
		free(mem_node);
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

void string_clean(struct string_t *string)
{
	http_free(string->buf);
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

size_t string_strsize(const struct string_t *string)
{
	return string->size;
}

char* string_buf(const struct string_t *string)
{
	return string->buf;
}

struct buffer_t* buffer_alloc(size_t size)
{
	struct buffer_t *buffer = NULL;
	buffer = http_malloc(sizeof(struct buffer_t) + size);
	buffer->ref = 1;
	buffer->size = size;
	buffer->len = 0;
	buffer->buf = (void *)buffer + sizeof(struct buffer_t);
	return buffer;
}

struct buffer_t* buffer_ref(struct buffer_t *buffer)
{
	buffer->ref++;
	return buffer;
}

void buffer_unref(struct buffer_t *buffer)
{
	buffer->ref--;
	if (buffer->ref == 0) {
		http_free(buffer);
	}
}

int buffer_full(struct buffer_t *buffer)
{
	return buffer->len == buffer->size;
}

int buffer_empty(struct buffer_t *buffer)
{
	return buffer->len == 0;
}

void fifo_init(struct fifo_t *fifo, unsigned int size)
{
	assert(is_power_of_2(size));
	fifo->data = http_malloc(size * sizeof(void*));
	fifo->size = size;
	fifo->in = 0;
	fifo->out = 0;
}

unsigned int fifo_size(struct fifo_t *fifo)
{
	return fifo->size;
}

unsigned int fifo_len(struct fifo_t *fifo)
{
	return fifo->in - fifo->out;
}

void fifo_push_tail(struct fifo_t *fifo, void *buffer)
{
	assert(fifo_len(fifo) < fifo->size);
	fifo->data[fifo->in & (fifo->size - 1)] = buffer;
	fifo->in++;
}

void fifo_pop_head(struct fifo_t *fifo, void **buffer)
{
	if (fifo_len(fifo) > 0) {
		*buffer = fifo->data[fifo->out & (fifo->size - 1)];
		fifo->out++;
	} else {
		*buffer = NULL;
	}
}

void *fifo_head(struct fifo_t *fifo)
{
	if (fifo_len(fifo) > 0) {
		return fifo->data[fifo->out & (fifo->size - 1)];
	} else {
		return NULL;
	}
}

void *fifo_tail(struct fifo_t *fifo)
{
	if (fifo_len(fifo) > 0) {
		return fifo->data[(fifo->in - 1) & (fifo->size - 1)];
	} else {
		return NULL;
	}
}
void fifo_clean(struct fifo_t *fifo)
{
	http_free(fifo->data);
}

const char* sockaddr_string(struct sockaddr *addr, char *str, int size)
{
	if (addr->sa_family == AF_INET) {
		inet_ntop(addr->sa_family, &((struct sockaddr_in *)addr)->sin_addr, str, size);
	} else if (addr->sa_family == AF_INET6) {
		inet_ntop(addr->sa_family, &((struct sockaddr_in6 *)addr)->sin6_addr, str, size);
	}
	return str;
}

unsigned short sockaddr_port(struct sockaddr *addr)
{
	unsigned short port = 0;
	if (addr->sa_family == AF_INET) {
		port = ntohs(((struct sockaddr_in *)addr)->sin_port);
	} else if (addr->sa_family == AF_INET6) {
		port = ntohs(((struct sockaddr_in6 *)addr)->sin6_port);
	}
	return port;
}

int socket_listen(const char *host, unsigned short port, int family)
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
		//LOG(LOG_ERROR, "%s addr error\n", host);
		return -1;
	}
	fd = socket(addr.sa_family, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0) {
		//LOG(LOG_ERROR, "socket fd=%d error:%s\n", fd, strerror(errno));
		return -1;
	}
	var = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &var, sizeof(var)) == -1) {
		//LOG(LOG_ERROR, "setsockopt fd=%d error:%s\n", fd, strerror(errno));
		close(fd);
		return -1;
	}
	if (bind(fd, &addr, sizeof(addr)) != 0) {
		//LOG(LOG_ERROR, "listen fd=%d error:%s\n", fd, strerror(errno));
		close(fd);
		return -1;
	}
	if (listen(fd, 1024) != 0) {
		//LOG(LOG_ERROR, "listen fd=%d error:%s\n", fd, strerror(errno));
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
