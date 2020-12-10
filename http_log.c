#include "http.h"
#include "http_log.h"

struct log_file_t {
	int fd;
	int64_t size;
	pthread_mutex_t mutex;
};

static struct log_file_t *log_file = NULL;

void log_printf(int level, const char *file, int line, const char *function, const char *fmt, ...)
{
	return;
	if (level > LOG_DEBUG) {
		return;
	}
	va_list argptr;
	time_t current;
	struct tm tm;;
	char buf[4096];
	ssize_t nwrite;
	int n1;
	int n2;
	current = time(NULL);
	localtime_r(&current, &tm);
	n1 = snprintf(buf, sizeof(buf), "%d/%02d/%02d %02d:%02d:%02d %s|%d|%s: ", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, file, line, function);
	va_start(argptr, fmt);
	n2 = vsnprintf(buf + n1, sizeof(buf) - n1, fmt, argptr);
	va_end(argptr);
	nwrite = write(log_file->fd, buf, MIN(n1 + n2, sizeof(buf) - 1));
	pthread_mutex_lock(&log_file->mutex);
	if (nwrite > 0) {
		log_file->size += nwrite;
	}
	pthread_mutex_unlock(&log_file->mutex);
}

void log_file_open()
{
	log_file = http_malloc(sizeof(struct log_file_t));
	memset(log_file, 0, sizeof(struct log_file_t));
	//log_file->fd = open("debug.log", O_WRONLY|O_CREAT|O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
	if (log_file->fd <= 0) {
		log_file->fd = 1;// stdout
	}
	pthread_mutex_init(&log_file->mutex, NULL);
}

void log_file_close()
{
	if (log_file->fd > 2) {
		close(log_file->fd);
	}
	pthread_mutex_destroy(&log_file->mutex);
	http_free(log_file);
	log_file = NULL;
}
