#include "http.h"
#include "http_log.h"

void log_printf(int level, const char *file, int line, const char *function, const char *fmt, ...)
{
	if (level > LOG_DEBUG) {
		return;
	}
	va_list argptr;
	time_t current;
	struct tm tm;;
	current = time(NULL);
	localtime_r(&current, &tm);
	fprintf(stdout, "%d/%02d/%02d %02d:%02d:%02d %s|%d|%s: ", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, file, line, function);
	va_start(argptr, fmt);
	vfprintf(stdout, fmt, argptr);
	va_end(argptr);
}

