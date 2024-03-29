#ifndef HTTP_LOG_H
#define HTTP_LOG_H

#define LOG_ERROR 0
#define LOG_WARNING 1
#define LOG_INFO 2
#define LOG_DEBUG 3

void log_printf(int level, const char *file, int line, const char *function, const char *fmt, ...);
#define LOG(level, arg...) log_printf(level, __FILE__, __LINE__, __FUNCTION__, ##arg)
//#define LOG(level, arg...) (void)0


#endif
