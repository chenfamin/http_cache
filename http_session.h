#ifndef HTTP_SESSION_H
#define HTTP_SESSION_H

void http_session_listen(const char *host, int port);
void cache_table_init();
void cache_table_clean();

#endif
