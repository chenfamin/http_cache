TARGET=http

GPROF_CFLAGS=
CFLAGS += $(GPROF_CFLAGS) -Wall -g -O0 -DMEM_POOL=0
LDFLAGS += -lpthread
#LDFLAGS += -static

OBJECTS = http_main.c listen_session.c http_dns.c http_session.c http_util.c http_header.c http_connection.c http_aio.c http_log.c rbtree.c http_parser.c

HFILES = 

TARGET: $(HFILES) $(OBJECTS)
	$(CC) $(CFLAGS) -o $(TARGET) $(HFILES) $(OBJECTS) $(LDFLAGS)

test:
	./$(TARGET)
clean:
	rm -f $(TARGET) *.o
	rm -f debug.log
	rm -f gmon.out
