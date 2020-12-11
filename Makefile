TARGET = http

CFLAGS += -g -Wall
LDFLAGS += -lpthread
#LDFLAGS += -static

OBJECTS = http_parser.c http_mem.c rbtree.c http_log.c http_aio.c http_connection.c http_header.c http_session.c http_dns.c http_main.c

HFILES = 

TARGET: $(HFILES) $(OBJECTS)
	$(CC) $(CFLAGS) -o $(TARGET) $(HFILES) $(OBJECTS) $(LDFLAGS)

test:
	./$(TARGET)
clean:
	rm -f $(TARGET) *.o
	rm -f debug.log
