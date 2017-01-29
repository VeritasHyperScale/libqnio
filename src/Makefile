all:

MAKEFILE = Makefile
SHELL = /bin/sh
CC    = gcc

CPPFLAGS     = -Iinclude
CFLAGS       = -fPIC -fno-strict-aliasing -Wall -Werror -g -pthread
DEPFLAGS     = -MMD -MP -MT $@ -MF $(@D)/$(*F).d
LDFLAGS      = -shared
DEBUGFLAGS   = -O0 -D_DEBUG -D_REENTRANT
RELEASEFLAGS = -03 -D_REENTRANT
HEADERS      = /usr/include/qnio
TEST_TARGET_DIR = /usr/local/bin
LIBRARY      = /usr/lib64

OPTFLAGS     = $(DEBUGFLAGS)

BASE_TARGET = libqnio.so
BASE_SOURCES = $(shell echo lib/qnio/*.c) 
BASE_OBJS = $(shell echo lib/qnio/*.o lib/qnio/*.d)
BASE_OBJECTS = $(BASE_SOURCES:.c=.o)
-include $(BASE_SOURCES:.c=.d)

TEST_TARGET = qnio_server 
TEST_SOURCES = $(shell echo test/server.c)
TEST_OBJS = $(shell echo test/server.o lib/qnio/server.d)
TEST_OBJECTS = $(TEST_SOURCES:.c=.o)
-include $(TEST_SOURCES:.c=.d)

TEST_CLIENT_TARGET = qnio_client
TEST_CLIENT_SOURCES = $(shell echo test/client.c)
TEST_CLIENT_OBJS = $(shell echo test/client.o lib/qnio/client.d)
TEST_CLIENT_OBJECTS = $(TEST_CLIENT_SOURCES:.c=.o)
-include $(TEST_CLIENT_SOURCES:.c=.d)

debug:
	$(MAKE) -f $(MAKEFILE) DEV2="-DDEBUG_QNIO";

all: $(BASE_TARGET) $(TEST_TARGET) $(TEST_CLIENT_TARGET)

.c.o:
	$(CC) $(CFLAGS) $(CPPFLAGS) $(DEV2) $(DEPFLAGS) $(OPTFLAGS) -c -o $@ $<

$(BASE_TARGET): $(BASE_OBJECTS)
	$(CC) $(FLAGS) $(CFLAGS) $(LDFLAGS) -o $(BASE_TARGET) $(BASE_OBJECTS)

$(TEST_TARGET): $(TEST_OBJECTS) $(BASE_TARGET)
	$(CC) $(FLAGS) $(CFLAGS) -o $(TEST_TARGET) $(TEST_OBJECTS) -L. -lqnio -lssl -lcrypto

$(TEST_CLIENT_TARGET): $(TEST_CLIENT_OBJECTS) $(BASE_TARGET)
	$(CC) $(FLAGS) $(CFLAGS) -o $(TEST_CLIENT_TARGET) $(TEST_CLIENT_OBJECTS) -L. -lqnio -lssl -lcrypto -lrt

clean:
	\rm -f $(BASE_TARGET)
	\rm -f $(BASE_OBJS)
	\rm -f $(TEST_TARGET)
	\rm -f $(TEST_OBJS)
	\rm -f $(TEST_CLIENT_TARGET)
	\rm -f $(TEST_CLIENT_OBJS)

install: all
	mkdir -p $(HEADERS) || exit
	cp -f include/qnio_api.h $(HEADERS)/qnio_api.h
	cp -f $(BASE_TARGET) $(LIBRARY)/$(BASE_TARGET)
	cp -f $(TEST_TARGET) ${TEST_TARGET_DIR}/$(TEST_TARGET)
	cp -f $(TEST_CLIENT_TARGET) ${TEST_TARGET_DIR}/$(TEST_CLIENT_TARGET)

uninstall:
	rm -f $(HEADERS)/qnio_api.h
	rm -f $(LIBRARY)/$(BASE_TARGET)
	rm -f ${TEST_TARGET_DIR}/$(TEST_TARGET)
	rm -f ${TEST_TARGET_DIR}/$(TEST_CLIENT_TARGET)
