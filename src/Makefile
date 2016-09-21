all:

SHELL = /bin/sh
CC    = gcc

CPPFLAGS     = -Iinclude
CFLAGS       = -fPIC -fno-strict-aliasing -Wall -Werror -g -pthread
DEPFLAGS     = -MMD -MP -MT $@ -MF $(@D)/$(*F).d
LDFLAGS      = -shared
DEBUGFLAGS   = -O0 -D_DEBUG -D_REENTRANT
RELEASEFLAGS = -03 -D_REENTRANT

OPTFLAGS     = $(DEBUGFLAGS)

HEADERS = $(shell echo include/*.h)

BASE_TARGET = libqnio.so
BASE_SOURCES = $(shell echo lib/qnio/*.c) 
BASE_OBJS = $(shell echo lib/qnio/*.o lib/qnio/*.d)
BASE_OBJECTS = $(BASE_SOURCES:.c=.o)
-include $(BASE_SOURCES:.c=.d)

TEST_TARGET = qnio_server 
TEST_SOURCES = $(shell echo test/*.c)
TEST_OBJS = $(shell echo test/*.o lib/qnio/*.d)
TEST_OBJECTS = $(TEST_SOURCES:.c=.o)
-include $(TEST_SOURCES:.c=.d)

all: $(BASE_TARGET) $(TEST_TARGET)

.c.o:
	$(CC) $(CFLAGS) $(CPPFLAGS) $(DEPFLAGS) $(OPTFLAGS) -c -o $@ $<

$(BASE_TARGET): $(BASE_OBJECTS)
	$(CC) $(FLAGS) $(CFLAGS) $(LDFLAGS) -o $(BASE_TARGET) $(BASE_OBJECTS)

$(TEST_TARGET): $(TEST_OBJECTS) $(BASE_TARGET)
	$(CC) $(FLAGS) $(CFLAGS) -o $(TEST_TARGET) $(TEST_OBJECTS) -L. -lqnio

clean:
	\rm -f $(BASE_TARGET)
	\rm -f $(BASE_OBJS)
	\rm -f $(TEST_TARGET)
	\rm -f $(TEST_OBJS)

