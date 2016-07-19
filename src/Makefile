SHELL = /bin/sh
CC    = gcc

CFLAGS       = -fPIC -fno-strict-aliasing -Wall -Werror -m64 -Iinclude -g -pthread
LDFLAGS      = -shared
DEBUGFLAGS   = -O0 -D_DEBUG -D_REENTRANT
RELEASEFLAGS = -03 -D_REENTRANT

HEADERS = $(shell echo include/*.h)

BASE_TARGET = libqnio.so
BASE_SOURCES = $(shell echo lib/qnio/*.c) 
BASE_OBJS = $(shell echo lib/qnio/*.o)
BASE_OBJECTS = $(BASE_SOURCES:.c=.o)

SHIM_TARGET = libqnioshim.so
SHIM_SOURCES = $(shell echo lib/qnioshim/*.c) 
SHIM_OBJS = $(shell echo lib/qnioshim/*.o)
SHIM_OBJECTS = $(SHIM_SOURCES:.c=.o)

TEST_TARGET = qnio_server 
TEST_SOURCES = $(shell echo test/*.c)
TEST_OBJECTS = $(TEST_SOURCES:.c=.o)
TEST_OBJS = $(shell echo test/*.o)

all: $(BASE_TARGET) $(SHIM_TARGET) $(TEST_TARGET)

$(BASE_TARGET): $(BASE_OBJECTS)
	$(CC) $(FLAGS) $(CFLAGS) $(LDFLAGS) $(DEBUGFLAGS) -o $(BASE_TARGET) $(BASE_OBJECTS)

$(SHIM_TARGET): $(SHIM_OBJECTS)
	$(CC) $(FLAGS) $(CFLAGS) $(LDFLAGS) $(DEBUGFLAGS) -o $(SHIM_TARGET) $(SHIM_OBJECTS) -L. -lqnio

$(TEST_TARGET):
	$(CC) $(FLAGS) $(CFLAGS) $(TEST_SOURCES) -o $(TEST_TARGET) -L. -lqnio

clean:
	\rm -f $(BASE_TARGET)
	\rm -f $(BASE_OBJS)
	\rm -f $(SHIM_TARGET)
	\rm -f $(SHIM_OBJS)
	\rm -f $(TEST_TARGET)
	\rm -f $(TEST_OBJS)

