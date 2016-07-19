all:

SHELL = /bin/sh
CC    = gcc

CPPFLAGS     = -Iinclude
CFLAGS       = -fPIC -fno-strict-aliasing -Wall -Werror -g -pthread
DEPFLAGS     = -MMD -MP -MT $@ -MF $(@D)/$(*F).d
LDFLAGS      = -shared
DEBUGFLAGS   = -O0 -D_DEBUG -D_REENTRANT
RELEASEFLAGS = -03 -D_REENTRANT

HEADERS = $(shell echo include/*.h)

BASE_TARGET = libqnio.so
BASE_SOURCES = $(shell echo lib/qnio/*.c) 
BASE_OBJS = $(shell echo lib/qnio/*.o lib/qnio/*.d)
BASE_OBJECTS = $(BASE_SOURCES:.c=.o)
-include $(BASE_SOURCES:.c=.d)

SHIM_TARGET = libqnioshim.so
SHIM_SOURCES = $(shell echo lib/qnioshim/*.c) 
SHIM_OBJS = $(shell echo lib/qnioshim/*.o lib/qnio/*.d)
SHIM_OBJECTS = $(SHIM_SOURCES:.c=.o)
-include $(SHIM_SOURCES:.c=.d)

TEST_TARGET = qnio_server 
TEST_SOURCES = $(shell echo test/*.c)
TEST_OBJS = $(shell echo test/*.o lib/qnio/*.d)
TEST_OBJECTS = $(TEST_SOURCES:.c=.o)
-include $(TEST_SOURCES:.c=.d)

all: $(BASE_TARGET) $(SHIM_TARGET) $(TEST_TARGET)

.c.o:
	$(CC) $(CFLAGS) $(CPPFLAGS) $(DEPFLAGS) -c -o $@ $<

$(BASE_TARGET): $(BASE_OBJECTS)
	$(CC) $(FLAGS) $(CFLAGS) $(LDFLAGS) $(DEBUGFLAGS) -o $(BASE_TARGET) $(BASE_OBJECTS)

$(SHIM_TARGET): $(SHIM_OBJECTS)
	$(CC) $(FLAGS) $(CFLAGS) $(LDFLAGS) $(DEBUGFLAGS) -o $(SHIM_TARGET) $(SHIM_OBJECTS) -L. -lqnio

$(TEST_TARGET): $(TEST_OBJECTS)
	$(CC) $(FLAGS) $(CFLAGS) $(DEBUGFLAGS) -o $(TEST_TARGET) $(TEST_OBJECTS) -L. -lqnio

clean:
	\rm -f $(BASE_TARGET)
	\rm -f $(BASE_OBJS)
	\rm -f $(SHIM_TARGET)
	\rm -f $(SHIM_OBJS)
	\rm -f $(TEST_TARGET)
	\rm -f $(TEST_OBJS)

