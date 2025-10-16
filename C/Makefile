# Optimize for local machine and reduce PLT overhead
# Base flags
CC=gcc
CFLAGS?=-O3 -Wall -Wextra -Wpedantic -std=c11 -march=native -fno-plt -fomit-frame-pointer -pipe
LDFLAGS?=
LIBS=-lcrypto -lpthread

# Enable OpenCL support by setting OPENCL=1 (default is disabled to avoid requiring headers)
OPENCL?=0
ifeq ($(OPENCL),1)
  CFLAGS+=-DME_KEYGEN_OPENCL
  LIBS+=-lOpenCL
  OCL_SRCS=opencl_keygen.c
  OCL_OBJS=$(OCL_SRCS:.c=.o)
else
  OCL_SRCS=
  OCL_OBJS=
endif

SRCS=meshtastic_keygen.c $(OCL_SRCS)
OBJS=$(SRCS:.c=.o)

all: meshtastic_keygen

meshtastic_keygen: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

debug: CFLAGS+=-g -O0
debug: meshtastic_keygen_debug

meshtastic_keygen_debug: $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f meshtastic_keygen meshtastic_keygen_debug $(OBJS)

.PHONY: all debug clean
