# Optimize for local machine and reduce PLT overhead
# Base flags
CC=gcc
CFLAGS?=-O3 -Wall -Wextra -Wpedantic -std=c11 -march=native -fno-plt -fomit-frame-pointer -pipe
LDFLAGS?=
LIBS=-lcrypto -lpthread -ldl

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

all: clean meshtastic_keygen

meshtastic_keygen: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

debug: CFLAGS+=-g -O0
debug: clean meshtastic_keygen_debug

meshtastic_keygen_debug: $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f meshtastic_keygen meshtastic_keygen_debug $(OBJS)

.PHONY: all debug clean

# Optional: SIMD-optimized builds (do not change the defaults)
simd-avx2: CFLAGS+= -mavx2 -mbmi2 -madx
simd-avx2: clean meshtastic_keygen

# Some CPUs won't support AVX-512 on i7-14700K; leave as a separate opt-in target
simd-ifma: CFLAGS+= -mavx512f -mavx512dq -mavx512ifma
simd-ifma: clean meshtastic_keygen

# Optional: build and link against lib25519 (download & compile locally)
# This will not replace OpenSSL everywhere; it only switches the X25519 public-key derivation path.
# Artifacts are placed under third_party/lib25519-current (symlink to the versioned folder).

LIB25519_SUBDIR:=third_party
LIB25519_CUR:=$(LIB25519_SUBDIR)/lib25519-current
# lib25519 produces arch-specific outputs under build/$(arch)/package
# Use amd64 here; adjust if upstream changes layout.
LIB25519_ARCH:=amd64
LIB25519_PKG:=$(LIB25519_CUR)/build/$(LIB25519_ARCH)/package
LIB25519_INC:=$(LIB25519_PKG)/include
LIB25519_LIB:=$(LIB25519_PKG)/lib

.PHONY: lib25519-download lib25519-build lib25519

lib25519-download:
	@set -e; \
	mkdir -p $(LIB25519_SUBDIR); \
	wget -q -m https://lib25519.cr.yp.to/lib25519-latest-version.txt -P $(LIB25519_SUBDIR); \
	version=$$(cat $(LIB25519_SUBDIR)/lib25519.cr.yp.to/lib25519-latest-version.txt); \
	echo "lib25519 version: $$version"; \
	wget -q -m https://lib25519.cr.yp.to/lib25519-$$version.tar.gz -P $(LIB25519_SUBDIR); \
	tar -xzf $(LIB25519_SUBDIR)/lib25519.cr.yp.to/lib25519-$$version.tar.gz -C $(LIB25519_SUBDIR); \
	ln -sfn lib25519-$$version $(LIB25519_CUR)

lib25519-build: lib25519-download
	@set -e; \
	cd $(LIB25519_CUR) && ./configure --no-valgrind; \
	# Provide a minimal randombytes.h so objects that include it can compile into the static archive. \ 
	# This avoids pulling in external librandombytes since we only need dh/nP from the archive. \ 
	mkdir -p $(LIB25519_CUR)/build/$(LIB25519_ARCH)/include-build; \
	echo '/* minimal */' > $(LIB25519_CUR)/build/$(LIB25519_ARCH)/include-build/randombytes.h; \
	echo 'void randombytes(unsigned char*, unsigned long long);' >> $(LIB25519_CUR)/build/$(LIB25519_ARCH)/include-build/randombytes.h; \
	$(MAKE) -C $(LIB25519_CUR)/build/$(LIB25519_ARCH) -j$$(getconf _NPROCESSORS_ONLN || echo 8) package/lib/lib25519.a

# Build our binary using lib25519 for X25519 operations.
lib25519: CFLAGS+= -DME_USE_LIB25519 -I$(LIB25519_INC)
lib25519: LDFLAGS+= -L$(LIB25519_LIB) -Wl,-rpath,$(LIB25519_LIB)
lib25519: LIBS+= -l25519
lib25519: clean lib25519-build meshtastic_keygen
