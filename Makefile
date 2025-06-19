PROG_NAME   := prefetch_hint
KERN_SRC    := $(PROG_NAME).ebpf.c
USER_SRC    := user.ebpf.c
ARCH        ?= x86

CLANG       := clang
PKG_CONFIG  ?= pkg-config

KERN_CFLAGS := \
  -O2 -g -v                                 \
  -target bpf                               \
  -Wall -Werror                             \
  -D__TARGET_ARCH_$(ARCH)                   \
  -I.
  
USER_CFLAGS := -O2 -g -v -Wall -Wextra
USER_LDFLAGS := $(shell $(PKG_CONFIG) --libs libbpf libelf zlib) -lelf -lz

KERN_OBJ    := $(KERN_SRC:.c=.o)

all: $(KERN_OBJ) $(PROG_NAME)

$(KERN_OBJ): $(KERN_SRC)  
	$(CLANG) $(KERN_CFLAGS) -c $< -o $@

$(PROG_NAME): $(USER_SRC)
	$(CLANG) $(USER_CFLAGS) $< -o $@ $(USER_LDFLAGS)

.PHONY: run clean

clean:
	rm $(KERN_OBJ) $(PROG_NAME)
