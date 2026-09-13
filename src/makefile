CC ?= gcc
CFLAGS ?= -fPIC -Wall -Wextra -O3 -pthread
YASM ?= yasm

all: bin/vanity-hash

bin/vanity-hash: obj/linux/sha256_avx1.o obj/linux/sha256_avx2_rorx2.o obj/linux/sha256_avx2_rorx8.o obj/linux/sha256_sse4.o obj/linux/sha256_sha.o obj/linux/main.o
	mkdir -p bin
	$(CC) $(CFLAGS) -z noexecstack -o bin/vanity-hash $^ -lm -lpthread

obj/linux/%.o: asm/%.asm
	mkdir -p obj/linux
	$(YASM) -f x64 -f elf64 -X gnu -g dwarf2 -D LINUX -o $@ $<

obj/linux/sha256_sha.o: asm/sha256_sha.asm.S
	mkdir -p obj/linux
	$(CC) $(CFLAGS) -c -o $@ $<

obj/linux/main.o: main.c d2fastlib.h utils.c sha256.c
	mkdir -p obj/linux
	$(CC) $(CFLAGS) -c -o $@ main.c

clean:
	-rm -rf bin obj

.PHONY: all clean
