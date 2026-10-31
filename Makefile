PS5_PAYLOAD_SDK ?= /opt/ps5-payload-sdk
CC := $(PS5_PAYLOAD_SDK)/bin/prospero-clang
CFLAGS := -O2 -Wall -Wno-unused-function

STUB := src/break_hv_payload

all: bin/ps5dump-12xx.elf bin/byepervisor-12xx.elf

bin/ps5dump-12xx.elf: src/ps5dump-12xx.c
	$(CC) $(CFLAGS) -Werror -lkernel_sys -o $@ $<

$(STUB)/break_hv.h: $(STUB)/break_hv.c $(STUB)/entry.S $(STUB)/link.ld $(STUB)/build.sh
	sh $(STUB)/build.sh
	rm -f $(STUB)/break_hv.o $(STUB)/entry.o $(STUB)/break_hv.elf $(STUB)/break_hv.bin

bin/byepervisor-12xx.elf: src/main.c src/kdlsym.c src/khook.c src/paging.c src/util.c include/offsets/*.h $(STUB)/break_hv.h
	$(CC) $(CFLAGS) -Iinclude -lSceSystemService -o $@ src/main.c src/kdlsym.c src/khook.c src/paging.c src/util.c

clean:
	rm -f bin/*.elf
	rm -f $(STUB)/break_hv.h $(STUB)/break_hv.bin $(STUB)/break_hv.elf $(STUB)/*.o

.PHONY: all clean
