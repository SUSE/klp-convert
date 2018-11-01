CFLAGS := -g -Wall
LDFLAGS := -lelf
OBJ := klp-convert.o elf.o

ifneq ($(filter local, $(MAKECMDGOALS)),)
CFLAGS += -DLOCAL_KLP_DEFS
else
CFLAGS += -I/usr/src/linux/include/uapi
endif

local: klp-convert

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

klp-convert: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

.PHONY: clean

clean:
	rm -f *.o; rm -f klp-convert
