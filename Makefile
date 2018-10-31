CFLAGS := -g -Wall -I/usr/src/linux/include/uapi
LDFLAGS := -lelf
OBJ := klp-convert.o elf.o

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

klp-convert: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

.PHONY: clean

clean:
	rm -f *.o; rm -f klp-convert
