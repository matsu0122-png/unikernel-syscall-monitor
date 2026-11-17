CFLAGS ?= -O2 -g -Wall -Wextra

libvmitrap.so: libvmitrap.c
	$(CC) $(CFLAGS) -fPIC -shared -o $@ $< -ldl -lpthread

clean:
	rm -f libvmitrap.so

.PHONY: clean
