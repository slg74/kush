CC      = gcc
CFLAGS  = -O2 -Wall -Wextra -std=c17
LDSSL   = $(shell pkg-config --cflags --libs openssl) -lpthread

BINS    = icmp_shell dns_shell https_shell

.PHONY: all clean

all: $(BINS)

icmp_shell: icmp_shell.c
	$(CC) $(CFLAGS) -o $@ $<

dns_shell: dns_shell.c
	$(CC) $(CFLAGS) -o $@ $<

https_shell: https_shell.c
	$(CC) $(CFLAGS) -o $@ $< $(LDSSL)

clean:
	rm -f $(BINS)
