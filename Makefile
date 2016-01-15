CC=gcc
INSTALL=install

CFLAGS=-W
LDFLAGS=-lssl -lcrypto

prefix = /usr/local
bindir = $(prefix)/bin

BINFILES=clipenc
SCRIPTFILES=c_enc c_dec c_gen
SRC=clipenc.c key_mngt.c crypto.c erase.c
OBJ=$(SRC:.c=.o)


all: $(BINFILES)

clipenc: $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

#TODO : static file dependencies
#main.o: hello.h

%.o: %.c
	$(CC) -o $@ -c $< $(CFLAGS)

install:
	$(INSTALL) -d $(DESTDIR)$(bindir)
	$(INSTALL) -m 755 $(BINFILES) $(SCRIPTFILES) $(DESTDIR)$(bindir)


.PHONY: clean

clean:
	rm -rf *.o $(BINFILES)

