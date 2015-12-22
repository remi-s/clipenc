CC=gcc
CFLAGS=-W
LDFLAGS=-lssl -lcrypto
EXEC=clipenc
SRC=clipenc.c key_mngt.c crypto.c
OBJ=$(SRC:.c=.o)

all: $(EXEC)

clipenc: $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

#TODO : static file dependencies
#main.o: hello.h

%.o: %.c
	$(CC) -o $@ -c $< $(CFLAGS)

.PHONY: clean mrproper

clean:
	rm -rf *.o

mrproper: clean
	rm -rf $(EXEC)
