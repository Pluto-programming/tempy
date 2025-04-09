CC=g++
CFLAGS=-Wall -Werror -g -I/opt/homebrew/opt/openssl@3/include
LDFLAGS=-L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto

.PHONY: all clean

all: client-server

client-server: main.o
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

main.o: main.cpp
	$(CC) $(CFLAGS) -c main.cpp

clean:
	rm -f *.o client-server
