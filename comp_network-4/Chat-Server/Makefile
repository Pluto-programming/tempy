CC=g++
CFLAGS=-Wall -Werror -std=c++11 -g -I../Include -I/opt/homebrew/opt/openssl@3/include
LDFLAGS=-L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto

.PHONY: all clean

all: chat-server

chat-server: main.o ../Src/logger.o ../Src/attack_detection.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

main.o: main.cpp
	$(CC) $(CFLAGS) -c main.cpp

clean:
	rm -f *.o chat-server
