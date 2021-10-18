CC = gcc
CFLAGS = -lssl -lcrypto
BIN = discordBot
SRC = sslConnection.c
OBJS = $(SRC:.c=.o)

build:
	$(CC) -o $(BIN) $(SRC) $(CFLAGS)
