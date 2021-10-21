CC = gcc
CFLAGS = -lssl -lcrypto
BIN = discordBot-bin
SRC = main.c \
	  ssl-tsl-connection.c
OBJS = $(SRC:.c=.o)

build:
	$(CC) -o $(BIN) $(SRC) $(CFLAGS)
	# export $(cat .env)
