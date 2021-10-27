CC     = gcc
CFLAGS = -lssl -lcrypto
BIN    = discordBot-bin
SRC    = src/main.c \
		 src/discord-for-c.c \
		 src/discord-for-c.h \
		 src/internet-protocols/https/ssl-tsl-connection.c \
		 src/internet-protocols/https/ssl-tsl-connection.h \
		 src/internet-protocols/https/requests.c \
		 src/internet-protocols/https/requests.h \
		 src/extras/colors-terminal.h

OBJS   = $(SRC:.c=.o)
CFLAGS_VERBOSE = -Wall
VERBOSE = true

DEBUG ?= 0
ifeq ($(DEBUG), 1)
CFLAGS += $(CFLAGS_VERBOSE)
endif

build:
	$(CC) -o $(BIN) $(SRC) $(CFLAGS)
