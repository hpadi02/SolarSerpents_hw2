# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -Werror -O2

# OpenSSL linking: prefer pkg-config (which may provide include/link flags),
# but fall back to explicitly linking libssl and libcrypto if pkg-config is
# not present. On Linux this usually works; on Windows (MinGW/MSYS) you may
# need to install the mingw-w64 OpenSSL package and adjust LDFLAGS to link
# against the MinGW-provided libraries (or build in WSL to avoid Windows
# portability work).
PKG_OPENSSL := $(shell pkg-config --libs openssl 2>/dev/null || true)
ifeq ($(PKG_OPENSSL),)
LDFLAGS = -lssl -lcrypto
else
LDFLAGS = $(PKG_OPENSSL)
endif

BIN = http_client
SRC_DIR = src
OBJ_DIR = build
SRCS = $(SRC_DIR)/http_client.c
OBJS = $(OBJ_DIR)/http_client.o

.PHONY: all clean run

all: $(BIN)

$(BIN): $(OBJ_DIR) $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

run: $(BIN)
	./$(BIN) -u https://www.w3.org/TR/2003/REC-PNG-20031110/iso_8859-1.txt -o iso_8859-1.txt

clean:
	rm -rf $(OBJ_DIR) $(BIN)


