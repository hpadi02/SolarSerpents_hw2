CC = gcc
CFLAGS = -Wall -Wextra -Werror -O2
LDFLAGS =

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


