CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic -Werror -D_POSIX_C_SOURCE=200809L -Iinclude
LDFLAGS ?=

SRC := $(sort $(wildcard src/*.c))
OBJ := $(SRC:.c=.o)
BIN := trustprobe

.PHONY: all clean

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(OBJ) -o $@ $(LDFLAGS)

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f src/*.o $(BIN)
