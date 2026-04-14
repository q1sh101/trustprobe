CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic -Werror -D_POSIX_C_SOURCE=200809L -Iinclude
LDFLAGS ?=

SRC := $(sort $(wildcard src/*.c))
OBJ := $(SRC:.c=.o)
BIN := trustprobe
RUNTIME_TEST_BIN := tests/runtime_capture

.PHONY: all clean run help-check runtime-test

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(OBJ) -o $@ $(LDFLAGS)

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

runtime-test: $(RUNTIME_TEST_BIN)
	./$(RUNTIME_TEST_BIN)

$(RUNTIME_TEST_BIN): tests/runtime_capture.c src/runtime.c include/runtime.h
	$(CC) $(CFLAGS) tests/runtime_capture.c src/runtime.c -o $@

run: $(BIN)
	./$(BIN)

help-check: $(BIN)
	./$(BIN) --help >/dev/null

clean:
	rm -f src/*.o $(BIN) $(RUNTIME_TEST_BIN)
