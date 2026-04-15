CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic -Werror -D_POSIX_C_SOURCE=200809L -Iinclude
LDFLAGS ?=

SRC := $(sort $(wildcard src/*.c))
OBJ := $(SRC:.c=.o)
BIN := trustprobe
RULES_TEST_BIN := tests/rules_parser
RUNTIME_TEST_BIN := tests/runtime_capture

.PHONY: all clean run help-check parser-test runtime-test

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(OBJ) -o $@ $(LDFLAGS)

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

parser-test: $(RULES_TEST_BIN)
	./$(RULES_TEST_BIN)

runtime-test: $(RUNTIME_TEST_BIN)
	./$(RUNTIME_TEST_BIN)

$(RULES_TEST_BIN): tests/rules_parser.c src/usbguard_rules.c include/usbguard_rules.h
	$(CC) $(CFLAGS) tests/rules_parser.c src/usbguard_rules.c -o $@

$(RUNTIME_TEST_BIN): tests/runtime_capture.c src/runtime.c include/runtime.h
	$(CC) $(CFLAGS) tests/runtime_capture.c src/runtime.c -o $@

run: $(BIN)
	./$(BIN)

help-check: $(BIN)
	./$(BIN) --help >/dev/null

clean:
	rm -f src/*.o $(BIN) $(RULES_TEST_BIN) $(RUNTIME_TEST_BIN)
