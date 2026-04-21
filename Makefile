CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic -Werror -D_POSIX_C_SOURCE=200809L -Iinclude
LDFLAGS ?=

SRC := $(sort $(wildcard src/*.c))
OBJ := $(SRC:.c=.o)
BIN := trustprobe
RULES_TEST_BIN := tests/rules_parser
POLICY_TEST_BIN := tests/policy_parser
FIRMWARE_TEST_BIN := tests/firmware_parsers
FIRMWARE_OWNERSHIP_TEST_BIN := tests/firmware_ownership
SILICON_TEST_BIN := tests/silicon_parsers
STORAGE_TEST_BIN := tests/storage_parsers
RUNTIME_TEST_BIN := tests/runtime_capture

.PHONY: all clean run help-check parser-test policy-test firmware-test firmware-ownership-test silicon-test storage-test runtime-test

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(OBJ) -o $@ $(LDFLAGS)

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

parser-test: $(RULES_TEST_BIN)
	./$(RULES_TEST_BIN)

policy-test: $(POLICY_TEST_BIN)
	./$(POLICY_TEST_BIN)

firmware-test: $(FIRMWARE_TEST_BIN)
	./$(FIRMWARE_TEST_BIN)

firmware-ownership-test: $(FIRMWARE_OWNERSHIP_TEST_BIN)
	./$(FIRMWARE_OWNERSHIP_TEST_BIN)

silicon-test: $(SILICON_TEST_BIN)
	./$(SILICON_TEST_BIN)

storage-test: $(STORAGE_TEST_BIN)
	./$(STORAGE_TEST_BIN)

runtime-test: $(RUNTIME_TEST_BIN)
	./$(RUNTIME_TEST_BIN)

$(RULES_TEST_BIN): tests/rules_parser.c src/usbguard_rules.c include/usbguard_rules.h
	$(CC) $(CFLAGS) tests/rules_parser.c src/usbguard_rules.c -o $@

$(POLICY_TEST_BIN): tests/policy_parser.c src/runtime.c include/runtime.h
	$(CC) $(CFLAGS) tests/policy_parser.c src/runtime.c -o $@

$(FIRMWARE_TEST_BIN): tests/firmware_parsers.c src/firmware_parsers.c include/firmware_parsers.h
	$(CC) $(CFLAGS) tests/firmware_parsers.c src/firmware_parsers.c -o $@

$(FIRMWARE_OWNERSHIP_TEST_BIN): tests/firmware_ownership.c src/firmware_ownership.c src/runtime.c src/firmware_parsers.c include/firmware_ownership.h include/runtime.h include/firmware_parsers.h
	$(CC) $(CFLAGS) tests/firmware_ownership.c src/firmware_ownership.c src/runtime.c src/firmware_parsers.c -o $@

$(SILICON_TEST_BIN): tests/silicon_parsers.c src/silicon_parsers.c src/runtime.c include/silicon_parsers.h include/runtime.h
	$(CC) $(CFLAGS) tests/silicon_parsers.c src/silicon_parsers.c src/runtime.c -o $@

$(STORAGE_TEST_BIN): tests/storage_parsers.c src/storage_parsers.c include/storage_parsers.h
	$(CC) $(CFLAGS) tests/storage_parsers.c src/storage_parsers.c -o $@

$(RUNTIME_TEST_BIN): tests/runtime_capture.c src/runtime.c include/runtime.h
	$(CC) $(CFLAGS) tests/runtime_capture.c src/runtime.c -o $@

run: $(BIN)
	./$(BIN)

help-check: $(BIN)
	./$(BIN) --help >/dev/null

clean:
	rm -f src/*.o $(BIN) $(RULES_TEST_BIN) $(POLICY_TEST_BIN) $(FIRMWARE_TEST_BIN) $(FIRMWARE_OWNERSHIP_TEST_BIN) $(SILICON_TEST_BIN) $(STORAGE_TEST_BIN) $(RUNTIME_TEST_BIN)
