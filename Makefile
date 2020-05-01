MAINFILES := verify-upload.c hash-service.c
MAIN_EXECS := $(patsubst %.c, %, $(MAINFILES))
CC := gcc
CFLAGS := -Wall -Werror
LIBS := -lpthread

SRC := $(wildcard *.c)
SRC_DEPS := $(filter-out $(MAINFILES), $(wildcard *.c))

DEPS_HEADERS := $(patsubst %.c, %.h, $(SRC_DEPS))

TESTS := $(wildcard test/*.c)
TESTS_EXCLUDE := 
TESTS_EXCLUDE_PATH := $(patsubst %, test/%, $(TESTS_EXCLUDE))
TEST_ALL_EXECS := $(patsubst %.c, %, $(wildcard test/*.c))
TEST_EXECS := $(filter-out $(TESTS_EXCLUDE_PATH), $(TEST_ALL_EXECS))

all: $(MAIN_EXECS) 

.PHONY: test clean

verify-upload: verify-upload.c $(SRC_DEPS) 
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

hash-service: hash-service.c $(SRC_DEPS) 
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

tests/%: tests/%.c $(SRC_DEPS) $(DEPS_HEADERS)
	$(info $^)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

test: $(TEST_EXECS)
	for x in $(TEST_EXECS); do ./$$x || exit 1; done

clean:
	@rm -f $(MAIN_EXECS) 
	@rm -f $(TEST_ALL_EXECS)
