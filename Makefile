MAINFILE := verify-upload.c
MAIN_EXEC := $(patsubst %.c, %, $(MAINFILE))
CC := gcc
CFLAGS := -Wall -Werror
LIBS := -lpthread

SRC := $(wildcard *.c)
SRC_DEPS := $(filter-out $(MAINFILE), $(wildcard *.c))

DEPS_HEADERS := $(patsubst %.c, %.h, $(SRC_DEPS))

TESTS := $(wildcard test/*.c)
TESTS_EXCLUDE := 
TESTS_EXCLUDE_PATH := $(patsubst %, test/%, $(TESTS_EXCLUDE))
TEST_ALL_EXECS := $(patsubst %.c, %, $(wildcard test/*.c))
TEST_EXECS := $(filter-out $(TESTS_EXCLUDE_PATH), $(TEST_ALL_EXECS))

all: $(MAIN_EXEC) 

.PHONY: test clean

$(MAIN_EXEC) : $(SRC)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

tests/%: tests/%.c $(SRC_DEPS) $(DEPS_HEADERS)
	$(info $^)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

test: $(TEST_EXECS)
	for x in $(TEST_EXECS); do ./$$x || exit 1; done

clean:
	@rm -f $(MAIN_EXEC) 
	@rm -f $(TEST_ALL_EXECS)
