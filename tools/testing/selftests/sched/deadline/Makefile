# SPDX-License-Identifier: GPL-2.0

TEST_GEN_PROGS := runner cpuhog

# override lib.mk's default rules
OVERRIDE_TARGETS := 1
include ../../lib.mk

CFLAGS += -Wall -O2 -g -pthread

OUTPUT_DIR := $(OUTPUT)

# Utility object files
UTIL_OBJS := $(OUTPUT)/dl_util.o

# Test object files (all .c files except runner.c, dl_util.c, cpuhog.c)
TEST_OBJS := $(OUTPUT)/basic.o $(OUTPUT)/bandwidth.o

# Runner binary links utility and test objects
$(OUTPUT)/runner: runner.c $(UTIL_OBJS) $(TEST_OBJS) dl_test.h | $(OUTPUT_DIR)
	$(CC) $(CFLAGS) -o $@ runner.c $(UTIL_OBJS) $(TEST_OBJS) $(LDFLAGS)

# cpuhog helper program
$(OUTPUT)/cpuhog: cpuhog.c | $(OUTPUT_DIR)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# Utility library
$(OUTPUT)/dl_util.o: dl_util.c dl_util.h | $(OUTPUT_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Test files
$(OUTPUT)/basic.o: basic.c dl_test.h dl_util.h | $(OUTPUT_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OUTPUT)/bandwidth.o: bandwidth.c dl_test.h dl_util.h | $(OUTPUT_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OUTPUT_DIR):
	mkdir -p $@

.PHONY: all clean

all: $(TEST_GEN_PROGS)

clean:
	rm -f $(OUTPUT)/runner $(OUTPUT)/cpuhog
	rm -f $(OUTPUT)/*.o
	rm -f *.o
