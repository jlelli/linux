# SPDX-License-Identifier: GPL-2.0

TEST_GEN_PROGS := runner

# override lib.mk's default rules
OVERRIDE_TARGETS := 1
include ../../lib.mk

CFLAGS += -Wall -O2 -g -pthread

OUTPUT_DIR := $(OUTPUT)

# Utility object files
UTIL_OBJS :=

# Test object files (all .c files except runner.c, dl_util.c, cpuhog.c)
# Will be populated as we add tests
TEST_OBJS :=

# Runner binary links utility and test objects
$(OUTPUT)/runner: runner.c $(UTIL_OBJS) $(TEST_OBJS) dl_test.h | $(OUTPUT_DIR)
	$(CC) $(CFLAGS) -o $@ runner.c $(UTIL_OBJS) $(TEST_OBJS) $(LDFLAGS)

$(OUTPUT_DIR):
	mkdir -p $@

.PHONY: all clean

all: $(TEST_GEN_PROGS)

clean:
	rm -f $(OUTPUT)/runner
	rm -f $(OUTPUT)/*.o
	rm -f *.o
