# Compiler
CC = gcc
CFLAGS = -Wall -Wextra -O2 -I./include
LDFLAGS = -lcrypto

# Source files
SRCS = src/bip32.c 
TEST_SRCS = tests/test_bip32.c

# Falcon library objects
FALCON_OBJS = external/falcon/falcon.o external/falcon/keygen.o external/falcon/shake.o \
              external/falcon/rng.o external/falcon/fpr.o external/falcon/fft.o \
              external/falcon/common.o external/falcon/codec.o external/falcon/sign.o \
              external/falcon/vrfy.o external/falcon/deterministic.o

# Binary name
BIN = bip32_falcon
TEST_BIN = test_bip32

.PHONY: all clean test

all: $(BIN)

test: $(TEST_BIN)

$(BIN): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(FALCON_OBJS) $(LDFLAGS)

$(TEST_BIN): $(TEST_SRCS) src/bip32.c $(FALCON_OBJS)
	$(CC) $(CFLAGS) -o $@ $(TEST_SRCS) src/bip32.c $(FALCON_OBJS) $(LDFLAGS)
