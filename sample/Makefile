TARGET = sample
LIBS = ../crypto/mcryptolib.a -lm -lcrypto -lncurses
CC = gcc
CFLAGS = -g -Wall -I../crypto/

.PHONY: default all clean

default: $(TARGET)
all: default

OBJECTS = $(patsubst %.c, %.o, $(wildcard *.c))
HEADERS = $(wildcard *.h)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

.PRECIOUS: $(TARGET) $(OBJECTS)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) $(OBJECTS) -Wall $(LIBS) -o $@
	-rm -f *.o

clean:
	-rm -f *.o
	-rm -f $(TARGET)
