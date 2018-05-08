TARGET = mcryptolib.a
LIBS =
CC = gcc
AR = ar
RANLIB = ranlib
CFLAGS = -g -Wall

.PHONY: default all clean

default: $(TARGET)
all: default

OBJECTS = $(patsubst %.c, %.o, $(wildcard *.c))
HEADERS = $(wildcard *.h)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

.PRECIOUS: $(TARGET) $(OBJECTS)

$(TARGET): $(OBJECTS)
	$(AR) rc $@ $(OBJECTS)
	-rm -f *.o

clean:
	-rm -f *.o
	-rm -f $(TARGET)
