TARGET1 = encrypt_app
TARGET2 = decrypt_app
LIBS = ../crypto/mcryptolib.a -lm -lcrypto -lncurses -lcurl -ljansson
CC = gcc
CFLAGS = -g -Wall -I../crypto/

.PHONY: default all clean

default: $(TARGET1) $(TARGET2)
all: default

OBJECTS = $(patsubst %.c, %.o, $(wildcard *.c))
HEADERS = $(wildcard *.h)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

.PRECIOUS: $(TARGET) $(OBJECTS)

$(TARGET1): $(OBJECTS)
	$(CC) $(CFLAGS) encrypt.o utils.o -Wall $(LIBS) -o $@

$(TARGET2): $(OBJECTS)
	$(CC) $(CFLAGS) decrypt.o utils.o -Wall $(LIBS) -o $@
	-rm -f *.o

clean:
	-rm -f *.o
	-rm -f $(TARGET1) $(TARGET2)
	-rm -f encrypted_file decrypted_file
	-rm -f private_key.pem public_key.pem
