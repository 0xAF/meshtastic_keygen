CC=gcc
# Optimize for local machine and reduce PLT overhead
CFLAGS=-O3 -march=native -fno-plt -fomit-frame-pointer -pipe
LDFLAGS=-lssl -lcrypto -lpthread
TARGET=meshtastic_keygen
SRC=meshtastic_keygen.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

debug: $(SRC)
	$(CC) -g -O0 -o $(TARGET)_debug $(SRC) $(LDFLAGS)

clean:
	rm -f $(TARGET) $(TARGET)_debug
