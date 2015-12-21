PROGRAM = idkex idkexd
LIBRARY = -ltepla -lgmp -lcrypto
CLIENT_SRC = keys.c idkex.c
CLIENT_OBJ = keys.o idkex.o

SERVER_SRC = keys.c idkexd.c
SERVER_OBJ = keys.o idkexd.o

CC := gcc

.PHONY: all
all: idkex idkexd

idkex: $(CLIENT_OBJ)
	$(CC) $(CFLAGS) $^ $(LIBRARY) -o $@

idkexd: $(SERVER_OBJ)
	$(CC) $(CFLAGS) $^ $(LIBRARY) -o $@

idkex.o: idkex.c
	$(CC) $(CFLAGS) -c $^

keys.o: keys.c
	$(CC) $(CFLAGS) -c $^

idkexd.o: idkexd.c
	$(CC) $(CFLAGS) -c $^

keys.c: keys.h

.PHONY: clean
clean:
	$(RM) $(PROGRAM) keys.o idkexd.o idkex.o
