CC=g++
TARGET=example
CPPFLAGS = -g -Wall
SRC=$(wildcard(*.c))
DIR = $(nodir $(SRC))
OBJ=$(patsubst %c,%.o,$(DIR)) 
all:$(TARGET)
$(TARGET):$(OBJ)
	$(CC) $^ -o $@
%.o: %.c
	$(CC) -c $(CPPFLAGS) $< -o $@ 
.PHONY:clean
clean:
	rm -f *.o
	rm $(TARGET)
test:
	echo $SRC
