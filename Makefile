CXX=g++
TARGET=hook.so
CPPFLAGS=-w -fPIC --shared
SRC=hook.c func.c
OBJ=$(SRC:.c=.o)
all:$(TARGET)
$(TARGET):$(OBJ)
	$(CXX) $(CPPFLAGS) -o $@ $^ 
$(OBJ):%.o:%.c
	$(CXX) $(CPPFLAGS) -c $< -o $@ 
.PHONY:clean
clean:
	-rm -f *.o
	-rm ./example/$(TARGET)
	-rm $(TARGET)
