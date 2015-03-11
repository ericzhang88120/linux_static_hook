CXX=g++
TARGET=example
CPPFLAGS = -g -Wall
OBJDIR=.obj
SRC=$(wildcard(*.c))
DIR = $(nodir $(SRC))
OBJ=example.o
all:$(TARGET)
$(TARGET):$(OBJDIR) $(OBJ)
	$(CXX) -o $@ $(CPPFLAGS) $(OBJDIR)/*.o 
$(OBJ):%.o:%.c
	$(CXX) -c $< -o $(OBJDIR)/$@
$(OBJDIR):
	mkdir -p ./$@
.PHONY:clean
clean:
	rm -f $(OBJDIR)/*.o
	rm $(TARGET)
test:
	@echo $(TARGET)
