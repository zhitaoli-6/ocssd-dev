
GCC = gcc
G++ = g++

default:blk-test 

blk-test: blk-test.cpp
	$(G++) $(CFLAGS) $< -o $@ $(LFLAGS) 

.PHONY: clean

clean:
	-rm -f *~ *.o blk-test

