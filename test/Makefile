
GCC = gcc
G++ = g++

default:blk-test stack_bio

blk-test: blk-test.cpp
	$(G++) $(CFLAGS) $< -o $@ $(LFLAGS) 

stack-bio: stack_bio.cpp
	$(G++) $(CFLAGS) $< -o $@ $(LFLAGS) 
.PHONY: clean

clean:
	-rm -f *~ *.o blk-test

