
GCC = gcc
G++ = g++

default:blk-test blk-read blk-write stack-bio

blk-test: blk-test.cpp common.h
	$(G++) $(CFLAGS) $< -o $@ $(LFLAGS) 

blk-read: blk-read.cpp common.h
	$(G++) $(CFLAGS) $< -o $@ $(LFLAGS) 

blk-write: blk-write.cpp common.h
	$(G++) $(CFLAGS) $< -o $@ $(LFLAGS) 

stack-bio: stack_bio.cpp
	$(G++) $(CFLAGS) $< -o $@ $(LFLAGS) 

.PHONY: clean

clean:
	-rm -f *~ *.o blk-test stack-bio blk-read blk-write

