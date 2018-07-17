
GCC = gcc

default:blk-test 

blk-test: ram-disk-test.c
	$(GCC) $(CFLAGS) $< -o $@ $(LFLAGS) 

.PHONY: clean

clean:
	-rm -f *~ *.o blk-test

