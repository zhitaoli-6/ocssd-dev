
GCC = gcc

default: ram-disk-test

ram-disk-test: ram-dist-test.c
	$(GCC) $(CFLAGS) $< -o $@ $(LFLAGS) 

.PHONY: clean

clean:
	-rm -f *~ *.o ram-disk-test

