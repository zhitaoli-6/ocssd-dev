default:../bin/rw_test ../bin/oss-cli

GCC = gcc
GXX = g++
CFLAGS = 
LFLAGS = -llightnvm

../bin/rw_test:rw_test.c
	$(GCC) $(CFLAGS) $< -o $@ $(LFLAGS) 

../bin/oss-cli:cli.cpp oss.h
	$(GXX) $(CPPFLAGS) $< -o $@ $(LFLAGS) 

clean:
	$(RM) ../bin/* *.o
	
