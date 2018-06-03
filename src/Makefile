default:../bin/rw_test ../bin/oss-cli

GCC = gcc
GXX = g++
CFLAGS = 
LFLAGS = -llightnvm

../bin/rw_test:rw_test.c
	$(GCC) $(CFLAGS) $< -o $@ $(LFLAGS) 
oss.o:oss.cpp
	$(GXX) $(CPPFLAGS) -c $< -o $@

../bin/oss-cli:cli.cpp oss.h oss.o
	$(GXX) $(CPPFLAGS) $< -o $@ oss.o $(LFLAGS) 

clean:
	$(RM) ../bin/* *.o
	
