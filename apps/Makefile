default:bin/rw_perf bin/rw_func bin/oss-cli

GCC = gcc -I.
GXX = g++
CFLAGS = 
LFLAGS = -llightnvm -lpthread -fopenmp

bin/rw_perf:tests/rw_perf.c tests/test-tool.h
	$(GCC) $(CFLAGS) $< -o $@ $(LFLAGS) 
bin/rw_func:tests/rw_func.c tests/test-tool.h
	$(GCC) $(CFLAGS) $< -o $@ $(LFLAGS) 

bin/oss-cli:cli.cpp oss.h error.h bitmap.h
	$(GXX) $(CPPFLAGS) $< -o $@ $(LFLAGS) 

clean:
	$(RM) ../bin/* *.o
	
