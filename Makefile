default:bin/rw_test

CC = gcc
CFLAGS = 
LFLAGS = -llightnvm

bin/rw_test:src/rw_test.c
	$(CC) $(CFLAGS) $< -o $@ $(LFLAGS) 
clean:
	$(RM) bin/rw_test
	
