#include <sys/time.h>
#include <cstdio>

#define TIME(a,b) (1.0*((b).tv_sec-(a).tv_sec)+0.000001*((b).tv_usec-(a).tv_usec))

#define EXIT_IF_NULL(ptr) \
    do { \
        if (ptr == NULL) { \
            fprintf(stderr, "FATAL: INVALID Pointer. (%s: Line %d)\n", \
                    __FILE__, __LINE__); \
            exit(1); \
        }\
    } while(0)

#define EXIT(msg) \
    do { \
        fprintf(stderr, "FATAL: %s (%s: Line %d)\n", \
                msg, __FILE__, __LINE__); \
        exit(1); \
    } while(0)

#define SECTOR_SIZE	(4096)
#define DEVICE_NAME	"/dev/pblk_md"


#define O_RAND (1)

#define W_PAGE_CNT (1ll*4096)
#define R_PAGE_CNT (1ll*4096)

void rand_data(char *buf, int size)
{
	for(int i = 0; i < size; i++)
		buf[i] = rand() % 26 + 'a';
}
