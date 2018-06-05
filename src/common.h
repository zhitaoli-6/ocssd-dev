#ifndef COMMON
#define COMMON
#include <sys/time.h>
#include <math.h>
#define gettime gettimeofday
#define TIMEs(a,b) (1.0*((b).tv_sec-(a).tv_sec)+0.000001*((b).tv_usec-(a).tv_usec))
#define TIMEus(a,b) (1ll * 1000000 *((b).tv_sec-(a).tv_sec)+((b).tv_usec-(a).tv_usec))
#include <stdlib.h>

float random_float(){
    return 1.0f * rand() / RAND_MAX;
}

#define EXIT(msg) \
    do { \
        fprintf(stderr, "FATAL: %s (%s: Line %d)\n", \
                msg, __FILE__, __LINE__); \
        exit(1); \
    } while(0)



#endif
