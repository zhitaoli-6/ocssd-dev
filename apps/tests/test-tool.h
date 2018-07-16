#include <stdio.h>
#include <liblightnvm.h>

void hello(){
    printf("hello\n");
}

enum OPMODE {
    READ = 0x0,
    WRITE = 0x1
};

typedef enum OPMODE OPMODE_T;

enum SCALE{
   SEQ = 0x0,
   RANDOM = 0x1
};



size_t compare_buffers(char *expected, char *actual, size_t nbytes)
{
    size_t diff = 0;

    for (size_t i = 0; i < nbytes; ++i) {
        if (expected[i] != actual[i]) {
            ++diff;
        }
    }

    printf("diff %lu/%lu\n", diff, nbytes);
    return diff;
}

void print_mismatch(char *expected, char *actual, size_t nbytes)
{
    printf("MISMATCHES:\n");
    for (size_t i = 0; i < nbytes; ++i) {
        if (expected[i] != actual[i]) {
            printf("i(%06lu), expected(%c) != actual(%02d|0x%02x|%c)\n",
                    i, expected[i], (int)actual[i], (int)actual[i], actual[i]);
        }
    }
}
void print_meta(char *buf, int nbytes, int meta_nbytes){
    for(int i = 0; i < nbytes; i+=meta_nbytes){
        for(int j = 0; j < meta_nbytes; j++)
            printf("%c", buf[i+j]);
        printf("\n");
    }
}
