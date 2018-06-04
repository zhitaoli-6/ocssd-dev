#include "oss.h"

#include <time.h>

oid_t seq_no;

#define MAX_BYTES (1<<24)


oid_t get_oid(){
    return seq_no++;
}


void buf_fill(char* buf, int len){
   for(int i = 0; i < len; i++) buf[i] = 'A' + (rand()%26);
}


struct cli_data_t{
    char* ptr;
    int len;
    cli_data_t(){}
    cli_data_t(char* buf, int l):ptr(buf),len(l){}
};



int main(){
    oss_t oss(1);
    oss.setup();

    //srand(time(0));
    srand(0);
    seq_no = 0;
    int ntimes = 65;
    char* buf;
    map<oid_t, cli_data_t> mem_obj;
    for(int t = 0; t < ntimes; t++){
        int len = MAX_BYTES;
        //int len = rand() % (MAX_BYTES) + 1;
        buf = (char*)aligned_alloc(4096, len);
        buf_fill(buf, len);
        oid_t oid = get_oid();
        int ret = oss.oss_put(oid, buf, len);
        if(ret < 0) {
            printf("error put %lu, len %d, ret %d\n", oid, len, ret);
            continue;
        }
        mem_obj[oid] = cli_data_t(buf, len);
        //printf("----------------\n");
    }

    int expected = 0;
    map<oid_t, cli_data_t>::iterator it;
    for(it = mem_obj.begin(); it != mem_obj.end(); it++){
        buf = (char*)aligned_alloc(4096, MAX_BYTES);
        int ret = oss.oss_get(it->first, buf, MAX_BYTES);
        if(ret < 0) {
            printf("error get %lu, ret %d\n", it->first, ret); 
            continue;
        }
        if(memcmp(it->second.ptr, buf, it->second.len) != 0){
            printf("not equal between get and put %lu\n", it->first);
            continue;
        }
        expected ++;
    }
    printf("[%d/%d object succeeds]\n", expected, ntimes);
error_exit:
    for(it = mem_obj.begin(); it != mem_obj.end(); it++){
        free(it->second.ptr);
    }
out:
    return 0;
}
