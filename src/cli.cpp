#include "oss.h"

#include <time.h>

oid_t seq_no;

#define MAX_BYTES (1<<24)


#define MB (1<<20)


oid_t get_oid(){
    return seq_no++;
}


void buf_fill(char* buf, int len){
   for(int i = 0; i < len; i++) buf[i] = 'A' + (rand()%26);
   //for(int i = 0; i < len; i++) buf[i] = 'D';
}


struct cli_data_t{
    char* ptr;
    int len;
    cli_data_t(){}
    cli_data_t(char* buf, int l):ptr(buf),len(l){}
};



int main(){
    oss_t oss(3, OSS_STRIPE);
    if(oss.setup() < 0) return 0;

    srand(0);
    //srand(time(0));
    seq_no = 0;
    int ntimes = 64;
    char* buf;
    map<oid_t, cli_data_t> mem_obj;
    //for(int t = 0; t < ntimes; t++){
    uint64_t total_nbytes = 0;
    int obj_cnt = 0;
    char errstr[128];
    struct timeval t1, t2;
    gettimeofday(&t1, NULL);
    while(true){
        int len = MAX_BYTES;
        //int len = rand() % (MAX_BYTES) + 1;
        //int len = 14215666;
        total_nbytes += len;
        buf = (char*)aligned_alloc(4096, len);
        if(!buf){
            printf("host does not have enough memory\n");
            break;
        }
        buf_fill(buf, len);
        oid_t oid = get_oid();
        int ret = oss.oss_put(oid, buf, len);
        if(ret < 0) {
            printf("error put %lu, len %d, ret %d, %s\n", oid, len, ret, oss_perror(ret, errstr));
            printf("total object size %lu\n", total_nbytes);
            if(ret == ENOSPACE){
                //printf("total object size %d\n", total_nbytes);
            }
            break;
        }
        mem_obj[oid] = cli_data_t(buf, len);
        obj_cnt ++;
        //printf("----successfully put oid %lu with len %d\n", oid, len);
    }
    gettime(&t2, NULL);
    printf("put bindwidth %.2fMB/s\n", total_nbytes * 1.0 / MB / TIMEs(t1,t2));

    int expected = 0;
    map<oid_t, cli_data_t>::iterator it;
    buf = (char*)aligned_alloc(4096, MAX_BYTES);
    for(it = mem_obj.begin(); it != mem_obj.end(); it++){
        int ret = oss.oss_get(it->first, buf, it->second.len);
        if(ret < 0) {
            printf("error get %lu, ret %d, %s\n", it->first, ret, oss_perror(ret, errstr)); 
            continue;
        }
        if(memcmp(it->second.ptr, buf, it->second.len) != 0){
            printf("not equal between get and put %lu\n", it->first);
            continue;
        }
        expected ++;
    }
    gettime(&t1, NULL);
    printf("get bindwidth %.2fMB/s\n", total_nbytes * 1.0 / MB / TIMEs(t2,t1));
    free(buf);
    printf("[%d/%d object succeeds]\n", expected, obj_cnt);
error_exit:
    for(it = mem_obj.begin(); it != mem_obj.end(); it++){
        free(it->second.ptr);
    }
out:
    return 0;
}
