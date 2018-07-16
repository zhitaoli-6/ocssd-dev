#include <stdio.h>
#include <string.h>
#include <liblightnvm.h>
#include <pthread.h>
#include <assert.h>
#include "common.h"
#include "test-tool.h"

#define MB (1<<20)
#define DEBUG(msg) \
    do { \
        fprintf(stderr, "FATAL ERROR: %s (%s: Line %d)\n", \
                msg, __FILE__, __LINE__); \
    }while(0)

static char nvm_dev_path[NVM_DEV_PATH_LEN] = "/dev/nvme0n1";

static struct nvm_dev *dev;
static const struct nvm_geo *geo;
static int pmode;

int setup(void)
{
    dev = nvm_dev_open(nvm_dev_path);
    if (!dev) {
        perror("nvm_dev_open");
        return -1;
    }
    geo = nvm_dev_get_geo(dev);
    //pmode = nvm_dev_get_pmode(dev);
    pmode = 0;
    return 0;
}

struct result_per_thread{
    uint64_t io_count;
    double elapse;
    int ret;
    char padding[44];
};

struct work_args{
    struct nvm_addr *addrs;
    struct nvm_addr blk_addr;
    struct result_per_thread *result;
    OPMODE_T op;
    int iters;
    int id;
};



void* sim_random_req(void *void_args){
    struct work_args* args = void_args;
    struct nvm_addr blk_addr = args->blk_addr;
    struct nvm_addr *addrs = args->addrs;
    struct nvm_ret ret;
    OPMODE_T op = args->op;
    printf("thread %d begin\n", args->id);
    //nvm_addr_pr(args->blk_addr);
    
    int iters = args->iters;
    
    //assert(geo->nchannels == 2 && geo->nluns == 8);
    //int naddr = geo->nplanes  * geo->nsectors;
    int naddr = geo->nsectors;

    char *buf = nvm_buf_alloc(geo, naddr * geo->sector_nbytes);
    if(!buf) {
        printf("not enough memory\n");
        return NULL;
    }
    nvm_buf_fill(buf, naddr * geo->sector_nbytes);

    double elapse = 0.0;
    struct timeval t1, t2;

    int iter = 0;
    while(iter < iters){
        int magic = iter;
        //int magic = rand() % 32;
        //int ch = magic % geo->nchannels;
        //int lun = magic % geo->nluns;
        //int blk = 0;
        int ch = blk_addr.g.ch;
        int lun = blk_addr.g.lun;
        int blk = blk_addr.g.blk;
        int pg = magic % geo->npages;

        for(int i = 0; i < naddr; i++){
            addrs[i].ppa = 0;
            addrs[i].g.ch = ch; 
            addrs[i].g.lun = lun;
            addrs[i].g.blk = blk;
            addrs[i].g.pg = pg;
            addrs[i].g.pl = i / geo->nsectors;
            addrs[i].g.sec = i % geo->nsectors;
        }
        int res = 0;
        gettime(&t1, NULL);
        if(op == WRITE)
            res = nvm_addr_write(dev, addrs, naddr, buf, NULL, pmode, &ret);
        else if(op == READ){
            res = nvm_addr_read(dev, addrs, naddr, buf, NULL, pmode, &ret);
        }
        gettime(&t2, NULL);
        elapse += TIMEs(t1, t2);
        if(res < 0){
            DEBUG("Read/Write failure: command error");
            return NULL;
        }
        //printf("page %d is ok\n", pg);
        iter ++;
    }
    args->result->ret = 0;
    args->result->io_count = iters;
    args->result->elapse = elapse;
    free(buf);
    return NULL;
}


void usage(){
    printf("./rw_perf thread_count(1..16) read/write\n");
}



int main(int argc, char **argv)
{
    assert(argc == 3);
    //printf("%lu\n", sizeof(struct result_per_thread));
    assert(sizeof(struct result_per_thread) == 64);
    int npu = atoi(argv[1]);
    assert(npu >= 1 && npu <= 16);
    OPMODE_T op = READ;
    if(strcmp("read", argv[2]) == 0) op = READ ;
    else if(strcmp("write", argv[2]) == 0) op = WRITE;
    else {
        usage();
        return 0;
    }
    
    if(setup() < 0) return -1;
    //nvm_dev_pr(dev);
    //int npu = geo->nchannels * geo->nluns;
    
    struct nvm_addr addrs[NVM_NADDR_MAX];
    struct nvm_addr blk_addr[npu];
    struct nvm_ret  ret;
    /* Erase */
    printf("Erase block 0 on every PU\n");
    for(int i = 0; i < npu; i++) {
        blk_addr[i].ppa = 0;
        blk_addr[i].g.ch = i % geo->nchannels;
        blk_addr[i].g.lun = i / geo->nchannels;
        blk_addr[i].g.blk = 0;
        if (pmode) {
            addrs[0].ppa = blk_addr[i].ppa;
        } else {
            for (size_t pl = 0; pl < geo->nplanes; ++pl) {
                addrs[pl].ppa = blk_addr[i].ppa;
                addrs[pl].g.pl = pl;
            }
        }
        int res = nvm_addr_erase(dev, addrs, pmode ? 1 : geo->nplanes, pmode, &ret);
        if (res < 0) {
            DEBUG("Erase failure");
            return 0;
        }
    }
    printf("begin %d io threads\n", npu);
    struct nvm_addr thread_blk_addr[npu];
    struct work_args args[npu];
    pthread_t* workers = (pthread_t *)malloc(sizeof(pthread_t) * npu);
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    struct timeval t1, t2;
    gettime(&t1, NULL);
    int iters = 32;
    for(int i = 0; i < npu; i++){
        args[i].blk_addr = blk_addr[i];
        args[i].id = i;
        args[i].addrs = (struct nvm_addr*)malloc(NVM_NADDR_MAX * sizeof(struct nvm_addr));
        args[i].result = (struct result_per_thread*)malloc(sizeof(struct result_per_thread));
        memset(args[i].result, 0, sizeof(struct result_per_thread));
        args[i].result->ret = -1;
        args[i].op = op;
        args[i].iters = iters;
        pthread_create(&workers[i], &attr, sim_random_req, &args[i]);
    }

    for(int i = 0; i < npu; i++){
        pthread_join(workers[i], NULL);
    }
    gettime(&t2, NULL);

    for(int i = 0; i < npu; i++){
        nvm_addr_pr(args[i].blk_addr);
        if(args[i].result->ret == 0){
            int iocnt = args[i].result->io_count;
            double elapse = args[i].result->elapse;
            printf("avg latency %.6fus. bindwidth %.2fMB/s\n", elapse*1000000/iocnt, iocnt * geo->nplanes * geo->page_nbytes / elapse / 1000000);
        }
        else printf("error in this block\n");
    }
    printf("total bindwidth %.2fMB/s\n", 1ll * npu * iters * geo->nplanes * geo->page_nbytes / TIMEs(t1, t2) / 1000000 );

    nvm_dev_close(dev);
    for(int i = 0; i < npu;i ++) {
        free(args[i].addrs);
        free(args[i].result);
    }
    free(workers);
    return 0;
}
