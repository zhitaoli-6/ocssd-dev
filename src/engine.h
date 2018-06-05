#ifndef __ENGINE
#define __ENGINE
#include "liblightnvm.h"
#include "bitmap.h"

enum OSS_TYPE{
    OSS_STRIPE = 0x0,
    OSS_REPLICA = 0x1,
    OSS_EC = 0x2
};

struct block_meta_t{
    struct nvm_addr blk_addr;
    block_meta_t* next;
    block_meta_t* group_next;
    int devno;
};

class storage_engine{
public:
    storage_engine(){}
    storage_engine(OSS_TYPE type){
        engine_type = type;
        devno = 0;
        this->ndevs = 0;
        this->nblocks = 0;
        this->geo = NULL;
    }
    struct block_meta_t* alloc_block(bitmap_t** blk_map){
        switch(engine_type){
            case OSS_STRIPE:
                return _stripe_alloc_block(blk_map);
            case OSS_REPLICA:
                return _replica_alloc_block(blk_map);
            default:
                return NULL;
        }
    }
private:
    struct block_meta_t* _stripe_alloc_block(bitmap_t** blk_map);
    struct block_meta_t* _replica_alloc_block(bitmap_t** blk_map);

public:
    OSS_TYPE engine_type;
    int devno;
    int ndevs;
    int nblocks;
    const struct nvm_geo* geo;
};

struct block_meta_t* storage_engine::_stripe_alloc_block(bitmap_t** blk_map){
    struct block_meta_t* blk = NULL;
    int no = devno;
    for(int i=0; i < nblocks; i++){
        if(get_bit(blk_map[no], i) == 0){
            set_bit(blk_map[no], i);
            blk = (block_meta_t*)malloc(sizeof(block_meta_t));
            blk->blk_addr.ppa = 0;
            blk->blk_addr.g.ch = i / (geo->nluns * geo->nblocks);
            blk->blk_addr.g.lun = (i / geo->nblocks) % geo->nluns;
            blk->blk_addr.g.blk = i % geo->nblocks;
            blk->next = NULL;
            blk->group_next = NULL;
            blk->devno = no;
            //printf("alloc block:");
            //nvm_addr_pr(blk->blk_addr);
            devno = (devno + 1) % ndevs;
            return blk;
        }
    }
    return blk;
}
struct block_meta_t* storage_engine::_replica_alloc_block(bitmap_t** blk_map){
    if(ndevs != 3) return NULL;
    block_meta_t* head = NULL;
    int replica_count = 0;
    for(int no = 0; no < ndevs; no++){
        for(int i=0; i < nblocks; i++){
            if(get_bit(blk_map[no], i) == 0){
                set_bit(blk_map[no], i);
                block_meta_t* blk = (block_meta_t*)malloc(sizeof(block_meta_t));
                blk->blk_addr.ppa = 0;
                blk->blk_addr.g.ch = i / (geo->nluns * geo->nblocks);
                blk->blk_addr.g.lun = (i / geo->nblocks) % geo->nluns;
                blk->blk_addr.g.blk = i % geo->nblocks;
                blk->next = NULL;
                blk->group_next = head;
                head = blk;
                replica_count ++;
                blk->devno = no;
                break;
            }
        }
    }
    // make sure 3 replica ready
    if(replica_count != 3){
        while(head){
            clear_bit(blk_map[head->devno], 
                    head->blk_addr.g.ch * (geo->nluns * geo->nluns)
                    + head->blk_addr.g.lun * geo->nblocks 
                    + head->blk_addr.g.blk);
            void* ptr = head;
            head = head->next;
            free(ptr);
        }
    }
}


#endif
