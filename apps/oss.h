#include <liblightnvm.h>
#include <iostream>
#include <cstring>
#include <map>
#include <stdint.h>
#include <assert.h>

#include "engine.h"
#include "error.h"
#include "bitmap.h"
#include "common.h"

using namespace std;

#define MAX_DEV 3

typedef uint64_t oid_t;
typedef uint64_t seq_t;

/*
typedef int (*oss_get_t)(oid_t oid, char* buf, int len);
typedef int (*oss_put_t)(char* buf, int len, oid_t* oid);
typedef int (*oss_del_t)(oid_t oid);
*/


struct index_t{
    struct nvm_dev* dev;
    // now object size is limited to block size of SSD, about 8MB.
    struct nvm_addr obj_addr;
    //struct engine_t* engine;
    int len;

    bool deleted;
};

typedef map<oid_t, index_t*> index_map_t;
typedef map<oid_t, index_t*>::iterator index_map_iter_t;

class oss_t{
private:
    index_t* _create_object(int len);
    int _get_free_space(struct nvm_addr blk_addr);
    block_meta_t* _alloc_block();

public:
    int setup();
    oss_t(int ndev, OSS_TYPE oss_type);
    ~oss_t();
    int oss_get(oid_t oid, char* buf, int len);
    int oss_put(oid_t oid, char* buf, int len); int oss_del(oid_t oid);
private:
    OSS_TYPE oss_type;
    struct nvm_dev *dev[MAX_DEV];
    int ndevs;

    // now all devices are identical
    size_t block_nbytes;
    const struct nvm_geo* geo;
    int pmode;
    int nblocks;
    block_meta_t* work_list;
    block_meta_t* full_list;

    index_map_t index_map;
    seq_t seq_no;


    // per device info
    bitmap_t* blk_map[MAX_DEV];
    
    //engine
    storage_engine engine;
};

oss_t::oss_t(int ndev, OSS_TYPE oss_type){
    this->ndevs = ndev;
    cout << "construct oss" << endl;
    switch (oss_type){
        case OSS_STRIPE:
        case OSS_REPLICA:
            this->oss_type = oss_type;
            engine = storage_engine(oss_type);
            break;
        //case OSS_EC:
        default:
            printf("not supported OSS type now\n");
    }
}
oss_t::~oss_t(){
    for(int i = 0; i < ndevs; i++)
        if(dev[i])
            nvm_dev_close(dev[i]);
    
    cout << "deconstruct oss" << endl;
}


int oss_t::setup(){
    assert(ndevs <= MAX_DEV);
    char name[128];
    for(int i = 0; i < ndevs; i++){
        sprintf(name, "/dev/nvme%01dn1", i);
        //sprintf(name, "/dev/nvme2n1");
        dev[i] = nvm_dev_open(name);
        if(!dev[i]){
            perror(name);
            return ESETUP;
        }
    }
    geo = nvm_dev_get_geo(dev[0]);
    pmode = nvm_dev_get_pmode(dev[0]);
    assert(pmode*2 == geo->nplanes);
    block_nbytes = geo->npages * geo->page_nbytes;

    nblocks = geo->nchannels * geo->nluns * geo->nblocks;
    for(int i = 0; i < ndevs; i++)
        blk_map[i] = (bitmap_t *)calloc(nblocks/8 + 1, 1);
    work_list = NULL;
    full_list = NULL;

    seq_no = 0;

    engine.ndevs = ndevs;
    engine.geo = geo;
    engine.nblocks = nblocks;

    return 0;
}

block_meta_t* oss_t::_alloc_block(){
    return engine.alloc_block(blk_map);
}

int oss_t::_get_free_space(struct nvm_addr blk_addr){
    return (geo->npages - blk_addr.g.pg - 1) * geo->page_nbytes;
}

index_t* oss_t::_create_object(int len){
    block_meta_t* blk = work_list;
    block_meta_t* pre = NULL;
    while(blk){
        if(_get_free_space(blk->blk_addr) * geo->nplanes >= len){
            break;
        }
        pre = blk;
        blk = blk->next;
    }

    if(!blk){
        blk = _alloc_block();
        if(!blk) {
            return NULL;
        }
        // insert into work_list;
        pre = NULL;
        blk->next = work_list;
        work_list = blk;
    }


    index_t* index = (index_t*)malloc(sizeof(index_t));
    index->dev = dev[blk->devno];
    index->obj_addr.ppa = blk->blk_addr.ppa;
    index->len = len;
    index->deleted = false;

    int alloc_page = (len + geo->nplanes * geo->page_nbytes - 1) / (geo->nplanes * geo->page_nbytes);
    //printf("object len %d alloc_pages %d\n", len, alloc_page);
    int pg = blk->blk_addr.g.pg;
    // delete from work_list, insert into full_list;
    if(pg + alloc_page == geo->npages){
        if(pre) pre->next = blk->next;
        else work_list = blk->next;
        blk->next = full_list;
        full_list = blk;
    }
    else{
        blk->blk_addr.g.pg += alloc_page;
        //nvm_addr_pr(blk->blk_addr);
    }

    printf("create object %dB: use %d plane-pages at dev %d.",index->len, alloc_page, blk->devno);
    printf("\n");
//    nvm_addr_pr(index->obj_addr);
    return index;
} 

int oss_t::oss_get(oid_t oid, char* buf_r, int len){
    index_map_iter_t iter =  index_map.find(oid);
    if(iter != index_map.end()){
        index_t* index = iter->second;
        if(index->deleted) return ENOEXIST;
        // read from SSD

        //printf("get oid %lu len %d\n", oid, len);
        len = min(index->len, len);
        char* buf = NULL;
        if((uint64_t)buf_r % geo->sector_nbytes || len % (geo->nplanes * geo->page_nbytes)) {
            int pad_size = len;
            if(len % (geo->nplanes * geo->page_nbytes)) pad_size = (len / (geo->nplanes * geo->page_nbytes) + 1) * (geo->nplanes * geo->page_nbytes);
            buf = (char*)nvm_buf_alloc(geo, pad_size);
            if(!buf) return ENOMEMORY;
        }else buf = buf_r;

        struct nvm_addr addrs[NVM_NADDR_MAX];
        struct nvm_ret ret;
        int naddr = NVM_NADDR_MAX;
        int xfer = geo->sector_nbytes * NVM_NADDR_MAX;
        //printf("xfer size %d\n", xfer);
        int xpg = NVM_NADDR_MAX / (geo->nplanes*geo->nsectors);
        int curoff = xfer, pgoff = 0;
        int pg = index->obj_addr.g.pg;
        for(; curoff <= len ; curoff += xfer){
            for(int i = 0; i < naddr; i++){
                addrs[i].ppa = index->obj_addr.ppa;
                addrs[i].g.pl = (i / geo->nsectors) % geo->nplanes;
                addrs[i].g.pg = pg + i / (geo->nsectors * geo->nplanes) + pgoff;
                addrs[i].g.sec = i % geo->nsectors;
            }
            pgoff += xpg;
            /*
            for(int i = 0; i < NVM_NADDR_MAX; i++){
                nvm_addr_pr(addrs[i]);
            }
            */
            int res = nvm_addr_read(index->dev, addrs, naddr, buf+curoff-xfer, NULL, pmode, &ret);
            if(res < 0) {
                //printf("GET fails for oid %lu at offset %d\n", oid, curoff-xfer);
                return EGETFAIL;
            }
            //printf("GET sucs for oid %lu at offset %d\n", oid, curoff-xfer);
        }
        if(curoff > len && curoff-xfer < len){
            int npage = (len + xfer - curoff + (geo->nplanes * geo->page_nbytes) - 1) / (geo->nplanes * geo->page_nbytes);
            naddr = npage * geo->nplanes * geo->nsectors;
            for(int i = 0; i < naddr; i++){
                addrs[i].ppa = index->obj_addr.ppa;
                addrs[i].g.pl = (i / geo->nsectors) % geo->nplanes;
                addrs[i].g.pg = pg + i / (geo->nsectors * geo->nplanes) + pgoff;
                addrs[i].g.sec = i % geo->nsectors;
            }
            int res = nvm_addr_read(index->dev, addrs, naddr, buf+curoff-xfer, NULL, pmode, &ret);
            if(res < 0) {
                printf("GET fails for oid %lu at offset %d\n", oid, curoff-xfer);
                return EGETFAIL;
            }
        }

        if(buf != buf_r)
            memcpy(buf_r, buf, len);
        return SUCCESS;
    }
    return ENOEXIST;
}

int oss_t::oss_put(oid_t oid, char* buf_w, int len){
    printf("put oid %lu", oid);
    if(len > geo->nplanes*block_nbytes) return ETOOLARGE;
    index_map_iter_t iter =  index_map.find(oid);
    if(iter != index_map.end()){
        return EDOEXIST;
    }
    index_t* index = _create_object(len);
    if(index == NULL){
        printf("create object fails\n");
        return ENOSPACE;
    }
    index_map[oid] = index;
    // write to SSD

    char* buf = NULL;
    if((uint64_t)buf_w % geo->sector_nbytes){
        buf = (char*)nvm_buf_alloc(geo, len);
        if(!buf){
            return ENOMEMORY;
        }
        memcpy(buf, buf_w, len);
    }else buf = buf_w;

    struct nvm_addr addrs[NVM_NADDR_MAX];
    struct nvm_ret ret;
    int naddr = NVM_NADDR_MAX;
    int xfer = geo->sector_nbytes * NVM_NADDR_MAX;
    //printf("xfer size %d\n", xfer);
    int xpg = NVM_NADDR_MAX / (geo->nplanes*geo->nsectors);
    int curoff = xfer, pgoff = 0;
    int pg = index->obj_addr.g.pg;
    for(; curoff <= len; curoff += xfer){
        for(int i = 0; i < naddr; i++){
            addrs[i].ppa = index->obj_addr.ppa;
            addrs[i].g.pl = (i / geo->nsectors) % geo->nplanes;
            addrs[i].g.pg = pg + i / (geo->nsectors * geo->nplanes) + pgoff;
            addrs[i].g.sec = i % geo->nsectors;
        }
        pgoff += xpg;
        /*
           for(int i = 0; i < NVM_NADDR_MAX; i++){
           nvm_addr_pr(addrs[i]);
           }
           */
        int res = nvm_addr_write(index->dev, addrs, naddr, buf+curoff-xfer, NULL, pmode, &ret);
        //printf("put %lu, len %d, res %d\n", oid, len, res);
        if(res < 0) {
            return EPUTFAIL;
        }
    }
    if(curoff > len && curoff-xfer < len){
        int npage = (len + xfer - curoff + (geo->nplanes * geo->page_nbytes) - 1) / (geo->nplanes * geo->page_nbytes);
        naddr = npage * geo->nplanes * geo->nsectors;
        for(int i = 0; i < naddr; i++){
            addrs[i].ppa = index->obj_addr.ppa;
            addrs[i].g.pl = (i / geo->nsectors) % geo->nplanes;
            addrs[i].g.pg = pg + i / (geo->nsectors * geo->nplanes) + pgoff;
            addrs[i].g.sec = i % geo->nsectors;
        }
        buf = buf + curoff - xfer; if(naddr * geo->sector_nbytes != len+xfer-curoff){
            char* buf_pad = (char*)nvm_buf_alloc(geo, naddr * geo->sector_nbytes);
            memset(buf_pad, 0, naddr * geo->sector_nbytes);
            memcpy(buf_pad, buf, len+xfer-curoff);
            buf = buf_pad;
        }
        int res = nvm_addr_write(index->dev, addrs, naddr, buf, NULL, pmode, &ret);
        if(res < 0) {
            return EPUTFAIL;
        }
    }
    return SUCCESS;
}

int oss_t::oss_del(oid_t oid){
    index_map_iter_t iter =  index_map.find(oid);
    if(iter != index_map.end()){
        index_t* index = iter->second;
        if(index->deleted) return ENOEXIST;
        index->deleted = true;
    }
    return ENOEXIST;
}

