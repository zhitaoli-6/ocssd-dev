#include "oss.h"
#include <cstring>

oss_t::oss_t(int ndev){
    this->ndevs = ndev;
}

void oss_t::setup(){
    assert(ndevs <= MAX_DEV);
    char name[128];
    for(int i = 0; i < ndevs; i++){
        sprintf(name, "/dev/nvme%01dn1", i);
        dev[i] = nvm_dev_open(name);
        if(!dev[i]){
            perror(name);
            return;
        }
    }
}

int oss_t::oss_get(oid_t oid, void* buf, int len){
    index_map_iter_t iter =  index_map.find(oid);
    if(iter != index_map.end()){
        index_t* index = iter->second;
        if(index->deleted) return ENOEXIST;
        void* buf_w = NULL;
        // read from SSD
        memcpy(buf, buf_w, min(index->len, len));
        return SUCCESS;
    }
    return ENOEXIST;
}

int oss_t::oss_put(void* buf, int len, oid_t *oid){
    if(len > block_nbytes) return ETOOLARGE;
    return ENOSUPPORT;
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

