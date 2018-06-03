#include <liblightnvm.h>
#include <map>
#include <assert.h>

#include "engine.h"
#include "error.h"

using namespace std;

#define MAX_DEV 3

typedef long long oid_t;

/*
typedef int (*oss_get_t)(oid_t oid, void* buf, int len);
typedef int (*oss_put_t)(void* buf, int len, oid_t* oid);
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
    struct nvm_dev *dev[MAX_DEV];
    int ndevs;
    index_map_t index_map;
    size_t block_nbytes;
    //inter_map_iter_t index_map_iter;
public:
    void setup();
    oss_t(int ndev);
    int oss_get(oid_t oid, void* buf, int len);
    int oss_put(void* buf, int len, oid_t *oid);
    int oss_del(oid_t oid);
};



