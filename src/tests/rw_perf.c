#include <stdio.h>
#include <string.h>
#include <liblightnvm.h>
#include "common.h"

#define MB (1<<20)


#define DEBUG(msg) \
    do { \
        fprintf(stderr, "FATAL ERROR: %s (%s: Line %d)\n", \
                msg, __FILE__, __LINE__); \
    }while(0)

static char nvm_dev_path[NVM_DEV_PATH_LEN] = "/dev/nvme0n1";

static int channel = 0;
static int lun = 1;
static int block = 3;


static struct nvm_dev *dev;
static const struct nvm_geo *geo;
static struct nvm_addr blk_addr;

int setup(void)
{
    dev = nvm_dev_open(nvm_dev_path);
    if (!dev) {
        perror("nvm_dev_open");
        return -1;
    }
    geo = nvm_dev_get_geo(dev);

    blk_addr.ppa = 0;
    blk_addr.g.ch = channel;
    blk_addr.g.lun = lun;
    blk_addr.g.blk = block;

    return 0;
}

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
void print_meta(char *buf, int nbytes){
    for(int i = 0; i < nbytes; i+=geo->meta_nbytes){
        for(int j = 0; j < geo->meta_nbytes; j++)
            printf("%c", buf[i+j]);
        printf("\n");
    }
}

int read_write_test(int use_meta){
    int pmode = nvm_dev_get_pmode(dev);
    //int pmode = dev->pmode;
    char *buf_w = NULL, *buf_r = NULL, *meta_w = NULL, *meta_r = NULL;
    const int naddrs = NVM_NADDR_MAX;
    //assert(naddrs = NVM_NADDR_MAX);
    struct nvm_addr addrs[naddrs];
    struct nvm_ret ret;
    ssize_t res;
    size_t buf_nbytes, meta_nbytes;
    int failed = 1;

    printf("INFO: N naddrs(%d), use_meta(%d) on ", naddrs, use_meta);
    nvm_addr_pr(blk_addr);

    buf_nbytes = naddrs * geo->sector_nbytes;
    meta_nbytes = naddrs * geo->meta_nbytes;
    //printf("INFO plane %d, nsector %d, meta_byte %d\n", geo->nplanes, geo->nsectors, geo->meta_nbytes);

    buf_w = nvm_buf_alloc(geo, buf_nbytes);	// Setup buffers
    if (!buf_w) {
        DEBUG("nvm_buf_alloc");
        goto exit_naddr;
    }
    for(size_t i = 0; i < buf_nbytes; i++)
        buf_w[i] = 'D';
    //nvm_buf_fill(buf_w, buf_nbytes);

    meta_w = nvm_buf_alloc(geo, meta_nbytes);
    if (!meta_w) {
        DEBUG("nvm_buf_alloc");
        goto exit_naddr;
    }
    for (size_t i = 0; i < meta_nbytes; ++i) {
        meta_w[i] = 'M';
    }
    //for (int i = 0; i < naddrs; ++i) {
    //    char meta_descr[meta_nbytes];
    //    int sec = i % geo->nsectors;
    //    int pl = (i / geo->nsectors) % geo->nplanes;

    //    sprintf(meta_descr, "[P(%02d),S(%02d)]", pl, sec);
    //    //sprintf(meta_descr, "hellohello");
    //    if (strlen(meta_descr) > geo->meta_nbytes) {
    //        DEBUG("Failed constructing meta buffer");
    //        goto exit_naddr;
    //    }

    //    memcpy(meta_w + i * geo->meta_nbytes, meta_descr, strlen(meta_descr));
    //}


    buf_r = nvm_buf_alloc(geo, buf_nbytes);
    if (!buf_r) {
        DEBUG("nvm_buf_alloc");
        goto exit_naddr;
    }

    meta_r = nvm_buf_alloc(geo, meta_nbytes);
    if (!meta_r) {
        DEBUG("nvm_buf_alloc");
        goto exit_naddr;
    }

    /* Erase */
    if (pmode) {
        addrs[0].ppa = blk_addr.ppa;
    } else {
        for (size_t pl = 0; pl < geo->nplanes; ++pl) {
            addrs[pl].ppa = blk_addr.ppa;

            addrs[pl].g.pl = pl;
        }
    }

    res = nvm_addr_erase(dev, addrs, pmode ? 1 : geo->nplanes, pmode, &ret);
    if (res < 0) {
        DEBUG("Erase failure");
        goto exit_naddr;
    }
    int pg = 7;
    size_t buf_diff = 0, meta_diff = 0;

    uint64_t tbytes = geo->nblocks * geo->npages * NVM_NADDR_MAX * geo->sector_nbytes;
    double tw = 0, tr = 0;
    struct timeval t1, t2;
    for(int pg = 0; pg < geo->npages; pg++){
        for(int blk = 0; blk < geo->nblocks; blk++){
            for (int i = 0; i < NVM_NADDR_MAX; ++i) {
                addrs[i].ppa = 0;
                addrs[i].g.ch = 0;
                addrs[i].g.lun = i / 8;

                addrs[i].g.blk = blk;
                addrs[i].g.pg = pg;
                addrs[i].g.pl = (i % 8 / geo->nsectors) % geo->nplanes;
                addrs[i].g.sec = i % geo->nsectors;
            }
            //printf("send write %d sectors\n", naddrs);
            gettime(&t1, NULL);
            res = nvm_addr_write(dev, addrs, naddrs, buf_w, use_meta ? meta_w : NULL, pmode, &ret);
            gettime(&t2, NULL);
            tw += TIMEs(t1, t2);
            
            //res = nvm_addr_write(dev, addrs, naddrs, buf_w, NULL, pmode, &ret);

            if (res < 0) {
                DEBUG("Write failure");
                goto exit_naddr;
            }

            memset(buf_r, 0, buf_nbytes);
            if (use_meta)
                memset(meta_r, 0 , meta_nbytes);

            gettime(&t1, NULL);
            res = nvm_addr_read(dev, addrs, naddrs, buf_r,
                    use_meta ? meta_r : NULL, pmode, &ret);
            gettime(&t2, NULL);
            tr += TIMEs(t1, t2);
            if (res < 0) {
                DEBUG("Read failure: command error");
                goto exit_naddr;
            }
            /*
            buf_diff = compare_buffers(buf_r, buf_w, buf_nbytes);
            if (use_meta)
                meta_diff = compare_buffers(meta_r, meta_w, meta_nbytes);

            if (buf_diff)
                DEBUG("Read failure: buffer mismatch");
            if (use_meta && meta_diff) {
                DEBUG("Read failure: meta mismatch");
                print_mismatch(meta_w, meta_r, meta_nbytes);
                printf("expected:\n");
                print_meta(meta_w, meta_nbytes);
                printf("got:\n");
                print_meta(meta_r, meta_nbytes);
            }
            if (buf_diff || meta_diff)
                goto exit_naddr;
                */
        }
    }
    printf("write bindwidth %.2f, read %.2f\n", tbytes*1.0/MB/tw, tbytes*1.0/MB/tr);

    failed = 0;
exit_naddr:
    nvm_buf_free(meta_r);
    nvm_buf_free(buf_r);
    nvm_buf_free(meta_w);
    nvm_buf_free(buf_w);

    if (failed)
        printf("Failure on PPA(0x%016lx)\n", blk_addr.ppa);
    return 0;
}

int main(int argc, char **argv)
{
    if(setup() < 0) return -1;
    //nvm_dev_pr(dev);
    read_write_test(0);
    nvm_dev_close(dev);

    return 0;
}
