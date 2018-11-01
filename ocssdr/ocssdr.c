/*
 * Implementation of a reliability enforced Block Devices on top of Multiple Open-channel SSDs
 */

#include "ocssdr.h"

struct bio_set *ocssdr_bio_set;

static blk_qc_t ocssdr_make_rq(struct request_queue *q, struct bio *bio)
{
	struct ocssdr *ocssdr = q->queuedata;
	//int child_cnt = ocssdr->child_target_cnt;
	sector_t total_sectors = bio_sectors(bio);
	unsigned int bi_sector = bio->bi_iter.bi_sector;
	unsigned int sectors;
	int tgt_id;
	pr_info("nvm: %s: op %u, bi_sector %8lu, size %8u, partno %u\n", 
			ocssdr->disk->disk_name, bio_op(bio), bio->bi_iter.bi_sector, 
			bio_sectors(bio), bio->bi_partno);
	if((total_sectors&(LOGICAL_SIZE-1)) || (bi_sector&(LOGICAL_SIZE-1))){
		pr_err("nvm: ocssdr recv bio with unaligned bi_sector or io_size\n");
		return BLK_QC_T_NONE;
	}
	switch (ocssdr->r_mode) {
		case MODE_STACK:
			bio->bi_disk = ocssdr->child_targets[0]->disk;
			generic_make_request(bio);
			break;
		case MODE_STRIPE:
			sectors = CHUNK_SIZE - (bi_sector&(CHUNK_SIZE-1));
			if(sectors < total_sectors){
				struct bio *split = bio_split(bio, sectors, GFP_NOIO, ocssdr_bio_set);
				bio_chain(split, bio);
				generic_make_request(bio);
				bio = split;
			}
			tgt_id = (bi_sector >> 3) & 1;
			bio->bi_disk = ocssdr->child_targets[tgt_id]->disk;
			bio->bi_iter.bi_sector = (bi_sector>>4)<<3;
			generic_make_request(bio);
			break;
		default:
			pr_err("nvm: ocssdr not supported run mode\n");
			break;
	}
	//bio->bi_partno = 0;
	return BLK_QC_T_NONE;
}


static void ocssdr_exit(void *private){
	struct ocssdr *ocssdr = private;
	kfree(ocssdr);
}

static sector_t ocssdr_capacity(void *private)
{
	struct ocssdr *ocssdr = private;
	struct nvm_target **t = ocssdr->child_targets;
	sector_t min_capacity = get_capacity(t[0]->disk);
	int i;
	sector_t cap;
	for(i = 1; i < ocssdr->child_target_cnt; i++){
		cap = get_capacity(t[i]->disk);
		if(cap < min_capacity)
			min_capacity = cap;
	}
	return min_capacity * ocssdr->child_target_cnt;
	//return min_capacity;
}

static void *ocssdr_init(int subdevcnt, struct nvm_target **child_targets, struct gendisk *tdisk,
		int flags)
{
	//struct nvm_target ** t;
	struct ocssdr *ocssdr;
	struct request_queue *bqueue = child_targets[0]->disk->queue;
	struct request_queue *tqueue = tdisk->queue;


	/* 
	 * defined at linux/block/blk-settings.c
	 * blk_queue_logical_block_size: minimal addressable lba for host
	 * blk_queue_physical_block_size: minimal size that device can write without r-m-w
	 */
	blk_queue_logical_block_size(tqueue, queue_physical_block_size(bqueue));
	//blk_queue_max_hw_sectors(tqueue, queue_max_hw_sectors(bqueue));
	//blk_queue_write_cache(tqueue, false, false);

	


	//int ret;
	ocssdr = kzalloc(sizeof(struct ocssdr), GFP_KERNEL);
	if(!ocssdr){
		return ERR_PTR(-ENOMEM);
	}
	ocssdr->disk = tdisk;
	ocssdr->child_targets = child_targets;
	ocssdr->child_target_cnt = subdevcnt;
	ocssdr->r_mode = (subdevcnt > 1 ? MODE_STRIPE: MODE_STACK);
	return ocssdr;

	//return ERR_PTR(-EINVAL);
}

/* physical block device target */
static struct nvm_tgt_type tt_ocssdr = {
	.name		= "ocssdr",
	.version	= {0, 0, 1},

	.make_rq	= ocssdr_make_rq,
	.capacity	= ocssdr_capacity,

	.init		= NULL,
	.minit		= ocssdr_init,
	.exit		= ocssdr_exit,

	.sysfs_init	= NULL,
	.sysfs_exit	= NULL,
	.owner		= THIS_MODULE,
};

static int __init ocssdr_module_init(void)
{
	int ret;

	ocssdr_bio_set = bioset_create(BIO_POOL_SIZE, 0, 0);
	if (!ocssdr_bio_set)
		return -ENOMEM;
	ret = nvm_register_tgt_type(&tt_ocssdr);
	if (ret)
		bioset_free(ocssdr_bio_set);
	return ret;
}

static void ocssdr_module_exit(void)
{
	bioset_free(ocssdr_bio_set);
	nvm_unregister_tgt_type(&tt_ocssdr);
}

module_init(ocssdr_module_init);
module_exit(ocssdr_module_exit);
MODULE_AUTHOR("Zhitao Li <zhitaoli1201@163.com>");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Enforce Reliabilit for Multiple Open-Channel SSDs");
