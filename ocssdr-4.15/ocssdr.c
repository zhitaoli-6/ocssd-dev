/*
 * Implementation of a reliability enforced Block Devices on top of Multiple Open-channel SSDs
 */

#include "ocssdr.h"

struct bio_set *ocssdr_bio_set;


static blk_qc_t ocssdr_make_rq(struct request_queue *q, struct bio *bio)
{
	struct ocssdr *ocssdr = q->queuedata;
	pr_info("nvm: %s: op %u, bi_sector %8lu, size %8u, partno %u\n", 
			ocssdr->disk->disk_name, bio_op(bio), bio->bi_iter.bi_sector, 
			bio_sectors(bio), bio->bi_partno);

	// 
	bio->bi_disk = ocssdr->child_targets[0]->disk;
	//bio->bi_partno = 0;
	generic_make_request(bio);

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
	sector_t total = 0;
	int i;
	for(i = 0; i < ocssdr->child_target_cnt; i++){
		total += get_capacity(t[i]->disk);
	}
	return get_capacity(t[0]->disk);
}

static void *ocssdr_init(int subdevcnt, struct nvm_target **child_targets, struct gendisk *tdisk,
		int flags)
{
	//struct nvm_target ** t;
	struct ocssdr *ocssdr;
	//int ret;
	ocssdr = kzalloc(sizeof(struct ocssdr), GFP_KERNEL);
	if(!ocssdr){
		return ERR_PTR(-ENOMEM);
	}
	ocssdr->disk = tdisk;
	ocssdr->child_targets = child_targets;
	ocssdr->child_target_cnt = subdevcnt;
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
