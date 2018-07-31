/*
 * Implementation of a reliability enforced Block Devices on top of Multiple Open-channel SSDs
 */

#include "ocssdr.h"

struct bio_set *ocssdr_bio_set;


static blk_qc_t ocssdr_make_rq(struct request_queue *q, struct bio *bio)
{
	return BLK_QC_T_NONE;
}


static void ocssdr_exit(void *private)
{
}

static sector_t ocssdr_capacity(void *private)
{
	return 0;
}

static void *ocssdr_init(int subdevcnt, struct nvm_target **sub_targets, struct gendisk *tdisk,
		int flags)
{
	return ERR_PTR(-EINVAL);
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
