/*
 * SO2 - Block device drivers lab (#7)
 * Linux - Exercise #1, #2, #3, #6 (RAM Disk)
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include <linux/genhd.h>
#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/vmalloc.h>

MODULE_DESCRIPTION("Simple RAM Disk");
MODULE_AUTHOR("SO2");
MODULE_LICENSE("GPL");


#define KERN_LOG_LEVEL		KERN_ALERT

#define MY_BLOCK_MAJOR		240
#define MY_BLKDEV_NAME		"mybdev"
#define MY_BLOCK_MINORS		1
#define NR_SECTORS		(1024*128)

#define KERNEL_SECTOR_SIZE	512

/* TODO 6/0: use bios for read/write requests */
#define USE_BIO_TRANSFER 1

enum {
	RM_FULL  = 0,	/* The extra-simple request function */
	RM_NOQUEUE = 1,	/* Use make_request */
};
static int request_mode = RM_NOQUEUE;

static struct my_block_dev {
	spinlock_t lock;
	struct request_queue *queue;
	struct gendisk *gd;
	u8 *data;
	size_t size;
} g_dev;

static int my_block_open(struct block_device *bdev, fmode_t mode)
{
	return 0;
}

static void my_block_release(struct gendisk *gd, fmode_t mode)
{
}

static const struct block_device_operations my_block_ops = {
	.owner = THIS_MODULE,
	.open = my_block_open,
	.release = my_block_release
};

static void my_block_transfer(struct my_block_dev *dev, sector_t sector,
		unsigned long len, char *buffer, int dir)
{
	unsigned long offset = sector * KERNEL_SECTOR_SIZE;

	/* check for read/write beyond end of block device */
	if ((offset + len) > dev->size)
		return;

	/* TODO 3/4: read/write to dev buffer depending on dir */
	if (dir == 1)		/* write */
		memcpy(dev->data + offset, buffer, len);
	else
		memcpy(buffer, dev->data + offset, len);
}

/* to transfer data using bio structures enable USE_BIO_TRANFER */
#if USE_BIO_TRANSFER == 1
static void my_xfer_request(struct my_block_dev *dev, struct request *req)
{
	/* TODO 6/10: iterate segments */
	struct bio_vec bvec;
	struct req_iterator iter;

	char *buffer;
	rq_for_each_segment(bvec, req, iter) {
		sector_t sector = iter.iter.bi_sector;
		unsigned long offset = bvec.bv_offset;
		size_t len = bvec.bv_len;
		int dir = bio_data_dir(iter.bio);
		buffer = kmap_atomic(bvec.bv_page);
		printk(KERN_LOG_LEVEL "%s: buf %8p offset %lu len %u dir %d\n", __func__, buffer, offset, len, dir);

		/* TODO 6/3: copy bio data to device buffer */
		my_block_transfer(dev, sector, len, buffer + offset, dir);
		kunmap_atomic(buffer);
	}
}
#endif


static blk_qc_t my_block_make_request(struct request_queue *q, struct bio *bio){
	struct my_block_dev *dev = bio->bi_disk->private_data;
	struct bio_vec bvec;
	sector_t sector;
	struct bvec_iter iter;
	char *buffer = NULL;

	sector = bio->bi_iter.bi_sector;
	if (bio_end_sector(bio) > get_capacity(bio->bi_disk))
		return BLK_QC_T_NONE;
	printk(KERN_LOG_LEVEL "%s pos %u dir=%c\n", __func__, sector, op_is_write(bio_op(bio)) ? 'W':'R');

	bio_for_each_segment(bvec, bio, iter) {
		sector = iter.bi_sector;

		buffer = kmap_atomic(bvec.bv_page);
		my_block_transfer(dev, sector, bvec.bv_len, buffer+bvec.bv_offset, op_is_write(bio_op(bio)));
		kunmap_atomic(buffer);
		
	}

	bio_endio(bio);
	return BLK_QC_T_NONE;
}

static void my_block_request(struct request_queue *q)
{
	struct request *rq;
	struct my_block_dev *dev = q->queuedata;

	while (1) {

		/* TODO 2/3: fetch request */
		rq = blk_fetch_request(q);
		if (rq == NULL)
			break;

		/* TODO 2/5: check fs request */
		if (blk_rq_is_passthrough(rq)) {
			printk(KERN_NOTICE "Skip non-fs request\n");
			__blk_end_request_all(rq, -EIO);
			continue;
		}

		/* TODO 2/6: print request information */
		printk(KERN_LOG_LEVEL
			"request received: pos=%llu bytes=%u "
			"cur_bytes=%u dir=%c\n",
			(unsigned long long) blk_rq_pos(rq),
			blk_rq_bytes(rq), blk_rq_cur_bytes(rq),
			rq_data_dir(rq) ? 'W' : 'R');

#if USE_BIO_TRANSFER == 1
		/* TODO 6/1: process the request by calling my_xfer_request */
		my_xfer_request(dev, rq);
#else
		/* TODO 3/3: process the request by calling my_block_transfer */
		my_block_transfer(dev, blk_rq_pos(rq),
				  blk_rq_bytes(rq),
				  bio_data(rq->bio), rq_data_dir(rq));
#endif

		/* TODO 2/1: end request successfully */
		__blk_end_request_all(rq, 0);
	}
}

static int create_block_device(struct my_block_dev *dev)
{
	int err;

	dev->size = NR_SECTORS * KERNEL_SECTOR_SIZE;
	dev->data = vmalloc(dev->size);
	if (dev->data == NULL) {
		printk(KERN_ERR "vmalloc: out of memory\n");
		err = -ENOMEM;
		goto out_vmalloc;
	}


	/* initialize the I/O queue */
	spin_lock_init(&dev->lock);

	switch (request_mode) {
		case RM_NOQUEUE:
			dev->queue = blk_alloc_queue(GFP_KERNEL);
			if (dev->queue == NULL)
				goto out_vfree;
			blk_queue_make_request(dev->queue, my_block_make_request);
			break;

		default:
			printk(KERN_NOTICE "Bad request mode %d, using FULL\n", request_mode);
			/* fall into.. */

		case RM_FULL:
			dev->queue = blk_init_queue(my_block_request, &dev->lock);
			if (dev->queue == NULL)
				goto out_vfree;
			break;
	}

	blk_queue_logical_block_size(dev->queue, KERNEL_SECTOR_SIZE);
	dev->queue->queuedata = dev;

	/* initialize the gendisk structure */
	dev->gd = alloc_disk(MY_BLOCK_MINORS);
	if (!dev->gd) {
		printk(KERN_ERR "alloc_disk: failure\n");
		err = -ENOMEM;
		goto out_alloc_disk;
	}

	dev->gd->major = MY_BLOCK_MAJOR;
	dev->gd->first_minor = 0;
	dev->gd->fops = &my_block_ops;
	dev->gd->queue = dev->queue;
	dev->gd->private_data = dev;
	snprintf(dev->gd->disk_name, DISK_NAME_LEN, "myblock");
	set_capacity(dev->gd, NR_SECTORS);

	add_disk(dev->gd);

	return 0;

out_alloc_disk:
	blk_cleanup_queue(dev->queue);
out_vfree:
	vfree(dev->data);
out_vmalloc:
	return err;
}

static int __init my_block_init(void)
{
	int err = 0;

	/* TODO 1/5: register block device */
	err = register_blkdev(MY_BLOCK_MAJOR, MY_BLKDEV_NAME);
	if (err < 0) {
		printk(KERN_ERR "register_blkdev: unable to register\n");
		return err;
	}

	/* TODO 2/3: create block device using create_block_device */
	err = create_block_device(&g_dev);
	if (err < 0)
		goto out;

	return 0;

out:
	/* TODO 1/1: unregister block device in case of an error */
	unregister_blkdev(MY_BLOCK_MAJOR, MY_BLKDEV_NAME);
	return err;
}

static void delete_block_device(struct my_block_dev *dev)
{
	if (dev->gd) {
		del_gendisk(dev->gd);
		put_disk(dev->gd);
	}
	if (dev->queue)
		blk_cleanup_queue(dev->queue);
	if (dev->data)
		vfree(dev->data);
}

static void __exit my_block_exit(void)
{
	/* TODO 2/1: cleanup block device using delete_block_device */
	delete_block_device(&g_dev);

	/* TODO 1/1: unregister block device */
	unregister_blkdev(MY_BLOCK_MAJOR, MY_BLKDEV_NAME);
}

module_init(my_block_init);
module_exit(my_block_exit);

