/*
 * Sample disk driver, from the beginning.
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>

#include <linux/sched.h>
#include <linux/kernel.h>	/* printk() */
#include <linux/slab.h>		/* kmalloc() */
#include <linux/fs.h>		/* everything... */
#include <linux/errno.h>	/* error codes */
#include <linux/timer.h>
#include <linux/types.h>	/* size_t */
#include <linux/fcntl.h>	/* O_ACCMODE */
#include <linux/hdreg.h>	/* HDIO_GETGEO */
#include <linux/kdev_t.h>
#include <linux/vmalloc.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>
#include <linux/buffer_head.h>	/* invalidate_bdev */
#include <linux/bio.h>

MODULE_LICENSE("Dual BSD/GPL");

static int sbull_major = 0;
module_param(sbull_major, int, 0);
static int hardsect_size = 512;
module_param(hardsect_size, int, 0);
static int nsectors = 1024*1024;	/* How big the drive is */
module_param(nsectors, int, 0);
static int ndevices = 4;
module_param(ndevices, int, 0);

static int RAID0 = 0;
module_param(RAID0, int, 0);

#define CHUNK_BITS (3)
#define CHUNK_SECTS (1<<CHUNK_BITS)
//static int CHUNK_SECTS = 8; // 8 sectors per chunk


static struct bio_set *sbull_bio_set = NULL;
/*
 * The different "request modes" we can use.
 */
enum {
	RM_SIMPLE  = 0,	/* The extra-simple request function */
	RM_FULL    = 1,	/* The full-blown version */
	RM_NOQUEUE = 2,	/* Use make_request */
};
static int request_mode = RM_NOQUEUE;
module_param(request_mode, int, 0);

/*
 * Minor number and partition management.
 */
#define SBULL_MINORS	16
#define MINOR_SHIFT	4
#define DEVNUM(kdevnum)	(MINOR(kdev_t_to_nr(kdevnum)) >> MINOR_SHIFT

/*
 * We can tweak our hardware sector size, but the kernel talks to us
 * in terms of small sectors, always.
 */
#define KERNEL_SECTOR_SIZE	512

/*
 * After this much idle time, the driver will simulate a media change.
 */
#define INVALIDATE_DELAY	30*HZ

/*
 * The internal representation of our device.
 */
struct sbull_dev {
        int size;                       /* Device size in sectors */
        u8 *data;                       /* The data array */
        short users;                    /* How many users */
        short media_change;             /* Flag a media change? */
        spinlock_t lock;                /* For mutual exclusion */
        struct request_queue *queue;    /* The device request queue */
        struct gendisk *gd;             /* The gendisk structure */
        //struct timer_list timer;        /* For simulated media changes */
		//custom
};

struct md_sbull_dev {
	struct request_queue *queue;    /* The device request queue */
	struct gendisk *gd;
	struct sbull_dev* child_dev[2];
	spinlock_t lock;                /* For mutual exclusion */
};

static struct sbull_dev *Devices = NULL;
static struct md_sbull_dev *md_dev= NULL;

/*
 * Handle an I/O request.
 */
static void sbull_transfer(struct sbull_dev *dev, unsigned long sector,
		unsigned long nbytes, char *buffer, int write)
{
	unsigned long offset = sector*KERNEL_SECTOR_SIZE;

	if ((offset + nbytes) > dev->size) {
		printk (KERN_NOTICE "Beyond-end write (%ld %ld)\n", offset, nbytes);
		return;
	}
	if (write)
		memcpy(dev->data + offset, buffer, nbytes);
	else
		memcpy(buffer, dev->data + offset, nbytes);
}


/*
 * The simple form of the request function.
 */
static void sbull_request(struct request_queue *q)
{
	struct request *req;

	while ((req = blk_fetch_request(q)) != NULL) {
		//struct sbull_dev *dev = req->rq_disk->private_data;
		//if (req->cmd_type != REQ_TYPE_FS) {
		if(blk_rq_is_passthrough(req)){
			printk (KERN_NOTICE "Skip non-fs request\n");
			__blk_end_request_cur(req, -EIO);
			continue;
		}
    //    	printk (KERN_NOTICE "Req dev %d dir %ld sec %ld, nr %d f %lx\n",
    //    			dev - Devices, rq_data_dir(req),
    //    			req->sector, req->current_nr_sectors,
    //    			req->flags);
		//sbull_transfer(dev, blk_rq_pos(req), blk_rq_cur_sectors(req),
				//req->buffer, rq_data_dir(req));
		__blk_end_request_cur(req, 0);
	}
}


/*
 * Transfer a single BIO.
 */
static int sbull_xfer_bio(struct sbull_dev *dev, struct bio *bio)
{
	//int i;
	struct bvec_iter i;
	struct bio_vec bvec;

	/* Do each segment independently. */
	bio_for_each_segment(bvec, bio, i) {
		sector_t sector = i.bi_sector;
		char *buffer = kmap_atomic(bvec.bv_page);
		unsigned long offset = bvec.bv_offset;
		sbull_transfer(dev, sector, bvec.bv_len,
				buffer+offset, op_is_write(bio_op(bio)));
		kunmap_atomic(buffer);
	}
	return 0; /* Always "succeed" */
}

/*
 * Transfer a full request.
 */
static void sbull_xfer_request(struct sbull_dev *dev, struct request *req)
{
	struct bio *bio;
    
	__rq_for_each_bio(bio, req) {
		sbull_xfer_bio(dev, bio);
	}
}



/*
 * Smarter request function that "handles clustering".
 */
static void sbull_full_request(struct request_queue *q)
{
	struct request *req;
	struct sbull_dev *dev = q->queuedata;

	while ((req = blk_fetch_request(q)) != NULL) {
		if(blk_rq_is_passthrough(req)){
		//if (req->cmd_type != REQ_TYPE_FS) {
			printk (KERN_NOTICE "Skip non-fs request\n");
			__blk_end_request(req, -EIO, blk_rq_cur_bytes(req));
			continue;
		}
		sbull_xfer_request(dev, req);
		__blk_end_request_all(req, 0);
	}
}



/*
 * The direct make request version.
 */
static blk_qc_t sbull_make_request(struct request_queue *q, struct bio *bio)
{
	struct sbull_dev *dev = bio->bi_disk->private_data;
	int status;
	printk(KERN_NOTICE "sbull: %s: op %s, lba %10lu, size %10u, partno %u\n", bio->bi_disk->disk_name, (bio_data_dir(bio) == WRITE?"write":"read"), bio->bi_iter.bi_sector, bio_sectors(bio), bio->bi_partno);

	status = sbull_xfer_bio(dev, bio);
	bio_endio(bio);
	return BLK_QC_T_NONE;
}

#ifdef MACRO_RAID0
static int get_target(int sector){
	return (sector >> 3) & 1;
}
#endif

static blk_qc_t md_sbull_make_request(struct request_queue *q, struct bio *bio)
{
	struct md_sbull_dev *dev = bio->bi_disk->private_data;
	//printk(KERN_NOTICE "RAID0 begins working\n");
	printk(KERN_NOTICE "sbull: %s: op %s, lba %10lu, size %10u, partno %u\n", bio->bi_disk->disk_name, (bio_data_dir(bio) == WRITE?"write":"read"), bio->bi_iter.bi_sector, bio_sectors(bio), bio->bi_partno);

#ifdef MACRO_RAID0
	unsigned int total_sectors = bio_sectors(bio);
	unsigned int bi_sector = bio->bi_iter.bi_sector;
	int sectors = CHUNK_SECTS - ( bi_sector & (CHUNK_SECTS - 1));
	int target;

	if(sectors < total_sectors){
		struct bio *split = bio_split(bio, sectors, GFP_NOIO, sbull_bio_set);
		bio_chain(split, bio);
		generic_make_request(bio);
		bio = split;
	}
	target = get_target(bi_sector);
	bio->bi_disk =  dev->child_dev[target]->gd;
	bio->bi_iter.bi_sector = ((bi_sector >> 4)  << 3) + (bi_sector & (CHUNK_SECTS - 1));
#else
	bio->bi_disk = dev->child_dev[0]->gd;
#endif
	generic_make_request(bio);
	return BLK_QC_T_NONE;
}


/*
 * Open and close.
 */

static int sbull_open(struct block_device *bdev, fmode_t mode)
{
	struct sbull_dev *dev = bdev->bd_disk->private_data;

	//del_timer_sync(&dev->timer);
	//filp->private_data = dev;
	spin_lock(&dev->lock);
	if (! dev->users) 
		check_disk_change(bdev);
	dev->users++;
	spin_unlock(&dev->lock);
	return 0;
}

static void sbull_release(struct gendisk *disk, fmode_t mode)
{
	struct sbull_dev *dev = disk->private_data;

	spin_lock(&dev->lock);
	dev->users--;

	if (!dev->users) {
		//dev->timer.expires = jiffies + INVALIDATE_DELAY;
		//add_timer(&dev->timer);
	}
	spin_unlock(&dev->lock);
}

/*
 * Look for a (simulated) media change.
 */
int sbull_media_changed(struct gendisk *gd)
{
	struct sbull_dev *dev = gd->private_data;
	
	return dev->media_change;
}

/*
 * Revalidate.  WE DO NOT TAKE THE LOCK HERE, for fear of deadlocking
 * with open.  That needs to be reevaluated.
 */
int sbull_revalidate(struct gendisk *gd)
{
	struct sbull_dev *dev = gd->private_data;
	
	if (dev->media_change) {
		dev->media_change = 0;
		memset (dev->data, 0, dev->size);
	}
	return 0;
}

/*
 * The "invalidate" function runs out of the device timer; it sets
 * a flag to simulate the removal of the media.
 */
void sbull_invalidate(unsigned long ldev)
{
	struct sbull_dev *dev = (struct sbull_dev *) ldev;

	spin_lock(&dev->lock);
	if (dev->users || !dev->data) 
		printk (KERN_WARNING "sbull: timer sanity check failed\n");
	else
		dev->media_change = 1;
	spin_unlock(&dev->lock);
}

/*
 * The ioctl() implementation
 */

int sbull_ioctl (struct block_device *bdev, fmode_t mode,
                 unsigned int cmd, unsigned long arg)
{
	long size;
	struct hd_geometry geo;
	struct sbull_dev *dev = bdev->bd_disk->private_data;

	switch(cmd) {
	    case HDIO_GETGEO:
        	/*
		 * Get geometry: since we are a virtual device, we have to make
		 * up something plausible.  So we claim 16 sectors, four heads,
		 * and calculate the corresponding number of cylinders.  We set the
		 * start of data at sector four.
		 */
		size = dev->size*(hardsect_size/KERNEL_SECTOR_SIZE);
		geo.cylinders = (size & ~0x3f) >> 6;
		geo.heads = 4;
		geo.sectors = 16;
		geo.start = 4;
		if (copy_to_user((void __user *) arg, &geo, sizeof(geo)))
			return -EFAULT;
		return 0;
	}

	return -ENOTTY; /* unknown command */
}



/*
 * The device operations structure.
 */
static struct block_device_operations sbull_ops = {
	.owner           = THIS_MODULE,
	.open 	         = sbull_open,
	.release 	 = sbull_release,
	.media_changed   = sbull_media_changed,
	.revalidate_disk = sbull_revalidate,
	.ioctl	         = sbull_ioctl
};

static struct block_device_operations md_sbull_ops = {
	.owner           = THIS_MODULE,
};


/*
 * Set up our internal device.
 */
static void setup_device(struct sbull_dev *dev, int which)
{
	/*
	 * Get some memory.
	 */
	memset (dev, 0, sizeof (struct sbull_dev));
	dev->size = nsectors*hardsect_size;
	dev->data = vmalloc(dev->size);
	if (dev->data == NULL) {
		printk (KERN_NOTICE "vmalloc failure.\n");
		return;
	}
	spin_lock_init(&dev->lock);
	
	/*
	 * The timer which "invalidates" the device.
	 */
	//__init_timer(&dev->timer);
	//dev->timer.data = (unsigned long) dev;
	//dev->timer.function = sbull_invalidate;
	
	/*
	 * The I/O queue, depending on whether we are using our own
	 * make_request function or not.
	 */
	switch (request_mode) {
	    case RM_NOQUEUE:
		dev->queue = blk_alloc_queue(GFP_KERNEL);
		if (dev->queue == NULL)
			goto out_vfree;
		blk_queue_make_request(dev->queue, sbull_make_request);
		break;

	    case RM_FULL:
		dev->queue = blk_init_queue(sbull_full_request, &dev->lock);
		if (dev->queue == NULL)
			goto out_vfree;
		break;

	    default:
		printk(KERN_NOTICE "Bad request mode %d, using simple\n", request_mode);
        	/* fall into.. */
	
	    case RM_SIMPLE:
		printk(KERN_NOTICE "Bad request mode %d\n", request_mode);
		goto out_vfree;
		dev->queue = blk_init_queue(sbull_request, &dev->lock);
		if (dev->queue == NULL)
			goto out_vfree;
		break;
	}
	blk_queue_logical_block_size(dev->queue, PAGE_SIZE);
	dev->queue->queuedata = dev;
	/*
	 * And the gendisk structure.
	 */
	dev->gd = alloc_disk(SBULL_MINORS);
	if (!dev->gd) {
		printk (KERN_NOTICE "alloc_disk failure\n");
		goto out_vfree;
	}
	dev->gd->major = sbull_major;
	dev->gd->first_minor = which*SBULL_MINORS;
	dev->gd->fops = &sbull_ops;
	dev->gd->queue = dev->queue;
	dev->gd->private_data = dev;
	snprintf (dev->gd->disk_name, 32, "sbull%c", which + 'a');
	set_capacity(dev->gd, nsectors*(hardsect_size/KERNEL_SECTOR_SIZE));
	add_disk(dev->gd);
	return;

  out_vfree:
	if (dev->data)
		vfree(dev->data);
}


static void setup_md_device(struct sbull_dev *child_devs, int devcnt)
{
	struct md_sbull_dev *dev;
	int i;
	md_dev = kzalloc(sizeof(struct md_sbull_dev), GFP_KERNEL);
	if (md_dev == NULL) {
		printk (KERN_NOTICE "vmalloc failure.\n");
		return;
	}
	dev = md_dev;
	spin_lock_init(&dev->lock);

	dev->queue = blk_alloc_queue(GFP_KERNEL);
	if(!dev->queue){
		return;
	}
	blk_queue_make_request(dev->queue, md_sbull_make_request);

	blk_queue_logical_block_size(dev->queue, hardsect_size);
	dev->queue->queuedata = dev;
	dev->gd = alloc_disk(SBULL_MINORS);
	if (! dev->gd) {
		printk (KERN_NOTICE "alloc_disk failure\n");
		//blk_cleanup_queue(dev->queue);
		//kfree(dev);
		return;
	}
	dev->gd->major = sbull_major;
	dev->gd->first_minor = 3*SBULL_MINORS;
	dev->gd->fops = &md_sbull_ops;
	dev->gd->queue = dev->queue;
	dev->gd->private_data = dev;
	strcpy(dev->gd->disk_name, "SBULLR");
	for(i=0; i < devcnt; i++)
		dev->child_dev[i] = &child_devs[i];
	//snprintf (dev->gd->disk_name, 32, "sbull%c", which + 'a');
#ifdef MACRO_RAID0
	set_capacity(dev->gd, devcnt * nsectors*(hardsect_size/KERNEL_SECTOR_SIZE));
#else
	set_capacity(dev->gd,  nsectors*(hardsect_size/KERNEL_SECTOR_SIZE));
#endif

	
	add_disk(dev->gd);
	printk(KERN_NOTICE "setup md RAID0 PASS\n");
}

static int __init sbull_init(void)
{
	int i;
	printk(KERN_INFO "sbull: begin init module\n");
	sbull_major = register_blkdev(sbull_major, "sbull");
	if (sbull_major <= 0) {
		printk(KERN_WARNING "sbull: unable to get major number\n");
		return -EBUSY;
	}
	// Allocate the device array, and initialize each one.
	Devices = kmalloc(ndevices*sizeof (struct sbull_dev), GFP_KERNEL);
	if (Devices == NULL)
		goto out_unregister;
	for (i = 0; i < ndevices; i++) 
		setup_device(Devices + i, i);
	
	if(RAID0){
		if(ndevices != 2){
			printk(KERN_NOTICE "sbull: wrong RAID0 configuration\n");
			unregister_blkdev(sbull_major, "sbull");
			return -EINVAL;
		}
		sbull_bio_set = bioset_create(BIO_POOL_SIZE, 0, 0);
		setup_md_device(Devices, ndevices);
	}
    
	return 0;

out_unregister:
	unregister_blkdev(sbull_major, "sbull");
	return -ENOMEM;
}

static void sbull_exit(void)
{	
	int i;
	printk(KERN_INFO "sbull: begin exit module\n");
	if(RAID0){
		if(md_dev->gd){
			del_gendisk(md_dev->gd);
			put_disk(md_dev->gd);
		}
		if(md_dev->queue){
			blk_cleanup_queue(md_dev->queue);
		}
		if(md_dev) kfree(md_dev);
		if(sbull_bio_set) bioset_free(sbull_bio_set);
	}

	if(Devices){
		for (i = 0; i < ndevices; i++) {
			struct sbull_dev *dev = Devices + i;

			//del_timer_sync(&dev->timer);
			del_gendisk(dev->gd);
			put_disk(dev->gd);
			blk_cleanup_queue(dev->queue);
			vfree(dev->data);
		}

		kfree(Devices);
	}
	unregister_blkdev(sbull_major, "sbull");
}
	
module_init(sbull_init);
module_exit(sbull_exit);
