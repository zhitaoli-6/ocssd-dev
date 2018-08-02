#ifndef OCR_H_
#define OCR_H_

#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/bio.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/vmalloc.h>
#include <linux/uuid.h>

#include <linux/lightnvm.h>


struct ocssdr {
	struct gendisk *disk;
	struct nvm_target **child_targets;
	int child_target_cnt;
};

#endif
