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

#define LOGICAL_SIZE  (1<<3)
#define CHUNK_SIZE  LOGICAL_SIZE

enum {
	MODE_STACK = 0,
	MODE_STRIPE = 1,
};

struct ocssdr {
	struct gendisk *disk;
	struct nvm_target **child_targets;
	int child_target_cnt;
	int r_mode;
};

#endif
