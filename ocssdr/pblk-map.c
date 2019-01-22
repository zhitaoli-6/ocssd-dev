/*
 * Copyright (C) 2016 CNEX Labs
 * Initial release: Javier Gonzalez <javier@cnexlabs.com>
 *                  Matias Bjorling <matias@cnexlabs.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * pblk-map.c - pblk's lba-ppa mapping strategy
 *
 */

#include "pblk.h"

static void pblk_md_new_group(struct pblk *pblk)
{
	struct pblk_md_line_group_set *set = &pblk->md_line_group_set;
	struct pblk_md_line_group *group = &set->line_groups[set->cur_group];
	struct pblk_line *line, *prev_line;
	int nr_unit = group->nr_unit;
	int i, dev_id;
	for (i = 0;  i < nr_unit; i++) {
		dev_id = group->line_units[i].dev_id;
		line = pblk_line_get_data(pblk, dev_id);

		if (!pblk_line_is_full(line)) {
			pr_err("pblk: line %d of dev %d in past line group not full\n",
					i, dev_id);
		}
	}

	set->cur_group++;
	group = &set->line_groups[set->cur_group];
	// naive strategy used here
	for (dev_id = 0; dev_id < pblk->nr_dev; dev_id++) {
		prev_line  = pblk_line_get_data(pblk, dev_id);
		line = pblk_line_replace_data(pblk, dev_id);
		pblk_line_close_meta(pblk, prev_line);

		group->nr_unit = nr_unit;
		group->line_units[dev_id].dev_id = dev_id;
		group->line_units[dev_id].line_id = line->id;
	}
}

static void pblk_map_page_data(struct pblk *pblk, struct nvm_rq *rqd, unsigned int sentry,
			       struct ppa_addr *ppa_list,
			       unsigned long *lun_bitmap,
			       struct pblk_sec_meta *meta_list,
			       unsigned int valid_secs, int dev_id)
{
	struct pblk_c_ctx *c_ctx = nvm_rq_to_pdu(rqd);
	struct pblk_line *line = pblk_line_get_data(pblk, dev_id);
	struct pblk_emeta *emeta;
	struct pblk_w_ctx *w_ctx;
	__le64 *lba_list;
	u64 paddr;
	struct ppa_addr dev_ppa;
	int nr_secs = pblk->min_write_pgs;
	int i;
    int meta_list_idx; //add by kan
    int meta_list_mod; //add by kan
	struct nvm_tgt_dev *dev = pblk->devs[dev_id]; //add by kan
    struct nvm_geo *geo = &dev->geo; //add by kan 

	if (pblk_line_is_full(line)) {
		// if this line is full, then other lines in the same group all are full
		pblk_md_new_group(pblk);
		line = pblk_line_get_data(pblk, dev_id);
		/*
		struct pblk_line *prev_line = line;
		line = pblk_line_replace_data(pblk, line->dev_id);
		pblk_line_close_meta(pblk, prev_line);
		*/
	}

	emeta = line->emeta;
	lba_list = emeta_to_lbas(pblk, emeta->buf);

	paddr = pblk_alloc_page(pblk, line, nr_secs);

	for (i = 0; i < nr_secs; i++, paddr++) {
		__le64 addr_empty = cpu_to_le64(ADDR_EMPTY);

		/* ppa to be sent to the device */
		ppa_list[i] = addr_to_gen_ppa(pblk, paddr, line->id);

		/* Write context for target bio completion on write buffer. Note
		 * that the write buffer is protected by the sync backpointer,
		 * and a single writer thread have access to each specific entry
		 * at a time. Thus, it is safe to modify the context for the
		 * entry we are setting up for submission without taking any
		 * lock or memory barrier.
		 */
        meta_list_idx = i / geo->ws_min;
        meta_list_mod = ppa_list[i].m.sec % geo->ws_min;
			
		if (i < valid_secs) {
			if (pblk_is_raid1(pblk) && c_ctx->map_id == dev_id) 
				goto fill_rqd;
			else if (pblk_is_raid5(pblk) && !pblk_id_is_parity(pblk, c_ctx->md_id))
				goto fill_rqd;
			else if (!pblk_is_raid1or5(pblk))
				goto fill_rqd;
			else
				continue;
fill_rqd:
			kref_get(&line->ref);
			dev_ppa = pblk_set_ppa_dev_id(ppa_list[i], line->dev_id);
			w_ctx = pblk_rb_w_ctx(&pblk->rwb, sentry + i);
			w_ctx->ppa = dev_ppa; // modified by zhitao
			//w_ctx->ppa = ppa_list[i]; // modified by zhitao
			meta_list[meta_list_idx].lba[meta_list_mod] = cpu_to_le64(w_ctx->lba);//modify by kan

			//for debug
			meta_list[meta_list_idx].d_idx[meta_list_mod] = meta_list_idx; //add by kan for debug
			meta_list[meta_list_idx].d_mod[meta_list_mod] = meta_list_mod; //add by kan for debug
			meta_list[meta_list_idx].d_ppa[meta_list_mod] = ppa_list[i].ppa; //add by kan for debug
			meta_list[meta_list_idx].d_sec_stripe = geo->ws_min; //add by kan for debug
			meta_list[meta_list_idx].d_nr_secs = nr_secs; //add by kan for debug

			lba_list[paddr] = cpu_to_le64(w_ctx->lba);
			if (lba_list[paddr] != addr_empty)
				line->nr_valid_lbas++;
			else
				atomic64_inc(&pblk->pad_wa);
		} else {
			lba_list[paddr] = meta_list[meta_list_idx].lba[meta_list_mod] = addr_empty;//modify by kan
			__pblk_map_invalidate(pblk, line, paddr);
		}
	}
    
    
	pblk_down_rq(pblk, ppa_list, nr_secs, lun_bitmap, dev_id);
}

void pblk_map_rq(struct pblk *pblk, struct nvm_rq *rqd, unsigned int sentry,
		 unsigned long *lun_bitmap, unsigned int valid_secs,
		 unsigned int off, int dev_id)
{
	struct pblk_sec_meta *meta_list = rqd->meta_list;
	unsigned int map_secs;
	int min = pblk->min_write_pgs;
	int i;
    struct nvm_tgt_dev *dev = pblk->devs[dev_id]; //add by kan 
    struct nvm_geo *geo = &dev->geo; //add by kan

	for (i = off; i < rqd->nr_ppas; i += min) {
		map_secs = (i + min > valid_secs) ? (valid_secs % min) : min;
		pblk_map_page_data(pblk, rqd, sentry + i, &rqd->ppa_list[i],
					lun_bitmap, &meta_list[i/geo->ws_min], map_secs, dev_id);
	}

    //add by kan for debug
    //rqd->ppa_list[i+0].ppa = 0x0123456789abcdef; //add by kan for debug
    //rqd->ppa_list[i+1].ppa = 0x1011121314151617; //add by kan for debug
}

/* only if erase_ppa is set, acquire erase semaphore */
void pblk_map_erase_rq(struct pblk *pblk, struct nvm_rq *rqd,
		       unsigned int sentry, unsigned long *lun_bitmap,
		       unsigned int valid_secs, struct ppa_addr *erase_ppa, int dev_id)
{
	struct nvm_tgt_dev *dev = pblk->devs[dev_id];
	struct nvm_geo *geo = &dev->geo;
	struct pblk_line_meta *lm = &pblk->lm;
	struct pblk_sec_meta *meta_list = rqd->meta_list;
	struct pblk_line *e_line, *d_line;
	unsigned int map_secs;
	int min = pblk->min_write_pgs;
	int i, erase_lun;

	for (i = 0; i < rqd->nr_ppas; i += min) {
		map_secs = (i + min > valid_secs) ? (valid_secs % min) : min;
		pblk_map_page_data(pblk, rqd, sentry + i, &rqd->ppa_list[i],
					lun_bitmap, &meta_list[i/geo->ws_min], map_secs, dev_id);

		erase_lun = pblk_ppa_to_pos(geo, rqd->ppa_list[i]);

		/* line can change after page map. We might also be writing the
		 * last line.
		 */
		e_line = pblk_line_get_erase(pblk, dev_id);
		if (!e_line)
			return pblk_map_rq(pblk, rqd, sentry, lun_bitmap,
							valid_secs, i + min, dev_id);

		spin_lock(&e_line->lock);
		if (!test_bit(erase_lun, e_line->erase_bitmap)) {
			set_bit(erase_lun, e_line->erase_bitmap);
			atomic_dec(&e_line->left_eblks);

			*erase_ppa = rqd->ppa_list[i];
			erase_ppa->a.blk = e_line->id;

			spin_unlock(&e_line->lock);

			/* Avoid evaluating e_line->left_eblks */
			return pblk_map_rq(pblk, rqd, sentry, lun_bitmap,
							valid_secs, i + min, dev_id);
		}
		spin_unlock(&e_line->lock);
	}

    //add by kan for debug
    //rqd->ppa_list[i+0].ppa = 0x0123456789abcdef; //add by kan for debug
    //rqd->ppa_list[i+1].ppa = 0x1011121314151617; //add by kan for debug



	d_line = pblk_line_get_data(pblk, dev_id);

	/* line can change after page map. We might also be writing the
	 * last line.
	 */
	e_line = pblk_line_get_erase(pblk, dev_id);
	if (!e_line)
		return;

	/* Erase blocks that are bad in this line but might not be in next */
	if (unlikely(pblk_ppa_empty(*erase_ppa)) &&
			bitmap_weight(d_line->blk_bitmap, lm->blk_per_line)) {
		int bit = -1;

retry:
		bit = find_next_bit(d_line->blk_bitmap,
						lm->blk_per_line, bit + 1);
		if (bit >= lm->blk_per_line)
			return;

		spin_lock(&e_line->lock);
		if (test_bit(bit, e_line->erase_bitmap)) {
			spin_unlock(&e_line->lock);
			goto retry;
		}
		spin_unlock(&e_line->lock);

		set_bit(bit, e_line->erase_bitmap);
		atomic_dec(&e_line->left_eblks);
		*erase_ppa = pblk->luns[dev_id][bit].bppa; /* set ch and lun */
		erase_ppa->a.blk = e_line->id;
	}
}
