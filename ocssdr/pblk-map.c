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

#include "pblk-map.h"

static void pblk_md_new_group(struct pblk *pblk)
{
	struct pblk_md_line_group_set *set = &pblk->md_line_group_set;
	struct pblk_md_line_group *group = &set->line_groups[set->cur_group];
	struct pblk_line *line, *prev_line;
	int nr_unit = group->nr_unit;
	int dev_buf[NVM_MD_MAX_DEV_CNT];
	int i, dev_id;
	int ret;

	// check lines become full at the same time
	for (i = 0;  i < nr_unit; i++) {
		dev_id = group->line_units[i].dev_id;
		line = pblk_line_get_data(pblk, dev_id);

		if (!pblk_line_is_full(line)) {
			pr_err("pblk: line %d of dev %d in past line group not full\n",
					i, dev_id);
		}
	}
	// replace old line group
	for (i = 0; i < nr_unit; i++) {
		dev_id = group->line_units[i].dev_id;
		prev_line  = pblk_line_get_data(pblk, dev_id);
		line = pblk_line_replace_data(pblk, dev_id);
		pblk_line_close_meta(pblk, prev_line);
	}

	// open new group
	set->cur_group++;
	group = &set->line_groups[set->cur_group];
	group->nr_unit = nr_unit;
	ret = pblk_schedule_line_group(pblk, dev_buf, nr_unit);
	if (ret < 0) {
		pr_err("pblk: %s: fail schedule new line_group\n", __func__);
		for (i = 0; i < nr_unit; i++)
			dev_buf[i] = i;
	}
	for (i = 0; i < nr_unit; i++) {
		dev_id = dev_buf[i];
		line = pblk_line_get_data(pblk, dev_id);
		group->line_units[i].dev_id = dev_id;
		group->line_units[i].line_id = line->id;
	}
	
	// update line emeta md info
	for (i = 0; i < group->nr_unit; i++) {
		dev_id = dev_buf[i];
		line = pblk_line_get_data(pblk, dev_id);
		pblk_line_setup_emeta_md(pblk, line);
		pr_info("pblk: %s: new md line_group %d dev %d line %d seq_nr %d,%d\n",
				__func__, set->cur_group, dev_id, line->id, line->seq_nr, line->g_seq_nr);
	}
}

static void pblk_map_prepare_rqd_sd(struct pblk *pblk, struct pblk_line *line,
		struct nvm_rq *rqd, unsigned int sentry,
		struct ppa_addr *ppa_list, struct pblk_sec_meta *meta_list, int i) 
{
	int dev_id = line->dev_id;
	struct nvm_tgt_dev *dev = pblk->devs[dev_id]; //add by kan
    struct nvm_geo *geo = &dev->geo; //add by kan 

	int meta_list_idx = i / geo->ws_min;
	int meta_list_mod = ppa_list[i].m.sec % geo->ws_min;

	struct pblk_emeta *emeta = line->emeta;
	struct pblk_w_ctx *w_ctx;
	__le64 *lba_list = emeta_to_lbas(pblk, emeta->buf);
	__le64 addr_empty = cpu_to_le64(ADDR_EMPTY);
	int nr_secs = pblk->min_write_pgs;
	u64 paddr = pblk_dev_ppa_to_line_addr(pblk, ppa_list[i]);
	struct ppa_addr dev_ppa;

	// fill rqd meta_list, line lba_list, rwb w_ctx
	kref_get(&line->ref);
	dev_ppa = pblk_set_ppa_dev_id(ppa_list[i], line->dev_id);
	w_ctx = pblk_rb_w_ctx(&pblk->rwb, sentry + i);
	w_ctx->ppa = dev_ppa; // modified by zhitao

	meta_list[meta_list_idx].lba[meta_list_mod] = cpu_to_le64(w_ctx->lba);//modify by kan for debug
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
}

static void pblk_map_prepare_rqd_raid1(struct pblk *pblk, struct pblk_line *line,
		struct nvm_rq *rqd, unsigned int sentry,
		struct ppa_addr *ppa_list, struct pblk_sec_meta *meta_list, int i) 
{
	struct pblk_c_ctx *c_ctx = nvm_rq_to_pdu(rqd);
	int dev_id = line->dev_id;
	struct nvm_tgt_dev *dev = pblk->devs[dev_id]; //add by kan
    struct nvm_geo *geo = &dev->geo; //add by kan 

	int meta_list_idx = i / geo->ws_min;
	int meta_list_mod = ppa_list[i].m.sec % geo->ws_min;

	struct pblk_emeta *emeta = line->emeta;
	struct pblk_w_ctx *w_ctx;
	__le64 *lba_list = emeta_to_lbas(pblk, emeta->buf);
	__le64 addr_empty = cpu_to_le64(ADDR_EMPTY);
	int nr_secs = pblk->min_write_pgs;
	u64 paddr = pblk_dev_ppa_to_line_addr(pblk, ppa_list[i]);
	struct ppa_addr dev_ppa;

	w_ctx = pblk_rb_w_ctx(&pblk->rwb, sentry + i);
	// fill rqd meta_list, line lba_list, rwb w_ctx
	if (c_ctx->map_id == dev_id) {
		// map_id as primary backup 
		kref_get(&line->ref);
		dev_ppa = pblk_set_ppa_dev_id(ppa_list[i], line->dev_id);
		w_ctx->ppa = dev_ppa; // modified by zhitao
	}

	meta_list[meta_list_idx].lba[meta_list_mod] = cpu_to_le64(w_ctx->lba);//modify by kan for debug
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
}

// Clear same lba in the same line group
// Red-black tree
static inline void pblk_clean_group_lba_raid0(struct pblk *pblk, int dev_id, u64 paddr, u64 lba)
{
	struct pblk_md_line_group_set *set = &pblk->md_line_group_set;
	struct rb_root *root = &set->l2p_rb_root;
	struct group_l2p_node *l2p_node, *new_node;

	struct pblk_line *line;
	struct pblk_emeta *emeta;

	__le64 *lba_list;
	__le64 addr_empty = cpu_to_le64(ADDR_EMPTY);
	//int unit_id;
	//u64 p;

	/*
	pr_info("pblk: %s: dev %d paddr %llu lba %llu le_lba %llu\n", 
			__func__, dev_id, paddr, lba, cpu_to_le64(lba));
			*/

	new_node = kmalloc(sizeof(struct group_l2p_node), GFP_KERNEL);
	new_node->lba = lba;
	new_node->paddr = paddr;
	new_node->dev_id =  dev_id;
	l2p_node = group_l2p_rb_search(root, lba);

	if (l2p_node) {
		rb_replace_node(&l2p_node->node, &new_node->node, root);

		line = pblk_line_get_data(pblk, l2p_node->dev_id);
		emeta = line->emeta;
		lba_list = emeta_to_lbas(pblk, emeta->buf);
		if (le64_to_cpu(lba_list[l2p_node->paddr]) != lba) {
			pr_err("pblk: %s: corrupt rb search\n", __func__);
		}
		/*
		pr_info("pblk: %s: lba %llu replace dev %d paddr %llu with dev %d paddr %llu\n",
				__func__, lba, l2p_node->dev_id, l2p_node->paddr, dev_id, paddr);
				*/
		lba_list[l2p_node->paddr] = addr_empty;
		line->nr_valid_lbas--;

		kfree(l2p_node);
	} else {
		if (!group_l2p_rb_insert(root, new_node)) {
			pr_err("pblk: %s: corrupt rb insert\n", __func__);
		}
		set->rb_size++;
		/*
		pr_info("pblk: %s: lba %llu insert dev %d paddr %llu into rb, rb_size %d\n",
				__func__, lba, dev_id, paddr, set->rb_size);
				*/
	}

	/*
	for (p = 0; p < paddr; p++) {
		for (unit_id = 0; unit_id < group->nr_unit; unit_id++) {
			dev_id = group->line_units[unit_id].dev_id;

			line = pblk_line_get_data(pblk, dev_id);
			emeta = line->emeta;
			lba_list = emeta_to_lbas(pblk, emeta->buf);

			if (lba_list[p] == lba) {
				lba_list[p] = addr_empty;
			}
		}
	}
	*/
}

static inline void pblk_clean_group_lba_raid5(struct pblk *pblk, int dev_id, u64 paddr, u64 lba)
{
	struct pblk_md_line_group_set *set = &pblk->md_line_group_set;
	struct pblk_md_line_group *group = &set->line_groups[set->cur_group];
	struct pblk_line *line; struct pblk_emeta *emeta; __le64 *lba_list;
	//int unit_id;
	int parity_id = group->nr_unit - 1;
	int parity_dev_id =  group->line_units[parity_id].dev_id;
	line = pblk_line_get_data(pblk, parity_dev_id);
	emeta = line->emeta;
	__le64 *parity_lba_list = emeta_to_lbas(pblk, emeta->buf);
	u64 p;
	__le64 addr_empty = cpu_to_le64(ADDR_EMPTY);

	struct rb_root *root = &set->l2p_rb_root;
	struct group_l2p_node *l2p_node, *new_node;

	new_node = kmalloc(sizeof(struct group_l2p_node), GFP_KERNEL);
	new_node->lba = lba;
	new_node->paddr = paddr;
	new_node->dev_id =  dev_id;
	l2p_node = group_l2p_rb_search(root, lba);

	if (l2p_node) {
		rb_replace_node(&l2p_node->node, &new_node->node, root);

		line = pblk_line_get_data(pblk, l2p_node->dev_id);
		emeta = line->emeta;
		lba_list = emeta_to_lbas(pblk, emeta->buf);
		if (le64_to_cpu(lba_list[l2p_node->paddr]) != lba) {
			pr_err("pblk: %s: corrupt rb search\n", __func__);
		}
		/*
		pr_info("pblk: %s: lba %llu replace dev %d paddr %llu with dev %d paddr %llu\n",
				__func__, lba, l2p_node->dev_id, l2p_node->paddr, dev_id, paddr);
				*/
		p = l2p_node->paddr;
		lba_list[p] = addr_empty;
		parity_lba_list[p] = parity_lba_list[p] ^ lba ^ addr_empty;
		line->nr_valid_lbas--;

		kfree(l2p_node);
	} else {
		if (!group_l2p_rb_insert(root, new_node)) {
			pr_err("pblk: %s: corrupt rb insert\n", __func__);
		}
		set->rb_size++;
		/*
		pr_info("pblk: %s: lba %llu insert dev %d paddr %llu into rb, rb_size %d\n",
				__func__, lba, dev_id, paddr, set->rb_size);
				*/
	}
	/*
	for (p = 0; p < paddr; p++) {
		for (unit_id = 0; unit_id < group->nr_unit - 1; unit_id++) {
			dev_id = group->line_units[unit_id].dev_id;

			line = pblk_line_get_data(pblk, dev_id);
			emeta = line->emeta;
			lba_list = emeta_to_lbas(pblk, emeta->buf);

			if (lba_list[p] == lba) {
				lba_list[p] = addr_empty;
				// bug: partial stripe parity
				parity_lba_list[p] = parity_lba_list[p] ^ lba ^ addr_empty;
			}
		}
	}
	*/
}

static void pblk_map_prepare_rqd_raid0(struct pblk *pblk, struct pblk_line *line,
		struct nvm_rq *rqd, unsigned int sentry,
		struct ppa_addr *ppa_list, struct pblk_sec_meta *meta_list, int i) 
{
	int dev_id = line->dev_id;
	struct nvm_tgt_dev *dev = pblk->devs[dev_id]; //add by kan
    struct nvm_geo *geo = &dev->geo; //add by kan 

	int meta_list_idx = i / geo->ws_min;
	int meta_list_mod = ppa_list[i].m.sec % geo->ws_min;

	struct pblk_emeta *emeta = line->emeta;
	struct pblk_w_ctx *w_ctx;
	__le64 *lba_list = emeta_to_lbas(pblk, emeta->buf);
	__le64 addr_empty = cpu_to_le64(ADDR_EMPTY);
	int nr_secs = pblk->min_write_pgs;
	u64 paddr = pblk_dev_ppa_to_line_addr(pblk, ppa_list[i]);
	struct ppa_addr dev_ppa;

	// fill rqd meta_list, line lba_list, rwb w_ctx
	kref_get(&line->ref);
	dev_ppa = pblk_set_ppa_dev_id(ppa_list[i], line->dev_id);
	w_ctx = pblk_rb_w_ctx(&pblk->rwb, sentry + i);
	w_ctx->ppa = dev_ppa; // modified by zhitao

	meta_list[meta_list_idx].lba[meta_list_mod] = cpu_to_le64(w_ctx->lba);//modify by kan for debug
	meta_list[meta_list_idx].d_idx[meta_list_mod] = meta_list_idx; //add by kan for debug
	meta_list[meta_list_idx].d_mod[meta_list_mod] = meta_list_mod; //add by kan for debug
	meta_list[meta_list_idx].d_ppa[meta_list_mod] = ppa_list[i].ppa; //add by kan for debug
	meta_list[meta_list_idx].d_sec_stripe = geo->ws_min; //add by kan for debug
	meta_list[meta_list_idx].d_nr_secs = nr_secs; //add by kan for debug

	lba_list[paddr] = cpu_to_le64(w_ctx->lba);
	if (lba_list[paddr] != addr_empty) {
#ifdef P2L_CLEAN
		//pblk_clean_group_lba_raid0(pblk, dev_id, paddr, w_ctx->lba);
#endif
		line->nr_valid_lbas++;
	}
	else
		atomic64_inc(&pblk->pad_wa);
}

static void pblk_map_prepare_rqd_raid5(struct pblk *pblk, struct pblk_line *line,
		struct nvm_rq *rqd, unsigned int sentry,
		struct ppa_addr *ppa_list, struct pblk_sec_meta *meta_list, int i) 
{
	struct pblk_c_ctx *c_ctx= nvm_rq_to_pdu(rqd);
	int dev_id = line->dev_id;
	struct nvm_tgt_dev *dev = pblk->devs[dev_id]; //add by kan
    struct nvm_geo *geo = &dev->geo; //add by kan 

	int meta_list_idx = i / geo->ws_min;
	int meta_list_mod = ppa_list[i].m.sec % geo->ws_min;

	struct pblk_emeta *emeta = line->emeta;
	struct pblk_w_ctx *w_ctx;
	__le64 *lba_list = emeta_to_lbas(pblk, emeta->buf);
	__le64 addr_empty = cpu_to_le64(ADDR_EMPTY);
	__le64 lba;
	int nr_secs = pblk->min_write_pgs;
	u64 paddr = pblk_dev_ppa_to_line_addr(pblk, ppa_list[i]);
	struct ppa_addr dev_ppa;
	
	if (!pblk_id_is_parity(pblk, c_ctx->md_id)) {
		// fill rqd meta_list, line lba_list, rwb w_ctx
		kref_get(&line->ref);
		dev_ppa = pblk_set_ppa_dev_id(ppa_list[i], line->dev_id);
		w_ctx = pblk_rb_w_ctx(&pblk->rwb, sentry + i);
		w_ctx->ppa = dev_ppa; // modified by zhitao
		lba = w_ctx->lba;
		// calculate parity of data and metadata
	} else {
		lba = pblk->md_line_group_set.lba_list[i];;
	}

	meta_list[meta_list_idx].lba[meta_list_mod] = cpu_to_le64(lba);//modify by kan for debug
	meta_list[meta_list_idx].d_idx[meta_list_mod] = meta_list_idx; //add by kan for debug
	meta_list[meta_list_idx].d_mod[meta_list_mod] = meta_list_mod; //add by kan for debug
	meta_list[meta_list_idx].d_ppa[meta_list_mod] = ppa_list[i].ppa; //add by kan for debug
	meta_list[meta_list_idx].d_sec_stripe = geo->ws_min; //add by kan for debug
	meta_list[meta_list_idx].d_nr_secs = nr_secs; //add by kan for debug

	lba_list[paddr] = cpu_to_le64(lba);

	if (!pblk_id_is_parity(pblk, c_ctx->md_id)) {
#ifdef P2L_CLEAN
		//pblk_clean_group_lba_raid5(pblk, dev_id, paddr, lba);
#endif
		if (lba_list[paddr] != addr_empty) {
			line->nr_valid_lbas++;
		} else
			atomic64_inc(&pblk->pad_wa);
	}
	else {
		line->nr_valid_lbas++;
	}
}

static void pblk_map_page_data(struct pblk *pblk, struct nvm_rq *rqd, unsigned int sentry,
			       struct ppa_addr *ppa_list,
			       unsigned long *lun_bitmap,
			       struct pblk_sec_meta *meta_list,
			       unsigned int valid_secs, int dev_id)
{
	struct pblk_line *line = pblk_line_get_data(pblk, dev_id);
	struct pblk_emeta *emeta;
	__le64 *lba_list;
	u64 paddr;
	int i;
    int meta_list_idx; //add by kan
    int meta_list_mod; //add by kan
	struct nvm_tgt_dev *dev = pblk->devs[dev_id]; //add by kan
    struct nvm_geo *geo = &dev->geo; //add by kan 
	int nr_secs = pblk->min_write_pgs;

	if (pblk_line_is_full(line)) {
		// if this line is full, then other lines in the same group all are full
		pr_info("pblk: %s: line %d of dev %d is full\n", 
				__func__, line->id, line->dev_id);
		if (!pblk_is_sd(pblk)) {
			pblk_md_new_group(pblk);
			line = pblk_line_get_data(pblk, dev_id);
		} else {
			struct pblk_line *prev_line = line;
			line = pblk_line_replace_data(pblk, line->dev_id);
			pblk_line_close_meta(pblk, prev_line);
		}
		pr_info("pblk: %s: now line %d seq_no %d take charge\n", 
				__func__, line->id, line->seq_nr);
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
			switch (pblk->md_mode) {
				case PBLK_SD:
					pblk_map_prepare_rqd_sd(pblk, line, rqd, sentry, ppa_list, meta_list, i);
					break;
				case PBLK_RAID0:
					pblk_map_prepare_rqd_raid0(pblk, line, rqd, sentry, ppa_list, meta_list, i);
					break;
				case PBLK_RAID1:
					pblk_map_prepare_rqd_raid1(pblk, line, rqd, sentry, ppa_list, meta_list, i);
					break;
				case PBLK_RAID5:
					pblk_map_prepare_rqd_raid5(pblk, line, rqd, sentry, ppa_list, meta_list, i);
					break;
			}
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
