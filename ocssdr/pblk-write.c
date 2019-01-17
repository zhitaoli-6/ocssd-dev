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
 * pblk-write.c - pblk's write path from write buffer to media
 */

#include "pblk.h"

static unsigned long pblk_end_w_bio(struct pblk *pblk, struct nvm_rq *rqd,
				    struct pblk_c_ctx *c_ctx)
{
	struct bio *original_bio;
	struct pblk_rb *rwb = &pblk->rwb;
	unsigned long ret;
	int i;

	for (i = 0; i < c_ctx->nr_valid; i++) {
		struct pblk_w_ctx *w_ctx;
		int pos = c_ctx->sentry + i;
		int flags;

		w_ctx = pblk_rb_w_ctx(rwb, pos);
		flags = READ_ONCE(w_ctx->flags);

		if (flags & PBLK_FLUSH_ENTRY) {
			flags &= ~PBLK_FLUSH_ENTRY;
			/* Release flags on context. Protect from writes */
			smp_store_release(&w_ctx->flags, flags);

#ifdef CONFIG_NVM_DEBUG
			atomic_dec(&rwb->inflight_flush_point);
#endif
		}

		while ((original_bio = bio_list_pop(&w_ctx->bios)))
			bio_endio(original_bio);
	}

	if (c_ctx->nr_padded)
		pblk_bio_free_pages(pblk, rqd->bio, c_ctx->nr_valid,
							c_ctx->nr_padded);

#ifdef CONFIG_NVM_DEBUG
	atomic_long_add(rqd->nr_ppas, &pblk->sync_writes);
#endif

	ret = pblk_rb_sync_advance(&pblk->rwb, c_ctx->nr_valid);

	bio_put(rqd->bio);
	pblk_free_rqd(pblk, rqd, PBLK_WRITE);
	
	if (pblk->md_mode == PBLK_RAID1 || pblk->md_mode == PBLK_RAID5) {
		kfree(c_ctx->cpl);
	}

	return ret;
}

static unsigned long pblk_end_queued_w_bio(struct pblk *pblk,
					   struct nvm_rq *rqd,
					   struct pblk_c_ctx *c_ctx)
{
	list_del(&c_ctx->list);
	return pblk_end_w_bio(pblk, rqd, c_ctx);
}

static void pblk_write_cpl_sync_rb(struct pblk *pblk, struct nvm_rq *rqd,
				struct pblk_c_ctx *c_ctx)
{
	struct pblk_c_ctx *c, *r;
	unsigned long flags;
	unsigned long pos;
	pos = pblk_rb_sync_init(&pblk->rwb, &flags);
	if (pos == c_ctx->sentry) {
		pos = pblk_end_w_bio(pblk, rqd, c_ctx);

retry:
		list_for_each_entry_safe(c, r, &pblk->compl_list, list) {
			rqd = nvm_rq_from_c_ctx(c);
			if (c->sentry == pos) {
				pos = pblk_end_queued_w_bio(pblk, rqd, c);
				goto retry; 
			}
		}
	} else {
		WARN_ON(nvm_rq_from_c_ctx(c_ctx) != rqd);
		list_add_tail(&c_ctx->list, &pblk->compl_list);
	}
	pblk_rb_sync_end(&pblk->rwb, &flags);
}

static void pblk_complete_write(struct pblk *pblk, struct nvm_rq *rqd,
				struct pblk_c_ctx *c_ctx)
{
	struct pblk_md_cpl *cpl = c_ctx->cpl;
	struct pblk_c_ctx *c, *r;
	struct nvm_rq *tmp_rqd;
	unsigned int done = 0;
	int md_id;
	int dev_id;
	dev_id = pblk_get_rq_dev_id(pblk, rqd);
	WARN_ON(dev_id == -1);
	if(dev_id == -1){
		pr_err("pblk: %s rqd undefined dev\n", __func__);
		return;
	}

#ifdef CONFIG_NVM_DEBUG
	atomic_long_sub(c_ctx->nr_valid, &pblk->inflight_writes);
#endif

	pblk_up_rq(pblk, rqd->ppa_list, rqd->nr_ppas, c_ctx->lun_bitmap, dev_id);
	
	if (pblk->md_mode == PBLK_RAID1) {
		md_id = c_ctx->md_id;

		spin_lock(&cpl->lock);
		WARN_ON(test_and_set_bit(md_id, &cpl->cpl_map));
		done = bitmap_weight(&cpl->cpl_map, cpl->nr_io);
		pr_info("pblk: md_id %d, end_io_write %u/%u\n", md_id, done, cpl->nr_io);
		if (!bitmap_full(&cpl->cpl_map, cpl->nr_io)) {
			list_add_tail(&c_ctx->list, &cpl->cpl_list);
			spin_unlock(&cpl->lock);
			return;
		}
		spin_unlock(&cpl->lock);

		done = 1;
		// free bio/rqd
		list_for_each_entry_safe(c, r, &cpl->cpl_list, list) {
			tmp_rqd = nvm_rq_from_c_ctx(c);
			if (c->nr_padded)
				pblk_bio_free_pages(pblk, tmp_rqd->bio, c->nr_valid,
									c->nr_padded);
			bio_put(tmp_rqd->bio);
			pblk_free_rqd(pblk, rqd, PBLK_WRITE);

			list_del(&c->list);

			done++;
		}
		if (done != cpl->nr_io) {
			pr_err("pblk: %s PBLK_RAID1 inconsistent done %u with nr_io %u\n",
					__func__, done, cpl->nr_io);
		}
		pblk_write_cpl_sync_rb(pblk, rqd, c_ctx);
	} else if (pblk->md_mode == PBLK_RAID5) {
		md_id = c_ctx->md_id;

		spin_lock(&cpl->lock);
		WARN_ON(test_and_set_bit(md_id, &cpl->cpl_map));
		list_add_tail(&c_ctx->list, &cpl->cpl_list);

		done = bitmap_weight(&cpl->cpl_map, cpl->nr_io);
		pr_info("pblk: md_id %d, end_io_write %u/%u\n", md_id, done, cpl->nr_io);
		if (!bitmap_full(&cpl->cpl_map, cpl->nr_io)) {
			spin_unlock(&cpl->lock);
			return;
		}
		spin_unlock(&cpl->lock);

		list_for_each_entry_safe(c, r, &cpl->cpl_list, list) {
			tmp_rqd = nvm_rq_from_c_ctx(c);
			list_del(&c->list);
			if (c->md_id == cpl->nr_io - 1) {
				if (c->nr_padded)
					pblk_bio_free_pages(pblk, tmp_rqd->bio, c->nr_valid,
										c->nr_padded);
				bio_put(tmp_rqd->bio);
				pblk_free_rqd(pblk, rqd, PBLK_WRITE);
				continue;
			}

			pblk_write_cpl_sync_rb(pblk, tmp_rqd, c);
		}
	} else {
		pblk_write_cpl_sync_rb(pblk, rqd, c_ctx);
	}
}

/* When a write fails, we are not sure whether the block has grown bad or a page
 * range is more susceptible to write errors. If a high number of pages fail, we
 * assume that the block is bad and we mark it accordingly. In all cases, we
 * remap and resubmit the failed entries as fast as possible; if a flush is
 * waiting on a completion, the whole stack would stall otherwise.
 */
static void pblk_end_w_fail(struct pblk *pblk, struct nvm_rq *rqd)
{
	void *comp_bits = &rqd->ppa_status;
	struct pblk_c_ctx *c_ctx = nvm_rq_to_pdu(rqd);
	struct pblk_rec_ctx *recovery;
	struct ppa_addr *ppa_list = rqd->ppa_list;
	int nr_ppas = rqd->nr_ppas;
	unsigned int c_entries;
	int bit, ret;

	if (unlikely(nr_ppas == 1))
		ppa_list = &rqd->ppa_addr;

	recovery = mempool_alloc(pblk->rec_pool, GFP_ATOMIC);

	INIT_LIST_HEAD(&recovery->failed);

	bit = -1;
	while ((bit = find_next_bit(comp_bits, nr_ppas, bit + 1)) < nr_ppas) {
		struct pblk_rb_entry *entry;
		struct ppa_addr ppa;

		/* Logic error */
		if (bit > c_ctx->nr_valid) {
			WARN_ONCE(1, "pblk: corrupted write request\n");
			mempool_free(recovery, pblk->rec_pool);
			goto out;
		}

		ppa = ppa_list[bit];
		// bugs: return NULL, marked by zhitao
		entry = pblk_rb_sync_scan_entry(&pblk->rwb, &ppa);
		if (!entry) {
			pr_err("pblk: could not scan entry on write failure\n");
			mempool_free(recovery, pblk->rec_pool);
			goto out;
		}

		/* The list is filled first and emptied afterwards. No need for
		 * protecting it with a lock
		 */
		list_add_tail(&entry->index, &recovery->failed);
	}

	c_entries = find_first_bit(comp_bits, nr_ppas);
	ret = pblk_recov_setup_rq(pblk, c_ctx, recovery, comp_bits, c_entries);
	if (ret) {
		pr_err("pblk: could not recover from write failure\n");
		mempool_free(recovery, pblk->rec_pool);
		goto out;
	}

	INIT_WORK(&recovery->ws_rec, pblk_submit_rec);
	queue_work(pblk->close_wq, &recovery->ws_rec);

out:
	pblk_complete_write(pblk, rqd, c_ctx);
}

static void pblk_end_io_write(struct nvm_rq *rqd)
{
	struct pblk *pblk = rqd->private;
	struct pblk_c_ctx *c_ctx = nvm_rq_to_pdu(rqd);

	if (rqd->error) {
		pblk_log_write_err(pblk, rqd);
		return pblk_end_w_fail(pblk, rqd);
	}
#ifdef CONFIG_NVM_DEBUG
	else
		WARN_ONCE(rqd->bio->bi_status, "pblk: corrupted write error\n");
#endif

	pblk_complete_write(pblk, rqd, c_ctx);
	atomic_dec(&pblk->inflight_io);
}

static void pblk_end_io_write_meta(struct nvm_rq *rqd)
{
	struct pblk *pblk = rqd->private;
	struct pblk_g_ctx *m_ctx = nvm_rq_to_pdu(rqd);
	struct pblk_line *line = m_ctx->private;
	struct pblk_emeta *emeta = line->emeta;
	int sync;

	pblk_up_page(pblk, rqd->ppa_list, rqd->nr_ppas, line->dev_id);

	if (rqd->error) {
		pblk_log_write_err(pblk, rqd);
		pr_err("pblk: metadata I/O failed. Line %d\n", line->id);
	}

	sync = atomic_add_return(rqd->nr_ppas, &emeta->sync);
	if (sync == emeta->nr_entries)
		pblk_gen_run_ws(pblk, line, NULL, pblk_line_close_ws,
						GFP_ATOMIC, pblk->close_wq);

	pblk_free_rqd(pblk, rqd, PBLK_WRITE_INT);

	atomic_dec(&pblk->inflight_io);
}

static int pblk_alloc_w_rq(struct pblk *pblk, struct nvm_rq *rqd,
			   unsigned int nr_secs,
			   nvm_end_io_fn(*end_io), int dev_id)
{
	struct nvm_tgt_dev *dev = pblk->devs[dev_id];

	/* Setup write request */
	rqd->opcode = NVM_OP_PWRITE;
	rqd->nr_ppas = nr_secs;
	rqd->flags = pblk_set_progr_mode(pblk, PBLK_WRITE);
	rqd->private = pblk;
	rqd->end_io = end_io;

	rqd->meta_list = nvm_dev_dma_alloc(dev->parent, GFP_KERNEL,
							&rqd->dma_meta_list);
    //int size = pblk_dma_meta_size + pblk_dma_ppa_size; //add by kan
    //rqd->meta_list = dma_alloc_coherent(ctrl->dev, size, &rqd->dma_meta_list, GFP_KERNEL); //modify by kan
	
    if (!rqd->meta_list) {
        printk("meta list dma cannot alloc\n");
		return -ENOMEM;
    }
	rqd->ppa_list = rqd->meta_list + pblk_dma_meta_size;
	rqd->dma_ppa_list = rqd->dma_meta_list + pblk_dma_meta_size;

	return 0;
}

static int pblk_setup_w_rq(struct pblk *pblk, struct nvm_rq *rqd,
			   struct ppa_addr *erase_ppa, int dev_id)
{
	struct pblk_line_meta *lm = &pblk->lm;
	struct pblk_line *e_line = pblk_line_get_erase(pblk, dev_id);
	struct pblk_c_ctx *c_ctx = nvm_rq_to_pdu(rqd);
	unsigned int valid = c_ctx->nr_valid;
	unsigned int padded = c_ctx->nr_padded;
	unsigned int nr_secs = valid + padded;
	unsigned long *lun_bitmap;
	int ret;

	lun_bitmap = kzalloc(lm->lun_bitmap_len, GFP_KERNEL);
	if (!lun_bitmap)
		return -ENOMEM;
	c_ctx->lun_bitmap = lun_bitmap;

	ret = pblk_alloc_w_rq(pblk, rqd, nr_secs, pblk_end_io_write, dev_id);
	if (ret) {
		kfree(lun_bitmap);
		return ret;
	}

	if (likely(!e_line || !atomic_read(&e_line->left_eblks)))
		pblk_map_rq(pblk, rqd, c_ctx->sentry, lun_bitmap, valid, 0, dev_id);
	else
		pblk_map_erase_rq(pblk, rqd, c_ctx->sentry, lun_bitmap,
							valid, erase_ppa, dev_id);

	return 0;
}

int pblk_setup_w_rec_rq(struct pblk *pblk, struct nvm_rq *rqd,
			struct pblk_c_ctx *c_ctx, int dev_id)
{
	struct pblk_line_meta *lm = &pblk->lm;
	unsigned long *lun_bitmap;
	int ret;

	lun_bitmap = kzalloc(lm->lun_bitmap_len, GFP_KERNEL);
	if (!lun_bitmap)
		return -ENOMEM;

	c_ctx->lun_bitmap = lun_bitmap;

	ret = pblk_alloc_w_rq(pblk, rqd, rqd->nr_ppas, pblk_end_io_write, dev_id);
	if (ret)
		return ret;

	pblk_map_rq(pblk, rqd, c_ctx->sentry, lun_bitmap, c_ctx->nr_valid, 0, dev_id);

	rqd->ppa_status = (u64)0;
	rqd->flags = pblk_set_progr_mode(pblk, PBLK_WRITE);

	return ret;
}

static int pblk_calc_secs_to_sync(struct pblk *pblk, unsigned int secs_avail,
				  unsigned int secs_to_flush)
{
	int secs_to_sync;

	secs_to_sync = pblk_calc_secs(pblk, secs_avail, secs_to_flush);

#ifdef CONFIG_NVM_DEBUG
	if ((!secs_to_sync && secs_to_flush)
			|| (secs_to_sync < 0)
			|| (secs_to_sync > secs_avail && !secs_to_flush)) {
		pr_err("pblk: bad sector calculation (a:%d,s:%d,f:%d)\n",
				secs_avail, secs_to_sync, secs_to_flush);
	}
#endif

	return secs_to_sync;
}

int pblk_submit_meta_io(struct pblk *pblk, struct pblk_line *meta_line)
{
	int dev_id = meta_line->dev_id;
	struct nvm_tgt_dev *dev = pblk->devs[dev_id];
	struct nvm_geo *geo = &dev->geo;
	struct pblk_line_mgmt *l_mg = &pblk->l_mg[dev_id];
	struct pblk_line_meta *lm = &pblk->lm;
	struct pblk_emeta *emeta = meta_line->emeta;
	struct pblk_g_ctx *m_ctx;
	struct bio *bio;
	struct nvm_rq *rqd;
	void *data;
	u64 paddr;
	int rq_ppas = pblk->min_write_pgs;
	int id = meta_line->id;
	int rq_len;
	int i, j;
	int ret;

	rqd = pblk_alloc_rqd(pblk, PBLK_WRITE_INT);

	m_ctx = nvm_rq_to_pdu(rqd);
	m_ctx->private = meta_line;

	rq_len = rq_ppas * geo->csecs;
	data = ((void *)emeta->buf) + emeta->mem;

	bio = pblk_bio_map_addr(pblk, data, rq_ppas, rq_len,
					l_mg->emeta_alloc_type, GFP_KERNEL, dev_id);
	if (IS_ERR(bio)) {
		ret = PTR_ERR(bio);
		goto fail_free_rqd;
	}
	bio->bi_iter.bi_sector = 0; /* internal bio */
	bio_set_op_attrs(bio, REQ_OP_WRITE, 0);
	rqd->bio = bio;
	rqd->dev = dev;

	ret = pblk_alloc_w_rq(pblk, rqd, rq_ppas, pblk_end_io_write_meta, dev_id);
	if (ret)
		goto fail_free_bio;

	for (i = 0; i < rqd->nr_ppas; ) {
		spin_lock(&meta_line->lock);
		paddr = __pblk_alloc_page(pblk, meta_line, rq_ppas);
		spin_unlock(&meta_line->lock);
		for (j = 0; j < rq_ppas; j++, i++, paddr++)
			rqd->ppa_list[i] = addr_to_gen_ppa(pblk, paddr, id);
	}

	emeta->mem += rq_len;
	if (emeta->mem >= lm->emeta_len[0]) {
		spin_lock(&l_mg->close_lock);
		list_del(&meta_line->list);
		spin_unlock(&l_mg->close_lock);
	}

	pblk_down_page(pblk, rqd->ppa_list, rqd->nr_ppas, dev_id);

	ret = pblk_submit_io(pblk, rqd, dev_id);
	if (ret) {
		pr_err("pblk: emeta I/O submission failed: %d\n", ret);
		goto fail_rollback;
	}

	return NVM_IO_OK;

fail_rollback:
	pblk_up_page(pblk, rqd->ppa_list, rqd->nr_ppas, dev_id);
	spin_lock(&l_mg->close_lock);
	pblk_dealloc_page(pblk, meta_line, rq_ppas);
	list_add(&meta_line->list, &meta_line->list);
	spin_unlock(&l_mg->close_lock);
fail_free_bio:
	bio_put(bio);
fail_free_rqd:
	pblk_free_rqd(pblk, rqd, PBLK_WRITE_INT);
	return ret;
}

static inline bool pblk_valid_meta_ppa(struct pblk *pblk,
				       struct pblk_line *meta_line,
				       struct nvm_rq *data_rqd)
{
	int dev_id = meta_line->dev_id;
	struct nvm_tgt_dev *dev = pblk->devs[dev_id];
	struct nvm_geo *geo = &dev->geo;
	struct pblk_c_ctx *data_c_ctx = nvm_rq_to_pdu(data_rqd);
	struct pblk_line *data_line = pblk_line_get_data(pblk, dev_id);
	struct ppa_addr ppa, ppa_opt;
	u64 paddr;
	int pos_opt;

	/* Schedule a metadata I/O that is half the distance from the data I/O
	 * with regards to the number of LUNs forming the pblk instance. This
	 * balances LUN conflicts across every I/O.
	 *
	 * When the LUN configuration changes (e.g., due to GC), this distance
	 * can align, which would result on metadata and data I/Os colliding. In
	 * this case, modify the distance to not be optimal, but move the
	 * optimal in the right direction.
	 */
	paddr = pblk_lookup_page(pblk, meta_line);
	ppa = addr_to_gen_ppa(pblk, paddr, 0);
	ppa_opt = addr_to_gen_ppa(pblk, paddr + data_line->meta_distance, 0);
	pos_opt = pblk_ppa_to_pos(geo, ppa_opt);

	if (test_bit(pos_opt, data_c_ctx->lun_bitmap) ||
				test_bit(pos_opt, data_line->blk_bitmap))
		return true;

	if (unlikely(pblk_ppa_comp(ppa_opt, ppa)))
		data_line->meta_distance--;

	return false;
}

static struct pblk_line *pblk_should_submit_meta_io(struct pblk *pblk,
						    struct nvm_rq *data_rqd, int dev_id)
{
	struct pblk_line_meta *lm = &pblk->lm;
	struct pblk_line_mgmt *l_mg = &pblk->l_mg[dev_id];
	struct pblk_line *meta_line;

	spin_lock(&l_mg->close_lock);
retry:
	if (list_empty(&l_mg->emeta_list)) {
		spin_unlock(&l_mg->close_lock);
		return NULL;
	}
	meta_line = list_first_entry(&l_mg->emeta_list, struct pblk_line, list);
	if (meta_line->emeta->mem >= lm->emeta_len[0])
		goto retry;
	spin_unlock(&l_mg->close_lock);

	if (!pblk_valid_meta_ppa(pblk, meta_line, data_rqd))
		return NULL;

	return meta_line;
}

static int pblk_submit_io_set(struct pblk *pblk, struct nvm_rq *rqd, int dev_id)
{
	struct ppa_addr erase_ppa;
	struct pblk_line *meta_line;
	int err;

	pblk_ppa_set_empty(&erase_ppa);

	/* Assign lbas to ppas and populate request structure */
	err = pblk_setup_w_rq(pblk, rqd, &erase_ppa, dev_id);
	if (err) {
		pr_err("pblk: could not setup write request: %d\n", err);
		return NVM_IO_ERR;
	}

	meta_line = pblk_should_submit_meta_io(pblk, rqd, dev_id);

	/* Submit data write for current data line */
	err = pblk_submit_io(pblk, rqd, dev_id);
	if (err) {
		pr_err("pblk: data I/O submission failed: %d\n", err);
		return NVM_IO_ERR;
	}

	if (!pblk_ppa_empty(erase_ppa)) {
		/* Submit erase for next data line */
		if (pblk_blk_erase_async(pblk, erase_ppa, dev_id)) {
			struct pblk_line *e_line = pblk_line_get_erase(pblk, dev_id);
			struct nvm_tgt_dev *dev = pblk->devs[dev_id];
			struct nvm_geo *geo = &dev->geo;
			int bit;

			atomic_inc(&e_line->left_eblks);
			bit = pblk_ppa_to_pos(geo, erase_ppa);
			WARN_ON(!test_and_clear_bit(bit, e_line->erase_bitmap));
		}
	}

	if (meta_line) {
		/* Submit metadata write for previous data line */
		err = pblk_submit_meta_io(pblk, meta_line);
		if (err) {
			pr_err("pblk: metadata I/O submission failed: %d", err);
			return NVM_IO_ERR;
		}
	}

	return NVM_IO_OK;
}

static void pblk_free_write_rqd(struct pblk *pblk, struct nvm_rq *rqd)
{
	struct pblk_c_ctx *c_ctx = nvm_rq_to_pdu(rqd);
	struct bio *bio = rqd->bio;

	if (c_ctx->nr_padded)
		pblk_bio_free_pages(pblk, bio, c_ctx->nr_valid,
							c_ctx->nr_padded);
}

static int pblk_schedule_write(struct pblk *pblk) 
{
	int dev_id = -1;
	struct pblk_md_line_group_set *set = &pblk->md_line_group_set;
	struct pblk_md_line_group *group = &set->line_groups[set->cur_group];
	int *unit_id_ptr = &pblk->sche_meta.unit_id;
	switch (pblk->md_mode) {
		case PBLK_SD:
			dev_id = DEFAULT_DEV_ID;
			break;
		case PBLK_RAID1:
			dev_id = group->line_units[*unit_id_ptr].dev_id;
			break;
		case PBLK_RAID0:
			dev_id = group->line_units[*unit_id_ptr].dev_id;
			*unit_id_ptr = (*unit_id_ptr+1) % group->nr_unit;
			break;
		case PBLK_RAID5:
			dev_id = group->line_units[*unit_id_ptr].dev_id;
			*unit_id_ptr = (*unit_id_ptr+1) % group->nr_unit;
			break;
		default:
			pr_err("pblk: schedule_write unexpected pblk md_mode\n");
	}
	return dev_id;
}

static void pblk_md_new_stripe(struct pblk *pblk, bool clear)
{
	struct pblk_md_line_group_set *set = &pblk->md_line_group_set;

	if (clear)
		memset(set->parity, 0, PAGE_SIZE*pblk->min_write_pgs);

	set->cpl = kzalloc(sizeof(struct pblk_md_cpl), GFP_KERNEL);

	set->cpl->nr_io = set->line_groups[set->cur_group].nr_unit;
	INIT_LIST_HEAD(&set->cpl->cpl_list);
	bitmap_zero(&set->cpl->cpl_map, set->cpl->nr_io);
	spin_lock_init(&set->cpl->lock);
	
	pblk->sche_meta.unit_id = 0;
}

static int pblk_submit_raid1_write(struct pblk *pblk, unsigned long pos, 
		unsigned int secs_to_sync, unsigned int secs_avail)
{
	struct nvm_rq *rqd;
	struct bio *bio;
	struct pblk_md_line_group_set *set = &pblk->md_line_group_set;
	struct pblk_md_line_group *group = &set->line_groups[set->cur_group];
	int unit_id = pblk->sche_meta.unit_id;
	int dev_id;
	bool set_flag;

	for (unit_id++; unit_id < group->nr_unit; unit_id++) {
		dev_id = group->line_units[unit_id].dev_id;

		bio = bio_alloc(GFP_KERNEL, secs_to_sync);
		bio->bi_iter.bi_sector = 0; /* internal bio */
		bio_set_op_attrs(bio, REQ_OP_WRITE, 0);

		rqd = pblk_alloc_rqd(pblk, PBLK_WRITE);
		rqd->bio = bio;
		rqd->dev = pblk->devs[dev_id];

		if (unit_id == group->nr_unit - 1) {
			set_flag = true;
		} else {
			set_flag = false;
		}

		if (pblk_rb_read_to_bio(&pblk->rwb, rqd, pos, secs_to_sync,
									secs_avail, set_flag)) {
			pr_err("pblk: corrupted write bio\n");
			goto fail_put_bio;
		}

		if (pblk_submit_io_set(pblk, rqd, dev_id))
			goto fail_free_bio;

#ifdef CONFIG_NVM_DEBUG
		atomic_long_add(secs_to_sync, &pblk->sub_writes);
#endif
	}
	pblk_md_new_stripe(pblk, false);
	return 0;
fail_free_bio:
	pblk_free_write_rqd(pblk, rqd);
fail_put_bio:
	bio_put(bio);
	pblk_free_rqd(pblk, rqd, PBLK_WRITE);
	return 1;
}

static int pblk_submit_raid5_write(struct pblk *pblk, unsigned long pos,
		unsigned int secs_to_sync, unsigned int secs_avail) 
{
	struct pblk_rb *rb = &pblk->rwb;
	struct pblk_rb_entry *entry;

	struct pblk_md_line_group_set *set = &pblk->md_line_group_set;
	struct pblk_md_line_group *group = &set->line_groups[set->cur_group];
	int unit_id = pblk->sche_meta.unit_id;

	struct nvm_rq *rqd;
	struct pblk_c_ctx *c_ctx;
	struct bio *bio;
	int dev_id;

	unsigned int pad = secs_to_sync - secs_avail;
	unsigned int to_read = secs_avail;

	
	unsigned int size = PAGE_SIZE / sizeof(unsigned long);
	unsigned long *parity = set->parity;
	unsigned long *data;

	unsigned int i, j;
	int ret = 0;

	// update parity or submit parity
	for (i = 0; i < to_read; i++) {
		entry = &rb->entries[pos];
		data = entry->data;
		
		for (j = 0; j < size; j++) {
			parity[i*size + j] ^= data[j];
		}
		pos = (pos + 1) & (rb->nr_entries - 1);
	}
	// assume pad vales are 0. todo
	for (i = 0; i < pad; i++) {
		for (j = 0; j < size; j++) {
			parity[to_read*size + i*size + j] ^= 0;
		}
	}
	if (unit_id == group->nr_unit-1) {
		dev_id = group->line_units[unit_id].dev_id;

		unsigned long data_len = PAGE_SIZE * pblk->min_write_pgs;
		void *buf = vmalloc(data_len);
		if (!buf) {
			pr_err("pblk: could not alloc buf for parity\n");
			return 1;
		}
		memcpy(buf, parity, data_len);

		bio = pblk_bio_map_addr(pblk, buf, secs_to_sync, data_len, 
				PBLK_VMALLOC_META, GFP_KERNEL, dev_id);
		bio->bi_iter.bi_sector = 0;
		bio_set_op_attrs(bio, REQ_OP_WRITE, 0);

		rqd = pblk_alloc_rqd(pblk, PBLK_WRITE);
		rqd->bio = bio;
		rqd->dev = pblk->devs[dev_id];

		c_ctx = nvm_rq_to_pdu(rqd);
		c_ctx->sentry = EMPTY_ENTRY;
		c_ctx->nr_padded = 0;
		c_ctx->nr_valid = pblk->min_write_pgs;
		c_ctx->md_id = unit_id;
		c_ctx->cpl = set->cpl;

		// parity end_io callback function???
		if (pblk_submit_io_set(pblk, rqd, dev_id))
			goto fail_free_bio;

		pblk_md_new_stripe(pblk, true);
		return 0;
fail_free_bio:
		bio_put(bio);
		pblk_free_rqd(pblk, rqd, PBLK_WRITE);
		return 1;
	}
	return 0;
}

static int pblk_submit_md_write(struct pblk *pblk, unsigned long pos, 
		unsigned int secs_to_sync, unsigned int secs_avail)
{
	int ret;
	
	if (secs_to_sync != pblk->min_write_pgs) {
		pr_err("pblk: %s inconsistent sync %u, min_pgs %u\n", __func__,
				secs_to_sync, pblk->min_write_pgs);
		return 1;
	}

	switch (pblk->md_mode) {
		case PBLK_RAID1:
			ret = pblk_submit_raid1_write(pblk, pos, secs_to_sync, secs_avail);
			break;
		case PBLK_RAID5:
			ret = pblk_submit_raid5_write(pblk, pos, secs_to_sync, secs_avail);
			break;
		default:
			ret = 0;
	}
	return ret;
}

static int pblk_submit_write(struct pblk *pblk)
{
	struct bio *bio;
	struct nvm_rq *rqd;
	unsigned int secs_avail, secs_to_sync, secs_to_com;
	unsigned int secs_to_flush;
	unsigned long pos;
	int dev_id;
	bool set_flag;

	/* If there are no sectors in the cache, flushes (bios without data)
	 * will be cleared on the cache threads
	 */
	secs_avail = pblk_rb_read_count(&pblk->rwb);
	if (!secs_avail)
		return 1;

	secs_to_flush = pblk_rb_flush_point_count(&pblk->rwb);
	if (!secs_to_flush && secs_avail < pblk->min_write_pgs)
		return 1;

	secs_to_sync = pblk_calc_secs_to_sync(pblk, secs_avail, secs_to_flush);
	if (secs_to_sync > pblk->max_write_pgs) {
		pr_err("pblk: bad buffer sync calculation\n");
		return 1;
	}

	secs_to_com = (secs_to_sync > secs_avail) ? secs_avail : secs_to_sync;
	pos = pblk_rb_read_commit(&pblk->rwb, secs_to_com);

	// decide which device of this IO
	dev_id = pblk_schedule_write(pblk);

	bio = bio_alloc(GFP_KERNEL, secs_to_sync);
	bio->bi_iter.bi_sector = 0; /* internal bio */
	bio_set_op_attrs(bio, REQ_OP_WRITE, 0);

	rqd = pblk_alloc_rqd(pblk, PBLK_WRITE);
	rqd->bio = bio;
	rqd->dev = pblk->devs[dev_id];

	if (pblk->md_mode == PBLK_RAID1) {
		set_flag = false;
	} else {
		set_flag = true;
	}

	if (pblk_rb_read_to_bio(&pblk->rwb, rqd, pos, secs_to_sync,
								secs_avail, set_flag)) {
		pr_err("pblk: corrupted write bio\n");
		goto fail_put_bio;
	}

	if (pblk_submit_io_set(pblk, rqd, dev_id))
		goto fail_free_bio;

#ifdef CONFIG_NVM_DEBUG
	atomic_long_add(secs_to_sync, &pblk->sub_writes);
#endif

	if (pblk_submit_md_write(pblk, pos, secs_to_sync, secs_avail)) {
		goto fail_md;
	}

	return 0;
fail_md:
	pr_err("pblk: %s fail md write submission\n", __func__);
fail_free_bio:
	pblk_free_write_rqd(pblk, rqd);
fail_put_bio:
	bio_put(bio);
	pblk_free_rqd(pblk, rqd, PBLK_WRITE);

	return 1;
}

int pblk_write_ts(void *data)
{
	struct pblk *pblk = data;

	while (!kthread_should_stop()) {
		if (!pblk_submit_write(pblk))
			continue;
		set_current_state(TASK_INTERRUPTIBLE);
		io_schedule();
	}

	return 0;
}
