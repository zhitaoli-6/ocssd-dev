/*
 * Copyright (C) 2016 CNEX Labs
 * Initial: Javier Gonzalez <javier@cnexlabs.com>
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
 * pblk-recovery.c - pblk's recovery path
 */


// md-bugs: recovery work left as in future work, so dev_id contained in this file
// may bring bugs, which is modified only for passing compiler check.

#include "pblk.h"

void pblk_submit_rec(struct work_struct *work)
{
	
	struct pblk_rec_ctx *recovery =
			container_of(work, struct pblk_rec_ctx, ws_rec);
	struct pblk *pblk = recovery->pblk;
	struct nvm_rq *rqd = recovery->rqd;
	struct pblk_c_ctx *c_ctx = nvm_rq_to_pdu(rqd);
	struct bio *bio;
	unsigned int nr_rec_secs;
	unsigned int pgs_read;
	int ret;
	pr_err("pblk rec: func(%s) bug here, never be called in this version\n", __func__);

	nr_rec_secs = bitmap_weight((unsigned long int *)&rqd->ppa_status,
								NVM_MAX_VLBA);

	bio = bio_alloc(GFP_KERNEL, nr_rec_secs);

	bio->bi_iter.bi_sector = 0;
	bio_set_op_attrs(bio, REQ_OP_WRITE, 0);
	rqd->bio = bio;
	rqd->nr_ppas = nr_rec_secs;

	pgs_read = pblk_rb_read_to_bio_list(&pblk->rwb, bio, &recovery->failed,
								nr_rec_secs);
	if (pgs_read != nr_rec_secs) {
		pr_err("pblk: could not read recovery entries\n");
		goto err;
	}

	if (pblk_setup_w_rec_rq(pblk, rqd, c_ctx, DEFAULT_DEV_ID)) {
		pr_err("pblk: could not setup recovery request\n");
		goto err;
	}

#ifdef CONFIG_NVM_DEBUG
	atomic_long_add(nr_rec_secs, &pblk->recov_writes);
#endif

	rqd->dev = pblk->devs[DEFAULT_DEV_ID];
	ret = pblk_submit_io(pblk, rqd, DEFAULT_DEV_ID);
	if (ret) {
		pr_err("pblk: I/O submission failed: %d\n", ret);
		goto err;
	}

	mempool_free(recovery, pblk->rec_pool);
	return;

err:
	bio_put(bio);
	pblk_free_rqd(pblk, rqd, PBLK_WRITE);
}

int pblk_recov_setup_rq(struct pblk *pblk, struct pblk_c_ctx *c_ctx,
			struct pblk_rec_ctx *recovery, u64 *comp_bits,
			unsigned int comp)
{
	struct nvm_rq *rec_rqd;
	struct pblk_c_ctx *rec_ctx;
	int nr_entries = c_ctx->nr_valid + c_ctx->nr_padded;
	pr_info("pblk rec: func(%s) called here, warning\n", __func__);

	rec_rqd = pblk_alloc_rqd(pblk, PBLK_WRITE);
	rec_ctx = nvm_rq_to_pdu(rec_rqd);

	/* Copy completion bitmap, but exclude the first X completed entries */
	bitmap_shift_right((unsigned long int *)&rec_rqd->ppa_status,
				(unsigned long int *)comp_bits,
				comp, NVM_MAX_VLBA);

	/* Save the context for the entries that need to be re-written and
	 * update current context with the completed entries.
	 */
	rec_ctx->sentry = pblk_rb_wrap_pos(&pblk->rwb, c_ctx->sentry + comp);
	if (comp >= c_ctx->nr_valid) {
		rec_ctx->nr_valid = 0;
		rec_ctx->nr_padded = nr_entries - comp;

		c_ctx->nr_padded = comp - c_ctx->nr_valid;
	} else {
		rec_ctx->nr_valid = c_ctx->nr_valid - comp;
		rec_ctx->nr_padded = c_ctx->nr_padded;

		c_ctx->nr_valid = comp;
		c_ctx->nr_padded = 0;
	}

	recovery->rqd = rec_rqd;
	recovery->pblk = pblk;

	return 0;
}

int pblk_recov_check_emeta_md(struct pblk *pblk, struct line_emeta *emeta_buf)
{
	int md_mode = le32_to_cpu(emeta_buf->md_mode);
	if (md_mode != pblk->md_mode) {
		pr_err("pblk: %s: wrong md_mode %d\n", __func__, md_mode);
		return 1;
	}


	int nr_unit = le32_to_cpu(emeta_buf->nr_unit);
	if (nr_unit != pblk->nr_dev) {
		pr_err("pblk: %s: wrong nr_unit %d\n", __func__, nr_unit);
		return 1;
	}
	return 0;
}

int pblk_recov_check_emeta(struct pblk *pblk, struct line_emeta *emeta_buf)
{
	u32 crc;

	crc = pblk_calc_emeta_crc(pblk, emeta_buf);
	if (le32_to_cpu(emeta_buf->crc) != crc) {
        printk("pblk: recov_check_emata crc fail(emata->crc=0x%x crc=0x%x)\n", le32_to_cpu(emeta_buf->crc), crc); //add by kan
		return 1;
    }
	if (le32_to_cpu(emeta_buf->header.identifier) != PBLK_MAGIC) {
        printk("pblk: recov_check_emata header id fail(header_id=0x%x PBLK_MAGIC=0x%x)\n", 
            le32_to_cpu(emeta_buf->header.identifier), PBLK_MAGIC);
		return 1;
    }

	if (!pblk_is_sd(pblk) && pblk_recov_check_emeta_md(pblk, emeta_buf)) {
		pr_info("pblk: %s: emeta_md error\n", __func__);
	}

	return 0;
}

static int pblk_recov_l2p_from_emeta(struct pblk *pblk, struct pblk_line *line)
{
	int dev_id = line->dev_id;
	struct nvm_tgt_dev *dev = pblk->devs[dev_id];
	struct nvm_geo *geo = &dev->geo;
	struct pblk_line_meta *lm = &pblk->lm;
	struct pblk_emeta *emeta = line->emeta;
	struct line_emeta *emeta_buf = emeta->buf;
	int map_id = 0;
	__le64 *lba_list;
	u64 data_start, data_end;
	u64 nr_valid_lbas, nr_lbas = 0;
	u64 i;

	lba_list = emeta_to_lbas(pblk, emeta_buf);
	if (!lba_list)
		return 1;

	line->left_msecs = 0;

	// raid1 or raid5 stores some parity, skip them
	if (pblk_is_raid5(pblk) && pblk_id_is_parity(pblk, dev_id))
		return 0;
	if (pblk_is_raid1(pblk) && dev_id > 0)
		return 0;

	data_start = pblk_line_smeta_start(pblk, line) + lm->smeta_sec;
	data_end = line->emeta_ssec;
	nr_valid_lbas = le64_to_cpu(emeta_buf->nr_valid_lbas);

	for (i = data_start; i < data_end; i++) {
		struct ppa_addr ppa;
		int pos;

		if (pblk_is_raid1(pblk))
			dev_id = map_id;

		ppa = addr_to_gen_ppa(pblk, i, line->id);
		ppa = pblk_set_ppa_dev_id(ppa, dev_id);
		pos = pblk_ppa_to_pos(geo, ppa);

		/* Do not update bad blocks */
		if (test_bit(pos, line->blk_bitmap))
			continue;

		if (le64_to_cpu(lba_list[i]) == ADDR_EMPTY) {
			spin_lock(&line->lock);
			if (test_and_set_bit(i, line->invalid_bitmap))
				WARN_ONCE(1, "pblk: rec. double invalidate:\n");
			else
				le32_add_cpu(line->vsc, -1);
			spin_unlock(&line->lock);

			continue;
		}

		pblk_update_map(pblk, le64_to_cpu(lba_list[i]), ppa);
		pr_info("pblk: %s: lba %llu in line %d of dev %d\n",
				__func__, le64_to_cpu(lba_list[i]), line->id, dev_id);
		nr_lbas++;
		if (pblk_is_raid1(pblk))
			map_id = (map_id + 1) % pblk->nr_dev;
	}

	if (nr_valid_lbas != nr_lbas)
		pr_err("pblk: line %d - inconsistent lba list(%llu/%llu)\n",
				line->id, nr_valid_lbas, nr_lbas);
	return 0;
}

static int pblk_calc_sec_in_line(struct pblk *pblk, struct pblk_line *line)
{
	struct nvm_tgt_dev *dev = pblk->devs[DEFAULT_DEV_ID];
	struct nvm_geo *geo = &dev->geo;
	struct pblk_line_meta *lm = &pblk->lm;
	int nr_bb = bitmap_weight(line->blk_bitmap, lm->blk_per_line);

	return lm->sec_per_line - lm->smeta_sec - lm->emeta_sec[0] -
				nr_bb * geo->clba;
}

struct pblk_recov_alloc {
	struct ppa_addr *ppa_list;
	struct pblk_sec_meta *meta_list;
	struct nvm_rq *rqd;
	void *data;
	dma_addr_t dma_ppa_list;
	dma_addr_t dma_meta_list;
};

static int pblk_recov_read_oob(struct pblk *pblk, struct pblk_line *line,
			       struct pblk_recov_alloc p, u64 r_ptr)
{
	struct nvm_tgt_dev *dev = pblk->devs[DEFAULT_DEV_ID];
	struct nvm_geo *geo = &dev->geo;
	struct ppa_addr *ppa_list;
	struct pblk_sec_meta *meta_list;
	struct nvm_rq *rqd;
	struct bio *bio;
	void *data;
	dma_addr_t dma_ppa_list, dma_meta_list;
	u64 r_ptr_int;
	int left_ppas;
	int rq_ppas, rq_len;
	int i, j;
	int ret = 0;
	int meta_list_idx; //add by kan
    int meta_list_mod; //add by kan

	ppa_list = p.ppa_list;
	meta_list = p.meta_list;
	rqd = p.rqd;
	data = p.data;
	dma_ppa_list = p.dma_ppa_list;
	dma_meta_list = p.dma_meta_list;

	left_ppas = line->cur_sec - r_ptr;
	if (!left_ppas)
		return 0;

	r_ptr_int = r_ptr;

next_read_rq:
	memset(rqd, 0, pblk_g_rq_size);

	rq_ppas = pblk_calc_secs(pblk, left_ppas, 0);
	if (!rq_ppas)
		rq_ppas = pblk->min_write_pgs;
	rq_len = rq_ppas * geo->csecs;

	bio = bio_map_kern(dev->q, data, rq_len, GFP_KERNEL);
	if (IS_ERR(bio))
		return PTR_ERR(bio);

	bio->bi_iter.bi_sector = 0; /* internal bio */
	bio_set_op_attrs(bio, REQ_OP_READ, 0);

	rqd->bio = bio;
	rqd->opcode = NVM_OP_PREAD;
	rqd->meta_list = meta_list;
	rqd->nr_ppas = rq_ppas;
	rqd->ppa_list = ppa_list;
	rqd->dma_ppa_list = dma_ppa_list;
	rqd->dma_meta_list = dma_meta_list;

	if (pblk_io_aligned(pblk, rq_ppas))
		rqd->flags = pblk_set_read_mode(pblk, PBLK_READ_SEQUENTIAL);
	else
		rqd->flags = pblk_set_read_mode(pblk, PBLK_READ_RANDOM);

	for (i = 0; i < rqd->nr_ppas; ) {
		struct ppa_addr ppa;
		int pos;

		ppa = addr_to_gen_ppa(pblk, r_ptr_int, line->id);
		pos = pblk_ppa_to_pos(geo, ppa);

		while (test_bit(pos, line->blk_bitmap)) {
			r_ptr_int += pblk->min_write_pgs;
			ppa = addr_to_gen_ppa(pblk, r_ptr_int, line->id);
			pos = pblk_ppa_to_pos(geo, ppa);
		}

		for (j = 0; j < pblk->min_write_pgs; j++, i++, r_ptr_int++)
			rqd->ppa_list[i] =
				addr_to_gen_ppa(pblk, r_ptr_int, line->id);
	}

	rqd->dev = dev;
	/* If read fails, more padding is needed */
	ret = pblk_submit_io_sync(pblk, rqd, DEFAULT_DEV_ID);
	if (ret) {
		pr_err("pblk: I/O submission failed: %d\n", ret);
		return ret;
	}

	atomic_dec(&pblk->inflight_io);

	/* At this point, the read should not fail. If it does, it is a problem
	 * we cannot recover from here. Need FTL log.
	 */
	if (rqd->error && rqd->error != NVM_RSP_WARN_HIGHECC) {
		pr_err("pblk: L2P recovery failed (%d)\n", rqd->error);
		return -EINTR;
	}

	for (i = 0; i < rqd->nr_ppas; i++) {
 
        meta_list_idx = i; //add by kan
        meta_list_mod = rqd->ppa_list[i].m.sec % geo->ws_min; //add by kan

		u64 lba = le64_to_cpu(meta_list[meta_list_idx].lba[meta_list_mod]); //modify by kan

		if (lba == ADDR_EMPTY || lba > pblk->rl.nr_secs)
			continue;

		pblk_update_map(pblk, lba, rqd->ppa_list[i]);
	}

	left_ppas -= rq_ppas;
	if (left_ppas > 0)
		goto next_read_rq;

	return 0;
}

static void pblk_recov_complete(struct kref *ref)
{
	struct pblk_pad_rq *pad_rq = container_of(ref, struct pblk_pad_rq, ref);

	complete(&pad_rq->wait);
}

static void pblk_end_io_recov(struct nvm_rq *rqd)
{
	struct pblk_pad_rq *pad_rq = rqd->private;
	struct pblk *pblk = pad_rq->pblk;
	
	int dev_id = pblk_get_rq_dev_id(pblk, rqd);
	if(dev_id < 0){
		pr_err("pblk: %s rqd undefined dev\n", __func__);
		dev_id = DEFAULT_DEV_ID;
	}

	pblk_up_page(pblk, rqd->ppa_list, rqd->nr_ppas, dev_id);

	pblk_free_rqd(pblk, rqd, PBLK_WRITE_INT);

	atomic_dec(&pblk->inflight_io);
	kref_put(&pad_rq->ref, pblk_recov_complete);
}

static int pblk_recov_pad_oob(struct pblk *pblk, struct pblk_line *line,
			      int left_ppas)
{
	int dev_id = line->dev_id;
	struct nvm_tgt_dev *dev = pblk->devs[dev_id];
	struct nvm_geo *geo = &dev->geo;
	struct ppa_addr *ppa_list;
	struct pblk_sec_meta *meta_list;
	struct pblk_pad_rq *pad_rq;
	struct nvm_rq *rqd;
	struct bio *bio;
	void *data;
	dma_addr_t dma_ppa_list, dma_meta_list;
	__le64 *lba_list = emeta_to_lbas(pblk, line->emeta->buf);
	u64 w_ptr = line->cur_sec;
	int left_line_ppas, rq_ppas, rq_len;
	int i, j;
	int ret = 0;
    int meta_list_idx; //add by kan
    int meta_list_mod; //add by kan

	spin_lock(&line->lock);
	left_line_ppas = line->left_msecs;
	spin_unlock(&line->lock);

	pad_rq = kmalloc(sizeof(struct pblk_pad_rq), GFP_KERNEL);
	if (!pad_rq)
		return -ENOMEM;

	data = vzalloc(pblk->max_write_pgs * geo->csecs);
	if (!data) {
		ret = -ENOMEM;
		goto free_rq;
	}

	pad_rq->pblk = pblk;
	init_completion(&pad_rq->wait);
	kref_init(&pad_rq->ref);

next_pad_rq:
	rq_ppas = pblk_calc_secs(pblk, left_ppas, 0);
	if (rq_ppas < pblk->min_write_pgs) {
		pr_err("pblk: corrupted pad line %d\n", line->id);
		goto fail_free_pad;
	}

	rq_len = rq_ppas * geo->csecs;

	meta_list = nvm_dev_dma_alloc(dev->parent, GFP_KERNEL, &dma_meta_list);
    //size = pblk_dma_meta_size + pblk_dma_ppa_size; //add by kan
    //meta_list = dma_alloc_coherent(ctrl->dev, size, &dma_meta_list, GFP_KERNEL); //modify by kan
	
    if (!meta_list) {
        printk("meta list dma cannot alloc\n");
		ret = -ENOMEM;
		goto fail_free_pad;
	}

	ppa_list = (void *)(meta_list) + pblk_dma_meta_size;
	dma_ppa_list = dma_meta_list + pblk_dma_meta_size;

	bio = pblk_bio_map_addr(pblk, data, rq_ppas, rq_len,
						PBLK_VMALLOC_META, GFP_KERNEL, dev_id);
	if (IS_ERR(bio)) {
		ret = PTR_ERR(bio);
		goto fail_free_meta;
	}

	bio->bi_iter.bi_sector = 0; /* internal bio */
	bio_set_op_attrs(bio, REQ_OP_WRITE, 0);

	rqd = pblk_alloc_rqd(pblk, PBLK_WRITE_INT);

	rqd->bio = bio;
	rqd->opcode = NVM_OP_PWRITE;
	rqd->flags = pblk_set_progr_mode(pblk, PBLK_WRITE);
	rqd->meta_list = meta_list;
	rqd->nr_ppas = rq_ppas;
	rqd->ppa_list = ppa_list;
	rqd->dma_ppa_list = dma_ppa_list;
	rqd->dma_meta_list = dma_meta_list;
	rqd->end_io = pblk_end_io_recov;
	rqd->private = pad_rq;
	rqd->dev = dev;


	
    for (i = 0; i < rqd->nr_ppas; ) {
		struct ppa_addr ppa;
		int pos;

		w_ptr = pblk_alloc_page(pblk, line, pblk->min_write_pgs);
		ppa = addr_to_gen_ppa(pblk, w_ptr, line->id);
		pos = pblk_ppa_to_pos(geo, ppa);

		while (test_bit(pos, line->blk_bitmap)) {
			w_ptr += pblk->min_write_pgs;
			ppa = addr_to_gen_ppa(pblk, w_ptr, line->id);
			pos = pblk_ppa_to_pos(geo, ppa);
		}

		for (j = 0; j < pblk->min_write_pgs; j++, i++, w_ptr++) {
			struct ppa_addr dev_ppa;
			__le64 addr_empty = cpu_to_le64(ADDR_EMPTY);

			dev_ppa = addr_to_gen_ppa(pblk, w_ptr, line->id);
			dev_ppa = pblk_set_ppa_dev_id(dev_ppa, dev_id);

			pblk_map_invalidate(pblk, dev_ppa);

            meta_list_idx = i / geo->ws_min; //add by kan
            meta_list_mod = dev_ppa.m.sec % geo->ws_min; //add by kan

			lba_list[w_ptr] = meta_list[meta_list_idx].lba[meta_list_mod] = addr_empty; //modify by kan
			rqd->ppa_list[i] = dev_ppa;
		}
	}

	kref_get(&pad_rq->ref);
	pblk_down_page(pblk, rqd->ppa_list, rqd->nr_ppas, dev_id);

	ret = pblk_submit_io(pblk, rqd, dev_id);
	if (ret) {
		pr_err("pblk: I/O submission failed: %d\n", ret);
		pblk_up_page(pblk, rqd->ppa_list, rqd->nr_ppas, dev_id);
		goto fail_free_bio;
	}

	left_line_ppas -= rq_ppas;
	left_ppas -= rq_ppas;
	if (left_ppas && left_line_ppas)
		goto next_pad_rq;

	kref_put(&pad_rq->ref, pblk_recov_complete);

	if (!wait_for_completion_io_timeout(&pad_rq->wait,
				msecs_to_jiffies(PBLK_COMMAND_TIMEOUT_MS))) {
		pr_err("pblk: pad write timed out\n");
		ret = -ETIME;
	}

	if (!pblk_line_is_full(line))
		pr_err("pblk: corrupted padded line: %d\n", line->id);

	vfree(data);
free_rq:
	kfree(pad_rq);
	return ret;

fail_free_bio:
	bio_put(bio);
fail_free_meta:
	nvm_dev_dma_free(dev->parent, meta_list, dma_meta_list);
	//dma_free_coherent(ctrl->dev, size, meta_list, dma_meta_list); //add by kan
fail_free_pad:
	kfree(pad_rq);
	vfree(data);
	return ret;
}

/* When this function is called, it means that not all upper pages have been
 * written in a page that contains valid data. In order to recover this data, we
 * first find the write pointer on the device, then we pad all necessary
 * sectors, and finally attempt to read the valid data
 */
static int pblk_recov_scan_all_oob(struct pblk *pblk, struct pblk_line *line,
				   struct pblk_recov_alloc p)
{
	struct nvm_tgt_dev *dev = pblk->devs[DEFAULT_DEV_ID];
	struct nvm_geo *geo = &dev->geo;
	struct ppa_addr *ppa_list;
	struct pblk_sec_meta *meta_list;
	struct nvm_rq *rqd;
	struct bio *bio;
	void *data;
	dma_addr_t dma_ppa_list, dma_meta_list;
	u64 w_ptr = 0, r_ptr;
	int rq_ppas, rq_len;
	int i, j;
	int ret = 0;
	int rec_round;
	int left_ppas = pblk_calc_sec_in_line(pblk, line) - line->cur_sec;
    int meta_list_idx; //add by kan
    int meta_list_mod; //add by kan

	ppa_list = p.ppa_list;
	meta_list = p.meta_list;
	rqd = p.rqd;
	data = p.data;
	dma_ppa_list = p.dma_ppa_list;
	dma_meta_list = p.dma_meta_list;

	/* we could recover up until the line write pointer */
	r_ptr = line->cur_sec;
	rec_round = 0;

	pr_info("pblk: %s: line id %d\n", __func__, line->id);

next_rq:
	memset(rqd, 0, pblk_g_rq_size);

	rq_ppas = pblk_calc_secs(pblk, left_ppas, 0);
	if (!rq_ppas)
		rq_ppas = pblk->min_write_pgs;
	rq_len = rq_ppas * geo->csecs;

	bio = bio_map_kern(dev->q, data, rq_len, GFP_KERNEL);
	if (IS_ERR(bio))
		return PTR_ERR(bio);

	bio->bi_iter.bi_sector = 0; /* internal bio */
	bio_set_op_attrs(bio, REQ_OP_READ, 0);

	rqd->bio = bio;
	rqd->opcode = NVM_OP_PREAD;
	rqd->meta_list = meta_list;
	rqd->nr_ppas = rq_ppas;
	rqd->ppa_list = ppa_list;
	rqd->dma_ppa_list = dma_ppa_list;
	rqd->dma_meta_list = dma_meta_list;

	if (pblk_io_aligned(pblk, rq_ppas))
		rqd->flags = pblk_set_read_mode(pblk, PBLK_READ_SEQUENTIAL);
	else
		rqd->flags = pblk_set_read_mode(pblk, PBLK_READ_RANDOM);

	for (i = 0; i < rqd->nr_ppas; ) {
		struct ppa_addr ppa;
		int pos;

		w_ptr = pblk_alloc_page(pblk, line, pblk->min_write_pgs);
		ppa = addr_to_gen_ppa(pblk, w_ptr, line->id);
		pos = pblk_ppa_to_pos(geo, ppa);

		while (test_bit(pos, line->blk_bitmap)) {
			w_ptr += pblk->min_write_pgs;
			ppa = addr_to_gen_ppa(pblk, w_ptr, line->id);
			pos = pblk_ppa_to_pos(geo, ppa);
		}

		for (j = 0; j < pblk->min_write_pgs; j++, i++, w_ptr++)
			rqd->ppa_list[i] =
				addr_to_gen_ppa(pblk, w_ptr, line->id);
	}

	ret = pblk_submit_io_sync(pblk, rqd, DEFAULT_DEV_ID);
	if (ret) {
		pr_err("pblk: I/O submission failed: %d\n", ret);
		return ret;
	}

	atomic_dec(&pblk->inflight_io);

	/* This should not happen since the read failed during normal recovery,
	 * but the media works funny sometimes...
	 */

	if (!rec_round++ && !rqd->error) {
		rec_round = 0;
		for (i = 0; i < rqd->nr_ppas; i++, r_ptr++) {

            meta_list_idx = i; //add by kan
            meta_list_mod = rqd->ppa_list[i].m.sec % geo->ws_min; //add by kan
			u64 lba = le64_to_cpu(meta_list[meta_list_idx].lba[meta_list_mod]); //modify by kan

			if (lba == ADDR_EMPTY || lba > pblk->rl.nr_secs)
				continue;

			pblk_update_map(pblk, lba, rqd->ppa_list[i]);
		}
	}

	/* Reached the end of the written line */
	if (rqd->error == NVM_RSP_ERR_EMPTYPAGE) {
		int pad_secs, nr_error_bits, bit;
		int ret;

		bit = find_first_bit((void *)&rqd->ppa_status, rqd->nr_ppas);
		nr_error_bits = rqd->nr_ppas - bit;

		/* Roll back failed sectors */
		line->cur_sec -= nr_error_bits;
		line->left_msecs += nr_error_bits;
		bitmap_clear(line->map_bitmap, line->cur_sec, nr_error_bits);

		pad_secs = pblk_pad_distance(pblk, line->dev_id);
		if (pad_secs > line->left_msecs)
			pad_secs = line->left_msecs;

		ret = pblk_recov_pad_oob(pblk, line, pad_secs);
		if (ret)
			pr_err("pblk: OOB padding failed (err:%d)\n", ret);

		ret = pblk_recov_read_oob(pblk, line, p, r_ptr);
		if (ret)
			pr_err("pblk: OOB read failed (err:%d)\n", ret);

		left_ppas = 0;
	}

	left_ppas -= rq_ppas;
	if (left_ppas > 0)
		goto next_rq;

	return ret;
}

static int pblk_recov_scan_oob(struct pblk *pblk, struct pblk_line *line,
			       struct pblk_recov_alloc p, int *done)
{
	struct nvm_tgt_dev *dev = pblk->devs[DEFAULT_DEV_ID];
	struct nvm_geo *geo = &dev->geo;
	struct ppa_addr *ppa_list;
	struct pblk_sec_meta *meta_list;
	struct nvm_rq *rqd;
	struct bio *bio;
	void *data;
	dma_addr_t dma_ppa_list, dma_meta_list;
	u64 paddr;
	int rq_ppas, rq_len;
	int i, j;
	int ret = 0;
	int left_ppas = pblk_calc_sec_in_line(pblk, line);
    int meta_list_idx; //add by kan
    int meta_list_mod; //add by kan

	ppa_list = p.ppa_list;
	meta_list = p.meta_list;
	rqd = p.rqd;
	data = p.data;
	dma_ppa_list = p.dma_ppa_list;
	dma_meta_list = p.dma_meta_list;

	*done = 1;
	pr_info("pblk: %s line %d\n", __func__, line->id);

next_rq:
	memset(rqd, 0, pblk_g_rq_size);

	rq_ppas = pblk_calc_secs(pblk, left_ppas, 0);
	if (!rq_ppas)
		rq_ppas = pblk->min_write_pgs;
	rq_len = rq_ppas * geo->csecs;

	bio = bio_map_kern(dev->q, data, rq_len, GFP_KERNEL);
	if (IS_ERR(bio))
		return PTR_ERR(bio);

	bio->bi_iter.bi_sector = 0; /* internal bio */
	bio_set_op_attrs(bio, REQ_OP_READ, 0);

	rqd->bio = bio;
	rqd->opcode = NVM_OP_PREAD;
	rqd->meta_list = meta_list;
	rqd->nr_ppas = rq_ppas;
	rqd->ppa_list = ppa_list;
	rqd->dma_ppa_list = dma_ppa_list;
	rqd->dma_meta_list = dma_meta_list;

	if (pblk_io_aligned(pblk, rq_ppas))
		rqd->flags = pblk_set_read_mode(pblk, PBLK_READ_SEQUENTIAL);
	else
		rqd->flags = pblk_set_read_mode(pblk, PBLK_READ_RANDOM);

	for (i = 0; i < rqd->nr_ppas; ) {
		struct ppa_addr ppa;
		int pos;

		paddr = pblk_alloc_page(pblk, line, pblk->min_write_pgs);
		ppa = addr_to_gen_ppa(pblk, paddr, line->id);
		pos = pblk_ppa_to_pos(geo, ppa);

		while (test_bit(pos, line->blk_bitmap)) {
			paddr += pblk->min_write_pgs;
			ppa = addr_to_gen_ppa(pblk, paddr, line->id);
			pos = pblk_ppa_to_pos(geo, ppa);
		}

		for (j = 0; j < pblk->min_write_pgs; j++, i++, paddr++)
			rqd->ppa_list[i] =
				addr_to_gen_ppa(pblk, paddr, line->id);
	}

	ret = pblk_submit_io_sync(pblk, rqd, DEFAULT_DEV_ID);
	if (ret) {
		pr_err("pblk: I/O submission failed: %d\n", ret);
		bio_put(bio);
		return ret;
	}

	atomic_dec(&pblk->inflight_io);

	/* Reached the end of the written line */
	if (rqd->error) {
		int nr_error_bits, bit;

		bit = find_first_bit((void *)&rqd->ppa_status, rqd->nr_ppas);
		nr_error_bits = rqd->nr_ppas - bit;

		/* Roll back failed sectors */
		line->cur_sec -= nr_error_bits;
		line->left_msecs += nr_error_bits;
		bitmap_clear(line->map_bitmap, line->cur_sec, nr_error_bits);

		left_ppas = 0;
		rqd->nr_ppas = bit;

		if (rqd->error != NVM_RSP_ERR_EMPTYPAGE)
			*done = 0;
	}
    

	for (i = 0; i < rqd->nr_ppas; i++) {
        meta_list_idx = i; //add by kan
        meta_list_mod = rqd->ppa_list[i].m.sec % geo->ws_min; //add by kan

		u64 lba = le64_to_cpu(meta_list[meta_list_idx].lba[meta_list_mod]); //modify by kan

		if (lba == ADDR_EMPTY || lba > pblk->rl.nr_secs)
			continue;

		pblk_update_map(pblk, lba, rqd->ppa_list[i]);
	}

	left_ppas -= rq_ppas;
	if (left_ppas > 0)
		goto next_rq;

	return ret;
}

/* Scan line for lbas on out of bound area */
static int pblk_recov_l2p_from_oob(struct pblk *pblk, struct pblk_line *line)
{
	struct nvm_tgt_dev *dev = pblk->devs[DEFAULT_DEV_ID];
	struct nvm_geo *geo = &dev->geo;
	struct nvm_rq *rqd;
	struct ppa_addr *ppa_list;
	struct pblk_sec_meta *meta_list;
	struct pblk_recov_alloc p;
	void *data;
	dma_addr_t dma_ppa_list, dma_meta_list;
	int done, ret = 0;

	pr_info("pblk: %s line %d\n", __func__, line->id);

	meta_list = nvm_dev_dma_alloc(dev->parent, GFP_KERNEL, &dma_meta_list);
    //int size = pblk_dma_meta_size + pblk_dma_ppa_size; //add by kan
    //meta_list = dma_alloc_coherent(ctrl->dev, size, &dma_meta_list, GFP_KERNEL); //modify by kan
	
    if (!meta_list) {
        printk("meta list dma cannot alloc\n");//add by kan
		return -ENOMEM;
    }

	ppa_list = (void *)(meta_list) + pblk_dma_meta_size;
	dma_ppa_list = dma_meta_list + pblk_dma_meta_size;

	data = kcalloc(pblk->max_write_pgs, geo->csecs, GFP_KERNEL);
	if (!data) {
		ret = -ENOMEM;
		goto free_meta_list;
	}

	rqd = pblk_alloc_rqd(pblk, PBLK_READ);

	p.ppa_list = ppa_list;
	p.meta_list = meta_list;
	p.rqd = rqd;
	p.data = data;
	p.dma_ppa_list = dma_ppa_list;
	p.dma_meta_list = dma_meta_list;

	ret = pblk_recov_scan_oob(pblk, line, p, &done);
	if (ret) {
		pr_err("pblk: could not recover L2P from OOB\n");
		goto out;
	}

	if (!done) {
		ret = pblk_recov_scan_all_oob(pblk, line, p);
		if (ret) {
			pr_err("pblk: could not recover L2P from OOB\n");
			goto out;
		}
	}

	if (pblk_line_is_full(line))
		pblk_line_recov_close(pblk, line);

out:
	kfree(data);
free_meta_list:
	nvm_dev_dma_free(dev->parent, meta_list, dma_meta_list);
	//dma_free_coherent(ctrl->dev, size, meta_list, dma_meta_list); //add by kan

	return ret;
}

/* Insert lines ordered by sequence number (seq_num) on list */
static void pblk_recov_line_add_ordered(struct list_head *head,
					struct pblk_line *line)
{
	struct pblk_line *t = NULL;

	list_for_each_entry(t, head, list)
		if (t->seq_nr > line->seq_nr)
			break;

	__list_add(&line->list, t->list.prev, &t->list);
}

static u64 pblk_line_emeta_start(struct pblk *pblk, struct pblk_line *line)
{
	int dev_id = line->dev_id;
	struct nvm_tgt_dev *dev = pblk->devs[dev_id];
	struct nvm_geo *geo = &dev->geo;
	struct pblk_line_meta *lm = &pblk->lm;
	unsigned int emeta_secs;
	u64 emeta_start;
	struct ppa_addr ppa;
	int pos;

	emeta_secs = lm->emeta_sec[0];
	emeta_start = lm->sec_per_line;

	while (emeta_secs) {
		emeta_start--;
		ppa = addr_to_gen_ppa(pblk, emeta_start, line->id);
		pos = pblk_ppa_to_pos(geo, ppa);
		if (!test_bit(pos, line->blk_bitmap))
			emeta_secs--;
	}

	return emeta_start;
}

static int pblk_recov_check_line_version(struct pblk *pblk,
					 struct line_emeta *emeta)
{
	struct line_header *header = &emeta->header;

	if (header->version_major != EMETA_VERSION_MAJOR) {
		pr_err("pblk: line major version mismatch: %d, expected: %d\n",
		       header->version_major, EMETA_VERSION_MAJOR);
		return 1;
	}

#ifdef NVM_DEBUG
	if (header->version_minor > EMETA_VERSION_MINOR)
		pr_info("pblk: newer line minor version found: %d\n", line_v);
#endif

	return 0;
}

static void pblk_recov_wa_counters(struct pblk *pblk,
				   struct line_emeta *emeta)
{
	struct pblk_line_meta *lm = &pblk->lm;
	struct line_header *header = &emeta->header;
	struct wa_counters *wa = emeta_to_wa(lm, emeta);

	/* WA counters were introduced in emeta version 0.2 */
	if (header->version_major > 0 || header->version_minor >= 2) {
		u64 user = le64_to_cpu(wa->user);
		u64 pad = le64_to_cpu(wa->pad);
		u64 gc = le64_to_cpu(wa->gc);

		atomic64_set(&pblk->user_wa, user);
		atomic64_set(&pblk->pad_wa, pad);
		atomic64_set(&pblk->gc_wa, gc);

		pblk->user_rst_wa = user;
		pblk->pad_rst_wa = pad;
		pblk->gc_rst_wa = gc;
	}
}

static int pblk_line_was_written(struct pblk_line *line,
			    struct pblk_line_meta *lm)
{

	int i;
	int state_mask = NVM_CHK_ST_OFFLINE | NVM_CHK_ST_FREE;

	for (i = 0; i < lm->blk_per_line; i++) {
		if (!(line->chks[i].state & state_mask))
			return 1;
	}

	return 0;
}

int pblk_recov_smeta_dev(struct pblk *pblk, int dev_id,
		struct list_head *recov_list, int *meta_line_ptr,
		int *err_no)
{
	struct pblk_line_meta *lm = &pblk->lm;
	struct pblk_line_mgmt *l_mg = &pblk->l_mg[dev_id];
	struct pblk_line *line;
	struct pblk_smeta *smeta;
	struct pblk_emeta *emeta;
	struct line_smeta *smeta_buf;
	int found_lines = 0;
	int meta_line;
	int i, valid_uuid = 0;
	*err_no = 0;
	//LIST_HEAD(recov_list);

	pr_info("--------------------------\n");
	pr_info("pblk: %s: dev %d\n", __func__, dev_id);
	//pr_err("pblk rec: func(%s) bug here, never be called in this version\n", __func__);
	/* TODO: Implement FTL snapshot */

	/* Scan recovery - takes place when FTL snapshot fails */
	spin_lock(&l_mg->free_lock);
	meta_line = find_first_zero_bit(&l_mg->meta_bitmap, PBLK_DATA_LINES);
	set_bit(meta_line, &l_mg->meta_bitmap);
	smeta = l_mg->sline_meta[meta_line];
	emeta = l_mg->eline_meta[meta_line];
	smeta_buf = (struct line_smeta *)smeta;
	spin_unlock(&l_mg->free_lock);
	*meta_line_ptr = meta_line;

	/* Order data lines using their sequence number */
	for (i = 0; i < l_mg->nr_lines; i++) {
		u32 crc;

		line = &pblk->lines[dev_id][i];

		memset(smeta, 0, lm->smeta_len);
		line->smeta = smeta;
		line->lun_bitmap = ((void *)(smeta_buf)) +
						sizeof(struct line_smeta);

		if (!pblk_line_was_written(line, lm)) {
			//pr_info("pblk: %s: line %d not written\n", __func__, i);
			continue;
		}

		/* Lines that cannot be read are assumed as not written here */
		if (pblk_line_read_smeta(pblk, line)) {
			//pr_info("pblk: %s: line %d read smeta fail\n", __func__, i);
			continue;
		}

		crc = pblk_calc_smeta_crc(pblk, smeta_buf);
		if (le32_to_cpu(smeta_buf->crc) != crc) {
			//pr_info("pblk: %s: line %d crc fail\n", __func__, i);
			continue;
		}

		if (le32_to_cpu(smeta_buf->header.identifier) != PBLK_MAGIC) {
			//pr_info("pblk: %s: line %d smeta identifier fail\n", __func__, i);
			continue;
		}

		if (smeta_buf->header.version_major != SMETA_VERSION_MAJOR) {
			pr_err("pblk: found incompatible line version %u\n",
					smeta_buf->header.version_major);
			*err_no = -EINVAL;
			return found_lines;
		}

		/* The first valid instance uuid is used for initialization */
		if (!valid_uuid) {
			memcpy(pblk->instance_uuid, smeta_buf->header.uuid, 16);
			valid_uuid = 1;
		}

		if (memcmp(pblk->instance_uuid, smeta_buf->header.uuid, 16)) {
			pr_debug("pblk: ignore line %u due to uuid mismatch\n",
					i);
			continue;
		}

		/*
		if (i < 9 || i >= 20) {
			pr_info("pblk: %s: unexpected rec line %d\n", __func__, i);
			continue;
		}
		*/
		pr_info("pblk: %s: found line %d to rec\n", __func__, i);

		/* Update line metadata */
		spin_lock(&line->lock);
		line->id = le32_to_cpu(smeta_buf->header.id);
		line->type = le16_to_cpu(smeta_buf->header.type);
		line->seq_nr = le64_to_cpu(smeta_buf->seq_nr);
		spin_unlock(&line->lock);

		/* Update general metadata */
		spin_lock(&l_mg->free_lock);
		if (line->seq_nr >= l_mg->d_seq_nr)
			l_mg->d_seq_nr = line->seq_nr + 1;
		l_mg->nr_free_lines--;
		spin_unlock(&l_mg->free_lock);

		if (pblk_line_recov_alloc(pblk, line)) {
			*err_no = -EINVAL;
			return found_lines;
		}

		pblk_recov_line_add_ordered(recov_list, line);
		found_lines++;
		pr_debug("pblk: recovering data line %d, seq:%llu\n",
						line->id, smeta_buf->seq_nr);
	}

	pr_info("pblk: %s: found %d line of dev %d to rec\n",
			__func__, found_lines, dev_id);

	if (!found_lines) {
		pblk_setup_uuid(pblk);

		spin_lock(&l_mg->free_lock);
		WARN_ON_ONCE(!test_and_clear_bit(meta_line,
							&l_mg->meta_bitmap));
		spin_unlock(&l_mg->free_lock);

	}
	pr_info("--------------------------\n");
	return found_lines;
}

int pblk_recov_l2p_sd(struct pblk *pblk)
{
	int dev_id = DEFAULT_DEV_ID;
	struct pblk_line_meta *lm = &pblk->lm;
	struct pblk_line_mgmt *l_mg = &pblk->l_mg[dev_id];
	int meta_line, err_no;
	LIST_HEAD(recov_list);
	int found_lines = pblk_recov_smeta_dev(pblk, dev_id, &recov_list, &meta_line, &err_no);
	int recovered_lines = 0, open_lines = 0;
	int is_next = 0;

	struct pblk_line *line, *tline, *data_line = NULL;
	struct pblk_emeta *emeta = l_mg->eline_meta[meta_line];
	if (!found_lines || err_no < 0) 
		goto out;

	/* Verify closed blocks and recover this portion of L2P table*/
	list_for_each_entry_safe(line, tline, &recov_list, list) {
		recovered_lines++;

		line->emeta_ssec = pblk_line_emeta_start(pblk, line);
		line->emeta = emeta;
		memset(line->emeta->buf, 0, lm->emeta_len[0]);

        printk("%s read emata line_id = %d\n", __func__, line->id);
		if (pblk_line_read_emeta(pblk, line, line->emeta->buf)) {
			pr_err("pblk: %s line %d partial written. Abort.We leave this case as future work\n",
					__func__, line->id);
			return -1;

			pblk_recov_l2p_from_oob(pblk, line);
			goto next;
		}

		if (pblk_recov_check_emeta(pblk, line->emeta->buf)) {
			return -1;

			pblk_recov_l2p_from_oob(pblk, line);
			goto next;
		}

		if (pblk_recov_check_line_version(pblk, line->emeta->buf))
			return -1;

		pblk_recov_wa_counters(pblk, line->emeta->buf);

		if (pblk_recov_l2p_from_emeta(pblk, line)) {
			pr_err("pblk: %s: recov l2p from emeta of line %d fail. Abort\n",
					__func__, line->id);
			return -1;

			pblk_recov_l2p_from_oob(pblk, line);
		}

next:
		if (pblk_line_is_full(line)) {
			struct list_head *move_list;

			spin_lock(&line->lock);
			line->state = PBLK_LINESTATE_CLOSED;
			move_list = pblk_line_gc_list(pblk, line);
			spin_unlock(&line->lock);

			spin_lock(&l_mg->gc_lock);
			list_move_tail(&line->list, move_list);
			spin_unlock(&l_mg->gc_lock);

			kfree(line->map_bitmap);
			line->map_bitmap = NULL;
			line->smeta = NULL;
			line->emeta = NULL;
		} else {
			if (open_lines > 1)
				pr_err("pblk: failed to recover L2P\n");

			open_lines++;
			line->meta_line = meta_line;
			data_line = line;
		}
	}

	spin_lock(&l_mg->free_lock);
	if (!open_lines) {
		WARN_ON_ONCE(!test_and_clear_bit(meta_line,
							&l_mg->meta_bitmap));
		pblk_line_replace_data(pblk, dev_id);
	} else {
		/* Allocate next line for preparation */
		l_mg->data_next = pblk_line_get(pblk, dev_id);
		if (l_mg->data_next) {
			l_mg->data_next->seq_nr = l_mg->d_seq_nr++;
			l_mg->data_next->type = PBLK_LINETYPE_DATA;
			is_next = 1;
		}
	}
	spin_unlock(&l_mg->free_lock);

	if (is_next)
		pblk_line_erase(pblk, l_mg->data_next);

out:
	if (found_lines != recovered_lines)
		pr_err("pblk: failed to recover all found lines %d/%d\n",
						found_lines, recovered_lines);

	return recovered_lines;
}

int pblk_check_found_lines(int found_lines[], int nr_dev) {
	int x = found_lines[0], i;
	for (i = 1; i < nr_dev; i++) {
		if (found_lines[i] != x) {
			pr_err("pblk: %s: found_lines[%d] %d not equal to found_lines[0] %d\n",
					__func__, i, found_lines[i], x);
			return -1;
		}
	}
	return 0;
}

int pblk_recov_emeta_dev(struct pblk *pblk, struct pblk_line *line, struct pblk_emeta *emeta) 
{
	int dev_id = line->dev_id;
	struct pblk_line_meta *lm = &pblk->lm;
	line->emeta_ssec = pblk_line_emeta_start(pblk, line);
	line->emeta = emeta;
	memset(line->emeta->buf, 0, lm->emeta_len[0]);
	pr_info("pblk: %s: read emata line_id = %d of dev %d\n",
			__func__, line->id, dev_id);

	if (pblk_line_read_emeta(pblk, line, line->emeta->buf)) {
		pr_err("pblk: %s line %d partial written. Abort.We leave this case as future work\n",
				__func__, line->id);
		return (-EINVAL);
	}

	if (pblk_recov_check_emeta(pblk, line->emeta->buf)) {
		return (-EINVAL);
	}

	if (pblk_recov_check_line_version(pblk, line->emeta->buf))
		return (-EINVAL);

	pblk_recov_wa_counters(pblk, line->emeta->buf);

	if (pblk_recov_l2p_from_emeta(pblk, line)) {
		pr_err("pblk: %s: recov l2p from emeta of line %d fail. Abort\n",
				__func__, line->id);
		return (-EINVAL);
	}

	return 0;

	
}

// not necessary to add lines_group info in RAID0
int pblk_recov_l2p_raid0(struct pblk *pblk)
{
	struct pblk_line *line[NVM_MD_MAX_DEV_CNT];
	struct pblk_line *tline[NVM_MD_MAX_DEV_CNT];
	struct pblk_line_mgmt *l_mg[NVM_MD_MAX_DEV_CNT];

	struct pblk_smeta *smeta[NVM_MD_MAX_DEV_CNT];
	struct pblk_emeta *emeta[NVM_MD_MAX_DEV_CNT];
	struct line_smeta *smeta_buf[NVM_MD_MAX_DEV_CNT];
	int found_lines[NVM_MD_MAX_DEV_CNT];
	int meta_line[NVM_MD_MAX_DEV_CNT];
	int err_no[NVM_MD_MAX_DEV_CNT];
	struct list_head recov_list[NVM_MD_MAX_DEV_CNT];
	struct line_emeta *emeta_buf;
	int recovered_lines = 0;
	int dev_id, i;

	for (i = 0; i < pblk->nr_dev; i++) {
		dev_id = i;
		l_mg[i] = &pblk->l_mg[i];

		INIT_LIST_HEAD(&recov_list[i]);
		found_lines[i] = pblk_recov_smeta_dev(pblk, dev_id, &recov_list[i], &meta_line[i], &err_no[i]);
		if (!found_lines[i] || err_no[i] < 0) {
			pr_err("pblk: %s: recov_smeta of dev %d fail\n", 
					__func__, dev_id);
			return -1;
		}

		smeta[i] = l_mg[i]->sline_meta[meta_line[i]];
		emeta[i] = l_mg[i]->eline_meta[meta_line[i]];
		smeta_buf[i] = (struct line_smeta *)smeta;
	}

	if (pblk_check_found_lines(found_lines, pblk->nr_dev)) {
		pr_err("pblk: %s: found_lines not equal, abort\n", __func__);
		return -1;
	}

	//pr_info("pblk: %s: stop before read emeta\n", __func__);
	//return ERR_PTR(-EINVAL);

	/* Verify closed blocks and recover this portion of L2P table*/
	
	for (i = 1; i < pblk->nr_dev; i++)
		line[i] = list_first_entry(&recov_list[i], typeof(*line[i]), list);

	list_for_each_entry_safe(line[0], tline[0], &recov_list[0], list) {
		recovered_lines++;
		for (i = 1; i < pblk->nr_dev; i++) {
			tline[i] = list_next_entry(line[i], list);
		}
		/*
		for (i = 0; i < pblk->nr_dev; i++) 
			pr_info("pblk: %s: recov emeta line %d dev %d\n",
					__func__, line[i]->id, i);
		*/
		for (i = 0; i < pblk->nr_dev; i++) {
			pr_info("pblk: %s: recov emeta line %d dev %d\n",
					__func__, line[i]->id, i);
			if (pblk_recov_emeta_dev(pblk, line[i], emeta[i])) {
				pr_err("pblk: %s: err to recov emeta line %d of dev %d\n", 
						__func__, line[0]->id, line[0]->dev_id);
				return -1;
			}
		}
		pr_info("pblk: %s: rec md_line seq_nr %d finish\n",
				__func__, line[0]->seq_nr);

		emeta_buf = line[0]->emeta->buf;
		for (i = 1; i < pblk->nr_dev; i++) {
			if (memcmp(line[i]->emeta->buf->line_units, emeta_buf->line_units, 
				sizeof(struct pblk_md_line_unit_le)*pblk->nr_dev)) {
				pr_err("pblk: %s: corrupt line id %d, seq_nr %d emeta line_units\n", 
						__func__, line[0]->id, line[0]->seq_nr);
				return -1;
			}
		}
		pr_info("pblk: %s: md_line seq_nr %d md_info PASS\n",
				__func__, line[0]->seq_nr);

		for (i = 0; i < pblk->nr_dev; i++) {
			if (pblk_line_is_full(line[i])) {
				pr_info("pblk: %s: rec line %d of dev %d is full\n",
						__func__, line[i]->id, line[i]->dev_id);
				struct list_head *move_list;

				spin_lock(&line[i]->lock);
				line[i]->state = PBLK_LINESTATE_CLOSED;
				move_list = pblk_line_gc_list(pblk, line[i]);
				spin_unlock(&line[i]->lock);

				spin_lock(&l_mg[i]->gc_lock);
				list_move_tail(&line[i]->list, move_list);
				spin_unlock(&l_mg[i]->gc_lock);

				kfree(line[i]->map_bitmap);
				line[i]->map_bitmap = NULL;
				line[i]->smeta = NULL;
				line[i]->emeta = NULL;
			} else {
				pr_err("pblk: %s: recov line %d of dev %d not full\n",
						__func__, line[i]->id, line[i]->dev_id);
				return -1;
			}
		}
		for (i = 1; i < pblk->nr_dev; i++)
			line[i] = tline[i];
	}

	for (i = 0; i < pblk->nr_dev; i++) {
		spin_lock(&l_mg[i]->free_lock);
		WARN_ON_ONCE(!test_and_clear_bit(meta_line[i], &l_mg[i]->meta_bitmap)); 
		pblk_line_replace_data(pblk, i);
		spin_unlock(&l_mg[i]->free_lock);
	}

	pr_info("pblk: %s: recov raid0 succ\n", __func__);
	return recovered_lines;
}

// todo: line_groups recovery
int pblk_recov_l2p_raid1(struct pblk *pblk)
{
	struct pblk_line *line[NVM_MD_MAX_DEV_CNT];
	struct pblk_line *tline[NVM_MD_MAX_DEV_CNT];
	struct pblk_line_mgmt *l_mg[NVM_MD_MAX_DEV_CNT];

	struct pblk_smeta *smeta[NVM_MD_MAX_DEV_CNT];
	struct pblk_emeta *emeta[NVM_MD_MAX_DEV_CNT];
	struct line_smeta *smeta_buf[NVM_MD_MAX_DEV_CNT];
	int found_lines[NVM_MD_MAX_DEV_CNT];
	int meta_line[NVM_MD_MAX_DEV_CNT];
	int err_no[NVM_MD_MAX_DEV_CNT];
	struct list_head recov_list[NVM_MD_MAX_DEV_CNT];
	struct line_emeta *emeta_buf;
	int recovered_lines = 0;
	int gid = 0; // cur_group of lines
	int dev_id, i;
	struct pblk_md_line_group_set *set = &pblk->md_line_group_set;
	struct pblk_md_line_group *group;

	for (i = 0; i < pblk->nr_dev; i++) {
		dev_id = i;
		l_mg[i] = &pblk->l_mg[i];

		INIT_LIST_HEAD(&recov_list[i]);
		found_lines[i] = pblk_recov_smeta_dev(pblk, dev_id, &recov_list[i], &meta_line[i], &err_no[i]);
		if (!found_lines[i] || err_no[i] < 0) {
			pr_err("pblk: %s: recov_smeta of dev %d fail\n", 
					__func__, dev_id);
			return -1;
		}

		smeta[i] = l_mg[i]->sline_meta[meta_line[i]];
		emeta[i] = l_mg[i]->eline_meta[meta_line[i]];
		smeta_buf[i] = (struct line_smeta *)smeta;
	}

	if (pblk_check_found_lines(found_lines, pblk->nr_dev)) {
		pr_err("pblk: %s: found_lines not equal, abort\n", __func__);
		return -1;
	}

	//pr_info("pblk: %s: stop before read emeta\n", __func__);
	//return ERR_PTR(-EINVAL);

	/* Verify closed blocks and recover this portion of L2P table*/
	
	for (i = 1; i < pblk->nr_dev; i++)
		line[i] = list_first_entry(&recov_list[i], typeof(*line[i]), list);

	list_for_each_entry_safe(line[0], tline[0], &recov_list[0], list) {
		// update line_group info
		group = &set->line_groups[gid];
		for (i = 0; i < pblk->nr_dev; i++) {
			group->line_units[i].dev_id = i;
			group->line_units[i].line_id = line[i]->id;
		}
		gid++;
		recovered_lines++;

		for (i = 1; i < pblk->nr_dev; i++) {
			tline[i] = list_next_entry(line[i], list);
		}
		/*
		for (i = 0; i < pblk->nr_dev; i++) 
			pr_info("pblk: %s: recov emeta line %d dev %d\n",
					__func__, line[i]->id, i);
		*/
		for (i = 0; i < pblk->nr_dev; i++) {
			pr_info("pblk: %s: recov emeta line %d dev %d\n",
					__func__, line[i]->id, i);
			if (pblk_recov_emeta_dev(pblk, line[i], emeta[i])) {
				pr_err("pblk: %s: err to recov emeta line %d of dev %d\n", 
						__func__, line[0]->id, line[0]->dev_id);
				return -1;
			}
		}
		pr_info("pblk: %s: rec md_line seq_nr %d finish\n",
				__func__, line[0]->seq_nr);

		emeta_buf = line[0]->emeta->buf;
		for (i = 1; i < pblk->nr_dev; i++) {
			if (memcmp(line[i]->emeta->buf->line_units, emeta_buf->line_units, 
				sizeof(struct pblk_md_line_unit_le)*pblk->nr_dev)) {
				pr_err("pblk: %s: corrupt line id %d, seq_nr %d emeta line_units\n", 
						__func__, line[0]->id, line[0]->seq_nr);
				return -1;
			}
		}
		pr_info("pblk: %s: md_line seq_nr %d md_info PASS\n",
				__func__, line[0]->seq_nr);

		for (i = 0; i < pblk->nr_dev; i++) {
			if (pblk_line_is_full(line[i])) {
				pr_info("pblk: %s: rec line %d of dev %d is full\n",
						__func__, line[i]->id, line[i]->dev_id);
				struct list_head *move_list;

				spin_lock(&line[i]->lock);
				line[i]->state = PBLK_LINESTATE_CLOSED;
				move_list = pblk_line_gc_list(pblk, line[i]);
				spin_unlock(&line[i]->lock);

				spin_lock(&l_mg[i]->gc_lock);
				list_move_tail(&line[i]->list, move_list);
				spin_unlock(&l_mg[i]->gc_lock);

				kfree(line[i]->map_bitmap);
				line[i]->map_bitmap = NULL;
				line[i]->smeta = NULL;
				line[i]->emeta = NULL;
			} else {
				pr_err("pblk: %s: recov line %d of dev %d not full\n",
						__func__, line[i]->id, line[i]->dev_id);
				return -1;
			}
		}
		for (i = 1; i < pblk->nr_dev; i++)
			line[i] = tline[i];
	}

	for (i = 0; i < pblk->nr_dev; i++) {
		spin_lock(&l_mg[i]->free_lock);
		WARN_ON_ONCE(!test_and_clear_bit(meta_line[i], &l_mg[i]->meta_bitmap)); 
		pblk_line_replace_data(pblk, i);
		spin_unlock(&l_mg[i]->free_lock);
	}

	pr_info("pblk: %s: recov raid1 succ\n", __func__);
	return recovered_lines;
}

int pblk_recov_l2p_raid5(struct pblk *pblk)
{
	struct pblk_line *line[NVM_MD_MAX_DEV_CNT];
	struct pblk_line *tline[NVM_MD_MAX_DEV_CNT];
	struct pblk_line_mgmt *l_mg[NVM_MD_MAX_DEV_CNT];

	struct pblk_smeta *smeta[NVM_MD_MAX_DEV_CNT];
	struct pblk_emeta *emeta[NVM_MD_MAX_DEV_CNT];
	struct line_smeta *smeta_buf[NVM_MD_MAX_DEV_CNT];
	int found_lines[NVM_MD_MAX_DEV_CNT];
	int meta_line[NVM_MD_MAX_DEV_CNT];
	int err_no[NVM_MD_MAX_DEV_CNT];
	struct list_head recov_list[NVM_MD_MAX_DEV_CNT];
	struct line_emeta *emeta_buf;
	int recovered_lines = 0;
	int gid = 0; // cur_group of lines
	int dev_id, i;
	struct pblk_md_line_group_set *set = &pblk->md_line_group_set;
	struct pblk_md_line_group *group;

	for (i = 0; i < pblk->nr_dev; i++) {
		dev_id = i;
		l_mg[i] = &pblk->l_mg[i];

		INIT_LIST_HEAD(&recov_list[i]);
		found_lines[i] = pblk_recov_smeta_dev(pblk, dev_id, &recov_list[i], &meta_line[i], &err_no[i]);
		if (!found_lines[i] || err_no[i] < 0) {
			pr_err("pblk: %s: recov_smeta of dev %d fail\n", 
					__func__, dev_id);
			return -1;
		}

		smeta[i] = l_mg[i]->sline_meta[meta_line[i]];
		emeta[i] = l_mg[i]->eline_meta[meta_line[i]];
		smeta_buf[i] = (struct line_smeta *)smeta;
	}

	if (pblk_check_found_lines(found_lines, pblk->nr_dev)) {
		pr_err("pblk: %s: found_lines not equal, abort\n", __func__);
		return -1;
	}

	//pr_info("pblk: %s: stop before read emeta\n", __func__);
	//return ERR_PTR(-EINVAL);

	/* Verify closed blocks and recover this portion of L2P table*/
	
	for (i = 1; i < pblk->nr_dev; i++)
		line[i] = list_first_entry(&recov_list[i], typeof(*line[i]), list);

	list_for_each_entry_safe(line[0], tline[0], &recov_list[0], list) {
		// update line_group info
		group = &set->line_groups[gid];
		for (i = 0; i < pblk->nr_dev; i++) {
			group->line_units[i].dev_id = i;
			group->line_units[i].line_id = line[i]->id;
		}
		gid++;
		recovered_lines++;

		for (i = 1; i < pblk->nr_dev; i++) {
			tline[i] = list_next_entry(line[i], list);
		}
		/*
		for (i = 0; i < pblk->nr_dev; i++) 
			pr_info("pblk: %s: recov emeta line %d dev %d\n",
					__func__, line[i]->id, i);
		*/
		for (i = 0; i < pblk->nr_dev; i++) {
			pr_info("pblk: %s: recov emeta line %d dev %d\n",
					__func__, line[i]->id, i);
			if (pblk_recov_emeta_dev(pblk, line[i], emeta[i])) {
				pr_err("pblk: %s: err to recov emeta line %d of dev %d\n", 
						__func__, line[0]->id, line[0]->dev_id);
				return -1;
			}
		}
		pr_info("pblk: %s: rec md_line seq_nr %d finish\n",
				__func__, line[0]->seq_nr);

		emeta_buf = line[0]->emeta->buf;
		for (i = 1; i < pblk->nr_dev; i++) {
			if (memcmp(line[i]->emeta->buf->line_units, emeta_buf->line_units, 
				sizeof(struct pblk_md_line_unit_le)*pblk->nr_dev)) {
				pr_err("pblk: %s: corrupt line id %d, seq_nr %d emeta line_units\n", 
						__func__, line[0]->id, line[0]->seq_nr);
				return -1;
			}
		}
		pr_info("pblk: %s: md_line seq_nr %d md_info PASS\n",
				__func__, line[0]->seq_nr);

		for (i = 0; i < pblk->nr_dev; i++) {
			if (pblk_line_is_full(line[i])) {
				pr_info("pblk: %s: rec line %d of dev %d is full\n",
						__func__, line[i]->id, line[i]->dev_id);
				struct list_head *move_list;

				spin_lock(&line[i]->lock);
				line[i]->state = PBLK_LINESTATE_CLOSED;
				move_list = pblk_line_gc_list(pblk, line[i]);
				spin_unlock(&line[i]->lock);

				spin_lock(&l_mg[i]->gc_lock);
				list_move_tail(&line[i]->list, move_list);
				spin_unlock(&l_mg[i]->gc_lock);

				kfree(line[i]->map_bitmap);
				line[i]->map_bitmap = NULL;
				line[i]->smeta = NULL;
				line[i]->emeta = NULL;
			} else {
				pr_err("pblk: %s: recov line %d of dev %d not full\n",
						__func__, line[i]->id, line[i]->dev_id);
				return -1;
			}
		}
		for (i = 1; i < pblk->nr_dev; i++)
			line[i] = tline[i];
	}

	for (i = 0; i < pblk->nr_dev; i++) {
		spin_lock(&l_mg[i]->free_lock);
		WARN_ON_ONCE(!test_and_clear_bit(meta_line[i], &l_mg[i]->meta_bitmap)); 
		pblk_line_replace_data(pblk, i);
		spin_unlock(&l_mg[i]->free_lock);
	}

	pr_info("pblk: %s: recov raid5 succ\n", __func__);
	return recovered_lines;
}

int pblk_recov_l2p(struct pblk  *pblk)
{
	switch (pblk->md_mode) {
		case PBLK_SD:
			return pblk_recov_l2p_sd(pblk);
		case PBLK_RAID0:
			return pblk_recov_l2p_raid0(pblk);
		case PBLK_RAID1:
			return pblk_recov_l2p_raid1(pblk);
		case PBLK_RAID5:
			return pblk_recov_l2p_raid5(pblk);
		default:
			pr_err("pblk: %s: %d not supported now\n", __func__, pblk->md_mode);
			return ERR_PTR(-EINVAL);
	}
}

/*
 * Pad current line
 */
int pblk_recov_pad(struct pblk *pblk, int dev_id)
{
	struct pblk_line *line;
	struct pblk_line_mgmt *l_mg = &pblk->l_mg[dev_id];
	int left_msecs;
	int ret = 0;
	pr_info("pblk rec: func(%s) called here, warning\n", __func__);

	spin_lock(&l_mg->free_lock);
	line = l_mg->data_line;
	left_msecs = line->left_msecs;
	spin_unlock(&l_mg->free_lock);

	pr_info("pblk rec: begin pad line %d of dev %d\n", line->id, line->dev_id);

	ret = pblk_recov_pad_oob(pblk, line, left_msecs);
	if (ret) {
		pr_err("pblk: Tear down padding failed (%d)\n", ret);
		return ret;
	}
	pr_info("pblk rec: wait for pad line meta\n");

	pblk_line_close_meta(pblk, line);
	pr_info("pblk rec: end pad line\n");
	return ret;
}
