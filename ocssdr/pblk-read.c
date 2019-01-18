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
 * pblk-read.c - pblk's read path
 */


// md-bugs: all bio forwarded to devs[0]

#include "pblk.h"

/*
 * There is no guarantee that the value read from cache has not been updated and
 * resides at another location in the cache. We guarantee though that if the
 * value is read from the cache, it belongs to the mapped lba. In order to
 * guarantee and order between writes and reads are ordered, a flush must be
 * issued.
 */
static int pblk_read_from_cache(struct pblk *pblk, struct bio *bio,
				sector_t lba, struct ppa_addr ppa,
				int bio_iter, bool advanced_bio)
{
#ifdef CONFIG_NVM_DEBUG
	/* Callers must ensure that the ppa points to a cache address */
	BUG_ON(pblk_ppa_empty(ppa));
	BUG_ON(!pblk_addr_in_cache(ppa));
#endif

	return pblk_rb_copy_to_bio(&pblk->rwb, bio, lba, ppa,
						bio_iter, advanced_bio);
}

static void pblk_read_ppalist_rq(struct pblk *pblk, struct nvm_rq *rqd,
				 sector_t blba, unsigned long *read_bitmap, struct ppa_addr  *ppa_list)
{
	struct pblk_sec_meta *meta_list = rqd->meta_list;
	struct bio *bio = rqd->bio;
	struct ppa_addr ppas[PBLK_MAX_REQ_ADDRS];
	int nr_secs = rqd->nr_ppas;
	bool advanced_bio = false;
	int i, j = 0;
    struct nvm_tgt_dev *dev = pblk->devs[DEFAULT_DEV_ID]; //add by kan
    struct nvm_geo *geo = &dev->geo; //add by kan
    int meta_list_idx; //add by kan
    int meta_list_mod; //add by kan

#ifdef META_READ
	if (!meta_list) {
		pr_err("pblk: %s: rqd->meta_list NULL, can't run META_READ\n", __func__);
	}
#endif

	pblk_lookup_l2p_seq(pblk, ppas, blba, nr_secs);


	for (i = 0; i < nr_secs; i++) {
		struct ppa_addr p = ppas[i];
		sector_t lba = blba + i;

        meta_list_idx = i; //add by kan
        meta_list_mod = p.m.sec % geo->ws_min; //add by kan
retry:
		if (pblk_ppa_empty(p)) {
			WARN_ON(test_and_set_bit(i, read_bitmap));
            
#ifdef META_READ
			meta_list[meta_list_idx].lba[0] = cpu_to_le64(ADDR_EMPTY); //modify by kan
			meta_list[meta_list_idx].lba[1] = cpu_to_le64(ADDR_EMPTY); //modify by kan
			meta_list[meta_list_idx].lba[2] = cpu_to_le64(ADDR_EMPTY); //modify by kan
			meta_list[meta_list_idx].lba[3] = cpu_to_le64(ADDR_EMPTY); //modify by kan
#endif

			if (unlikely(!advanced_bio)) {
				bio_advance(bio, (i) * PBLK_EXPOSED_PAGE_SIZE);
				advanced_bio = true;
			}

			goto next;
		}

		/* Try to read from write buffer. The address is later checked
		 * on the write buffer to prevent retrieving overwritten data.
		 */
		if (pblk_addr_in_cache(p)) {
			if (!pblk_read_from_cache(pblk, bio, lba, p, i,
								advanced_bio)) {
				pblk_lookup_l2p_seq(pblk, &p, lba, 1);
				goto retry;
			}
			WARN_ON(test_and_set_bit(i, read_bitmap));
#ifdef META_READ
			meta_list[meta_list_idx].lba[0] = cpu_to_le64(lba); //modify by kan
			meta_list[meta_list_idx].lba[1] = cpu_to_le64(lba); //modify by kan
			meta_list[meta_list_idx].lba[2] = cpu_to_le64(lba); //modify by kan
			meta_list[meta_list_idx].lba[3] = cpu_to_le64(lba); //modify by kan
#endif
			advanced_bio = true;
#ifdef CONFIG_NVM_DEBUG
			atomic_long_inc(&pblk->cache_reads);
#endif
		} else {
			/* Read from media non-cached sectors */
			ppa_list[j++] = p;
		}

next:
		if (advanced_bio)
			bio_advance(bio, PBLK_EXPOSED_PAGE_SIZE);
	}

	// question: meaning?  by zhitao.
	// PBLK_READ_RANDOM always. by zhitao.
	/*
	if (pblk_io_aligned(pblk, nr_secs))
		rqd->flags = pblk_set_read_mode(pblk, PBLK_READ_SEQUENTIAL);
	else
		rqd->flags = pblk_set_read_mode(pblk, PBLK_READ_RANDOM);
	*/
	rqd->flags = pblk_set_read_mode(pblk, PBLK_READ_RANDOM);

#ifdef CONFIG_NVM_DEBUG
	atomic_long_add(nr_secs, &pblk->inflight_reads);
#endif
}

static int pblk_submit_read_io(struct pblk *pblk, struct nvm_rq *rqd, int dev_id)
{
	int err;

	err = pblk_submit_io(pblk, rqd, dev_id);
	if (err)
		return NVM_IO_ERR;

	return NVM_IO_OK;
}

static void pblk_read_check(struct pblk *pblk, struct nvm_rq *rqd,
			   sector_t blba)
{
	struct pblk_sec_meta *meta_list = rqd->meta_list;
	int nr_lbas = rqd->nr_ppas;
	int i;
    struct nvm_tgt_dev *dev = pblk->devs[DEFAULT_DEV_ID]; //add by kan
    struct nvm_geo *geo = &dev->geo; //add by kan
    int meta_list_idx; //add by kan
    int meta_list_mod; //add by kan
    struct ppa_addr *ppas; //add by kan
    struct ppa_addr ppa; //add by kan
    struct ppa_addr p;

    //add by kan
    if(nr_lbas > 1)
        ppas = rqd->ppa_list; 
    else 
        ppa = rqd->ppa_addr;

	for (i = 0; i < nr_lbas; i++) {
        meta_list_idx = i; //add by kan
        //add by kan
        if(nr_lbas > 1) 
            p = ppas[i];
        else
            p = ppa;

        //add by kan
        if(p.c.is_cached)
            meta_list_mod = 0;
        else 
            meta_list_mod = p.m.sec % geo->ws_min;

		u64 lba = le64_to_cpu(meta_list[meta_list_idx].lba[meta_list_mod]); //modify by kan

        //printk( "pblk: glba=%llx rlba=%llx | ppa=%llx m.sec=%x nr_lbas=%x\n", blba + i, lba, p.ppa, p.m.sec, nr_lbas); //add by kan for debug


		if (lba == ADDR_EMPTY)
			continue;

        if (lba != blba + i)
            printk("pblk: lba = %llx blba =%lx ppa=%llx\n", lba, blba + i, p.ppa);    
		WARN(lba != blba + i, "pblk: corrupted read LBA\n");
	}
}

static void pblk_read_put_rqd_kref(struct pblk *pblk, struct nvm_rq *rqd)
{
	struct ppa_addr *ppa_list;
	int i;
	int dev_id;

	ppa_list = (rqd->nr_ppas > 1) ? rqd->ppa_list : &rqd->ppa_addr;

	for (i = 0; i < rqd->nr_ppas; i++) {
		struct ppa_addr ppa = ppa_list[i];
		struct pblk_line *line;
		dev_id = pblk_get_ppa_dev_id(ppa);

		line = &pblk->lines[dev_id][pblk_ppa_to_line(ppa)];
		kref_put(&line->ref, pblk_line_put_wq);
	}
}

static void pblk_end_user_read(struct bio *bio)
{
#ifdef CONFIG_NVM_DEBUG
	WARN_ONCE(bio->bi_status, "pblk: corrupted read bio\n");
#endif
	
	bio_endio(bio);
	bio_put(bio);
}

static void pblk_fill_read_io(struct bio *dst_bio, struct bio *src_bio, int nr_secs)
{
	struct bio_vec src_bv, dst_bv;
	void *src_p, *dst_p;
	int i;
	pr_info("pblk: %s now we fill read bio %d secs\n", __func__, nr_secs);
	for (i = 0; i < nr_secs; i++) {
		src_bv = src_bio->bi_io_vec[i];
		dst_bv = dst_bio->bi_io_vec[i];

		src_p = kmap_atomic(src_bv.bv_page);
		dst_p = kmap_atomic(dst_bv.bv_page);

		memcpy(dst_p + dst_bv.bv_offset,
			src_p + src_bv.bv_offset,
			PBLK_EXPOSED_PAGE_SIZE);

		kunmap_atomic(src_p);
		kunmap_atomic(dst_p);
	}
}

static void __pblk_end_io_read(struct pblk *pblk, struct nvm_rq *rqd,
			       bool put_line)
{
	struct pblk_g_ctx *r_ctx = nvm_rq_to_pdu(rqd);
	struct bio *bio = rqd->bio;
	//unsigned long start_time = r_ctx->start_time;

	if (rqd->error)
		pblk_log_read_err(pblk, rqd);
#ifdef CONFIG_NVM_DEBUG
	else
		WARN_ONCE(bio->bi_status, "pblk: corrupted read error\n");
#endif

	//pblk_read_check(pblk, rqd, r_ctx->lba);

	if (r_ctx->private) {
		//pblk_fill_read_io((struct bio *)r_ctx->private, bio, rqd->nr_ppas);
		pblk_end_user_read((struct bio *)r_ctx->private);
	}
	bio_put(bio);

	if (put_line)
		pblk_read_put_rqd_kref(pblk, rqd);

#ifdef CONFIG_NVM_DEBUG
	atomic_long_add(rqd->nr_ppas, &pblk->sync_reads);
	atomic_long_sub(rqd->nr_ppas, &pblk->inflight_reads);
#endif

	pblk_free_rqd(pblk, rqd, PBLK_READ);
	atomic_dec(&pblk->inflight_io);
}

static void pblk_end_io_read(struct nvm_rq *rqd)
{
	struct pblk *pblk = rqd->private;

	__pblk_end_io_read(pblk, rqd, true);
}

static void __pblk_end_io_read_md(struct pblk *pblk, struct pblk_md_read_ctx *md_r_ctx) 
{
	struct nvm_rq *md_rqd;
	struct bio *md_bio, *child_bio;
	int *offset;
	struct ppa_addr ppa;
	int i, dev_id;
	struct bio_vec src_bv, dst_bv;
	void *src_p, *dst_p;
	int done = atomic_inc_return(&md_r_ctx->completion_cnt);
	int bio_init_idx = md_r_ctx->bio_init_idx;

	//pr_info("pblk: %s: %d/%d done\n", __func__, done, md_r_ctx->nr_child_io);
	if (done == md_r_ctx->nr_child_io) {
		//pr_info("pblk: %s: now fill md_bio\n", __func__);
		// now user read io complete
		md_rqd = md_r_ctx->rqd;
		md_bio = md_rqd->bio;
			
		offset = kcalloc(NVM_MD_MAX_DEV_CNT, sizeof(int), GFP_KERNEL);
		if (!offset) {
			pr_err("pblk: %s not able to alloc offset arr\n", __func__);
			goto out;
		}
		// fill md_bio with child_bio
		for (i = 0; i < md_rqd->nr_ppas; i++) {
			if (test_bit(i, &md_r_ctx->read_bitmap))
				continue;

			ppa = md_r_ctx->ppa_list[i];
			dev_id = pblk_get_ppa_dev_id(ppa);
			child_bio = md_r_ctx->bio[dev_id];
			if (!child_bio) {
				pr_err("pblk: NULL off child_bio %d\n", dev_id);
				goto free_offset;
			}

			src_bv = child_bio->bi_io_vec[offset[dev_id]];
			dst_bv = md_bio->bi_io_vec[bio_init_idx + i];

			src_p = kmap_atomic(src_bv.bv_page);
			dst_p = kmap_atomic(dst_bv.bv_page);

			memcpy(dst_p + dst_bv.bv_offset,
				src_p + src_bv.bv_offset,
				PBLK_EXPOSED_PAGE_SIZE);
			/*
			pr_info("pblk: %s copy md_bio page_no %d from child_bio page_no %d\n",
					__func__, offset[dev_id], bio_init_idx+i);
				*/

			kunmap_atomic(src_p);
			kunmap_atomic(dst_p);

			offset[dev_id]++;
		}
free_offset:
		kfree(offset);
out:
		bio_endio(md_bio);
		bio_put(md_bio);
		for (dev_id = 0; dev_id < NVM_MD_MAX_DEV_CNT; dev_id++) {
			child_bio = md_r_ctx->bio[dev_id];
			if (child_bio) {
				pblk_bio_free_pages(pblk, child_bio, 0, child_bio->bi_vcnt);
				bio_put(child_bio);
			}
		}

		pblk_read_put_rqd_kref(pblk, md_rqd);

#ifdef CONFIG_NVM_DEBUG
		atomic_long_add(md_rqd->nr_ppas, &pblk->sync_reads);
		atomic_long_sub(md_rqd->nr_ppas, &pblk->inflight_reads);
#endif

		pblk_free_rqd(pblk, md_rqd, PBLK_READ);
		kfree(md_r_ctx);
	}
}

static void pblk_end_io_read_child(struct nvm_rq *child_rqd)
{
	struct nvm_rq *rqd = child_rqd;
	struct pblk *pblk = rqd->private;
	struct nvm_tgt_dev *dev = rqd->dev;
	struct pblk_g_ctx *r_ctx = nvm_rq_to_pdu(rqd);
	struct bio *bio = rqd->bio;
	int dev_id;
	if (!dev) {
		pr_err("pblk: %s rqd undefined dev\n", __func__);
		dev = pblk->devs[DEFAULT_DEV_ID];
	}
	//dev_id = pblk_get_rq_dev_id(pblk, rqd);
	//pr_info("pblk: %s callback, dev %d\n", __func__, dev_id);

	if (rqd->error)
		pblk_log_read_err(pblk, rqd);
#ifdef CONFIG_NVM_DEBUG
	else
		WARN_ONCE(bio->bi_status, "pblk: corrupted read error\n");
#endif

	__pblk_end_io_read_md(pblk, (struct pblk_md_read_ctx *)r_ctx->private);

	pblk_free_rqd(pblk, rqd, PBLK_READ);
	atomic_dec(&pblk->inflight_io);
}


static int pblk_partial_read_bio(struct pblk *pblk, struct nvm_rq *rqd,
				 unsigned int bio_init_idx,
				 unsigned long *read_bitmap)
{
	int dev_id = DEFAULT_DEV_ID;
	struct bio *new_bio, *bio = rqd->bio;
	struct pblk_sec_meta *meta_list = rqd->meta_list;
	struct bio_vec src_bv, dst_bv;
	void *ppa_ptr = NULL;
	void *src_p, *dst_p;
	dma_addr_t dma_ppa_list = 0;
	__le64 *lba_list_mem, *lba_list_media;
	int nr_secs = rqd->nr_ppas;
	int nr_holes = nr_secs - bitmap_weight(read_bitmap, nr_secs);
	int i, ret, hole;
    int meta_list_idx; //add by kan
    int meta_list_mod; //add by kan
    struct nvm_tgt_dev *dev = pblk->devs[dev_id]; //add by kan
    struct nvm_geo *geo = &dev->geo; //add by kan

	/* Re-use allocated memory for intermediate lbas */
	lba_list_mem = (((void *)rqd->ppa_list) + pblk_dma_ppa_size);
	lba_list_media = (((void *)rqd->ppa_list) + 2 * pblk_dma_ppa_size);
    //lba_list_media = kmalloc(pblk_dma_ppa_size, GFP_KERNEL);// add by kan	

	new_bio = bio_alloc(GFP_KERNEL, nr_holes);

	if (pblk_bio_add_pages(pblk, new_bio, GFP_KERNEL, nr_holes, dev_id))
		goto err;

	if (nr_holes != new_bio->bi_vcnt) {
		pr_err("pblk: malformed bio\n");
		goto err;
	}

    //if data not in media //kan	
    for (i = 0; i < nr_secs; i++) {
        meta_list_idx = i; //add by kan
        //add by kan
        if(nr_secs > 1)
            meta_list_mod = rqd->ppa_list[i].m.sec % geo->ws_min; 
        else 
            meta_list_mod = rqd->ppa_addr.m.sec % geo->ws_min;     
		lba_list_mem[i] = meta_list[meta_list_idx].lba[meta_list_mod]; //modify by kan
    }

	new_bio->bi_iter.bi_sector = 0; /* internal bio */
	bio_set_op_attrs(new_bio, REQ_OP_READ, 0);

	rqd->bio = new_bio;
	rqd->nr_ppas = nr_holes;
    //printk("pblk: device read nr_ppas=%d\n",rqd->nr_ppas); //add by kan for debug
	rqd->flags = pblk_set_read_mode(pblk, PBLK_READ_RANDOM);

	if (unlikely(nr_holes == 1)) {
		ppa_ptr = rqd->ppa_list;
		dma_ppa_list = rqd->dma_ppa_list;
		rqd->ppa_addr = rqd->ppa_list[0];
	}

#ifndef META_READ
	memset(rqd->meta_list, 0, pblk_dma_meta_size);
#endif

	ret = pblk_submit_io_sync(pblk, rqd, dev_id);
	if (ret) {
		bio_put(rqd->bio);
		pr_err("pblk: sync read IO submission failed\n");
		goto err;
	}

	if (rqd->error) {
		atomic_long_inc(&pblk->read_failed);
#ifdef CONFIG_NVM_DEBUG
		pblk_print_failed_rqd(pblk, rqd, rqd->error);
#endif
	}

	if (unlikely(nr_holes == 1)) {
		struct ppa_addr ppa;

		ppa = rqd->ppa_addr;
		rqd->ppa_list = ppa_ptr;
		rqd->dma_ppa_list = dma_ppa_list;
		rqd->ppa_list[0] = ppa;
	}

    //read metadata from media
	for (i = 0; i < nr_secs; i++) {
        meta_list_idx = i; //add by kan
        //add by kan
        if(nr_secs > 1)
            meta_list_mod = rqd->ppa_list[i].m.sec % geo->ws_min; 
        else 
            meta_list_mod = rqd->ppa_addr.m.sec % geo->ws_min;     
		lba_list_media[i] = meta_list[meta_list_idx].lba[meta_list_mod]; //modify by kan
		meta_list[meta_list_idx].lba[meta_list_mod] = lba_list_mem[i]; //modify by kan
	}

	/* Fill the holes in the original bio */
	i = 0;
	hole = find_first_zero_bit(read_bitmap, nr_secs);
	do {
		int line_id = pblk_ppa_to_line(rqd->ppa_list[i]);
		struct pblk_line *line = &pblk->lines[dev_id][line_id];

		kref_put(&line->ref, pblk_line_put);

        meta_list_idx = hole; //add by kan
        //add by kan
        if (nr_secs > 1)
            meta_list_mod = rqd->ppa_list[hole].m.sec % geo->ws_min; //add by kan
        else 
            meta_list_mod = rqd->ppa_addr.m.sec % geo->ws_min; //add by kan      
            
		meta_list[meta_list_idx].lba[meta_list_mod] = lba_list_media[i]; //modify by kan

		src_bv = new_bio->bi_io_vec[i++];
		dst_bv = bio->bi_io_vec[bio_init_idx + hole];

		src_p = kmap_atomic(src_bv.bv_page);
		dst_p = kmap_atomic(dst_bv.bv_page);

		memcpy(dst_p + dst_bv.bv_offset,
			src_p + src_bv.bv_offset,
			PBLK_EXPOSED_PAGE_SIZE);

		kunmap_atomic(src_p);
		kunmap_atomic(dst_p);

		mempool_free(src_bv.bv_page, pblk->page_bio_pool);

		hole = find_next_zero_bit(read_bitmap, nr_secs, hole + 1);
	} while (hole < nr_secs);

	bio_put(new_bio);

	/* Complete the original bio and associated request */
	bio_endio(bio);
	rqd->bio = bio;
	rqd->nr_ppas = nr_secs;

	__pblk_end_io_read(pblk, rqd, false);
    //kfree(lba_list_media); //add by kan
	return NVM_IO_OK;

err:
	pr_err("pblk: failed to perform partial read\n");

	/* Free allocated pages in new bio */
	pblk_bio_free_pages(pblk, bio, 0, new_bio->bi_vcnt);
	__pblk_end_io_read(pblk, rqd, false);
    //kfree(lba_list_media); //add by kan
	return NVM_IO_ERR;
}

static void pblk_read_rq(struct pblk *pblk, struct nvm_rq *rqd,
			 sector_t lba, unsigned long *read_bitmap)
{
	struct pblk_sec_meta *meta_list = rqd->meta_list;
	struct bio *bio = rqd->bio;
	struct ppa_addr ppa;

#ifdef META_READ
	if (!meta_list) {
		pr_err("pblk: %s: rqd->meta_list NULL, can't run META_READ\n", __func__);
	}
#endif

	pblk_lookup_l2p_seq(pblk, &ppa, lba, 1);

#ifdef CONFIG_NVM_DEBUG
	atomic_long_inc(&pblk->inflight_reads);
#endif

retry:
	if (pblk_ppa_empty(ppa)) {
		WARN_ON(test_and_set_bit(0, read_bitmap));
#ifdef META_READ
		meta_list[0].lba[0] = cpu_to_le64(ADDR_EMPTY); //modify by kan
#endif
		return;
	}

	/* Try to read from write buffer. The address is later checked on the
	 * write buffer to prevent retrieving overwritten data.
	 */
	if (pblk_addr_in_cache(ppa)) {
		if (!pblk_read_from_cache(pblk, bio, lba, ppa, 0, 1)) {
			pblk_lookup_l2p_seq(pblk, &ppa, lba, 1);
			goto retry;
		}

		WARN_ON(test_and_set_bit(0, read_bitmap));
#ifdef META_READ
		meta_list[0].lba[0] = cpu_to_le64(lba);
#endif

#ifdef CONFIG_NVM_DEBUG
		atomic_long_inc(&pblk->cache_reads);
#endif
	} else {
		rqd->ppa_addr = ppa;
	}

	rqd->flags = pblk_set_read_mode(pblk, PBLK_READ_RANDOM);
}

static int pblk_submit_read_bio_md_async(struct pblk *pblk, struct nvm_rq *md_rqd, struct pblk_md_read_ctx *md_r_ctx, struct nvm_rq **ret_rqd)
{
	struct ppa_addr ppa_buf[PBLK_MAX_REQ_ADDRS];
	struct ppa_addr *ppa_list = md_r_ctx->ppa_list;
	unsigned long read_bitmap = md_r_ctx->read_bitmap;
	int nr_secs = md_rqd->nr_ppas;
	int hole = 0;
	int nr_holes = nr_secs - bitmap_weight(&read_bitmap, nr_secs);
	struct nvm_rq *rqd;
	struct bio *bio;
	struct pblk_g_ctx *r_ctx;
	int nr_child_secs = 0;
	int nr_child_io = 0;
	int dev_id, i;
	int ret = NVM_IO_ERR;

	//pr_info("pblk: %s nr_holes %d, nr_secs %d\n", __func__, nr_holes, nr_secs);

	// fill md_r_ctx
	for (dev_id = 0; dev_id < pblk->nr_dev; dev_id++) {
		for (i = 0; i < nr_secs; i++) {
			if (test_bit(i, &read_bitmap))
				continue;
			if (pblk_get_ppa_dev_id(ppa_list[i]) == dev_id) {
				nr_child_io++;
				break;
			}
		}
	}
	md_r_ctx->rqd = md_rqd;
	md_r_ctx->nr_child_io = nr_child_io;
	atomic_set(&md_r_ctx->completion_cnt, 0);
	//pr_info("pblk: %s: nr_child_io %d\n", __func__, nr_child_io);

	// fill each child_io
	//for (dev_id = 0; dev_id < 1; dev_id++) {
	for (dev_id = 0; dev_id < pblk->nr_dev; dev_id++) {
		nr_child_secs = 0;
		for (i = 0; i < nr_secs; i++) {
			if (test_bit(i, &read_bitmap))
				continue;
			if (pblk_get_ppa_dev_id(ppa_list[i]) == dev_id) {
				// clear dev_id info in ppa
				ppa_buf[nr_child_secs] = ppa_list[i];
				ppa_buf[nr_child_secs] = pblk_set_ppa_dev_id(ppa_buf[nr_child_secs], 0);
				nr_child_secs++;
				hole++;
			}
		}

		/*
		pr_info("pblk: %s, %d/%d in dev[%d]\n", 
				__func__, nr_child_secs, nr_secs, dev_id);
		*/

		// no ppa of dev_id
		if (!nr_child_secs) 
			continue;

		rqd = pblk_alloc_rqd(pblk, PBLK_READ);
		*ret_rqd = rqd;

		rqd->dev = pblk->devs[dev_id];
		rqd->opcode = NVM_OP_PREAD;
		rqd->nr_ppas = nr_child_secs;
		rqd->private = pblk;
		rqd->end_io = pblk_end_io_read_child;
		rqd->flags = pblk_set_read_mode(pblk, PBLK_READ_RANDOM);

		r_ctx = nvm_rq_to_pdu(rqd);
		r_ctx->private = md_r_ctx;

		// fill rqd->bio
		bio = bio_alloc(GFP_KERNEL, nr_child_secs);
		if (pblk_bio_add_pages(pblk, bio, GFP_KERNEL, nr_child_secs, dev_id))
			goto prepare_err;
		if (bio->bi_vcnt != nr_child_secs)
			goto prepare_err;
		bio->bi_iter.bi_sector = 0;
		bio_set_op_attrs(bio, REQ_OP_READ, 0);

		md_r_ctx->bio[dev_id] = bio;
		rqd->bio = bio;

		// fill rqd ppa_list
		rqd->meta_list = nvm_dev_dma_alloc(rqd->dev->parent, GFP_KERNEL,
								&rqd->dma_meta_list);
		if (!rqd->meta_list) {
			pr_err("pblk: not able to allocate ppa list\n");
			goto prepare_err;
		}
		if (nr_child_secs > 1) {
			rqd->ppa_list = rqd->meta_list + pblk_dma_meta_size;
			rqd->dma_ppa_list = rqd->dma_meta_list + pblk_dma_meta_size;

			for (i = 0; i < nr_child_secs; i++) {
				rqd->ppa_list[i] = ppa_buf[i];
				/*
				pr_info("pblk: child_io %d, ppa_list[%d] %llu\n",
						dev_id, i, ppa_buf[i].ppa);
				*/
			}
		} else {
			rqd->ppa_addr = ppa_buf[0];
		}

		/*
		if (nr_holes != nr_secs) {
			pr_err("pblk: %s partial read called, forbidden by zhitao\n", __func__);
			for (i = 0; i < nr_secs; i++) {
				pr_info("pblk: read_map info sec %d bit %d\n", i, test_bit(i, &read_bitmap));
			}
			//return  ret;
		}
		*/

		ret = pblk_submit_read_io(pblk, rqd, dev_id);
		if (ret) {
			pr_err("pblk: md read IO submission to dev %d failed\n", dev_id);
			goto fail_submission;
		}
	}

	if (hole != nr_holes) {
		pr_err("pblk: %s, hole %d not equal to nr_hole %d\n", __func__, hole, nr_holes);
	}
	return NVM_IO_OK;

prepare_err:
	pblk_bio_free_pages(pblk, bio, 0, nr_child_secs);
	bio_put(bio);
	pblk_free_rqd(pblk, rqd, PBLK_READ);
	return NVM_IO_ERR;
fail_submission:
	// todo: failed Read IO
	pr_err("pblk: %s todo work: failed IO\n", __func__);
	bio_put(bio);
	pblk_free_rqd(pblk, rqd, PBLK_READ);
	atomic_dec(&pblk->inflight_io);

	bio_put(md_rqd->bio);
	pblk_free_rqd(pblk, md_rqd, PBLK_READ);

	kfree(md_r_ctx);
	return NVM_IO_ERR;
}
 
static int pblk_check_rqd(struct nvm_rq *ref_rqd, struct nvm_rq *rqd) 
{
	int ret = 1;
	int i;
	if (ref_rqd->dev != rqd->dev)
		return 0;
	pr_info("pblk: check_rqd same dev\n");
	if (ref_rqd->opcode != rqd->opcode) 
		return 0;
	pr_info("pblk: check_rqd same opcode\n");
	if (ref_rqd->flags != rqd->flags)
		return 0;
	pr_info("pblk: check_rqd same flags\n");
	if (ref_rqd->nr_ppas != rqd->nr_ppas)
		return 0;
	pr_info("pblk: check_rqd same nr_ppas\n");
	for (i = 0; i < rqd->nr_ppas; i++) {
		if (rqd->ppa_list[i].ppa != ref_rqd->ppa_list[i].ppa) 
			return 0;
	}
	pr_info("pblk: check_rqd same ppa_list\n");
	return ret;
}

int pblk_submit_read(struct pblk *pblk, struct bio *bio)
{
	sector_t blba = pblk_get_lba(bio);
	unsigned int nr_secs = pblk_get_secs(bio);
	struct pblk_md_read_ctx *md_r_ctx;
	struct pblk_g_ctx *r_ctx;
	struct nvm_rq *rqd;
	unsigned long read_bitmap; /* Max 64 ppas per request */
	int ret = NVM_IO_ERR;

	//pr_info("pblk: %s blba %lu, nr_secs %u\n", __func__, blba, nr_secs);

	/* logic error: lba out-of-bounds. Ignore read request */
	if (blba >= pblk->rl.nr_secs || nr_secs > PBLK_MAX_REQ_ADDRS) {
		WARN(1, "pblk: read lba out of bounds (lba:%llu, nr:%d)\n",
					(unsigned long long)blba, nr_secs);
		return NVM_IO_ERR;
	}
	//generic_start_io_acct(q, READ, bio_sectors(bio), &pblk->disk->part0); 
	bitmap_zero(&read_bitmap, nr_secs);

	md_r_ctx = kcalloc(1, sizeof(struct pblk_md_read_ctx), GFP_ATOMIC);
	if (!md_r_ctx) {
		pr_err("pblk: %s: not able to alloc md_r_ctx\n", __func__);
		return NVM_IO_ERR;
	}
	/* Save the index for this bio's start. This is needed in case
	 * we need to fill a partial read.
	 */
	md_r_ctx->bio_init_idx = pblk_get_bi_idx(bio);

	rqd = pblk_alloc_rqd(pblk, PBLK_READ);

	rqd->dev = pblk->devs[DEFAULT_DEV_ID];
	rqd->opcode = NVM_OP_PREAD;
	rqd->bio = bio;
	rqd->nr_ppas = nr_secs;
	rqd->private = pblk;
	rqd->end_io = pblk_end_io_read;

	r_ctx = nvm_rq_to_pdu(rqd);
	//r_ctx->start_time = jiffies;
	r_ctx->lba = blba;

	pblk_read_ppalist_rq(pblk, rqd, blba, &read_bitmap, md_r_ctx->ppa_list);
	// ppa_list is not xfer to device, only exists in md_rqd layer
	if (rqd->nr_ppas > 1) {
		rqd->ppa_list = md_r_ctx->ppa_list;
	} else {
		rqd->ppa_addr = md_r_ctx->ppa_list[0];
	}
	md_r_ctx->read_bitmap = read_bitmap;

	bio_get(bio);
	if (bitmap_full(&read_bitmap, nr_secs)) {
		bio_endio(bio);
		atomic_inc(&pblk->inflight_io);
		__pblk_end_io_read(pblk, rqd, false);
		return NVM_IO_OK;
	}
	struct nvm_rq *ret_rqd;
	//pr_info("pblk: pblk-read.c %s: async_read called\n", __func__);
	return pblk_submit_read_bio_md_async(pblk, rqd, md_r_ctx, &ret_rqd);

	// community read path

	rqd->meta_list = nvm_dev_dma_alloc(rqd->dev->parent, GFP_KERNEL,
			&rqd->dma_meta_list);
	if (nr_secs > 1) {
		rqd->ppa_list = rqd->meta_list + pblk_dma_meta_size;
		rqd->dma_ppa_list = rqd->dma_meta_list + pblk_dma_meta_size;

		int i;
		for (i = 0; i < nr_secs; i++)
			rqd->ppa_list[i] = md_r_ctx->ppa_list[i];
	} else {
		rqd->ppa_addr = md_r_ctx->ppa_list[0];
	}

	if (bitmap_empty(&read_bitmap, rqd->nr_ppas)) {
		if (!pblk_check_rqd(rqd, ret_rqd)) {
			pr_info("pblk: not equal rqd for two methods\n");
		}
		
		// Clone from raw bio
		/*
		struct bio *int_bio = bio_clone_fast(bio, GFP_KERNEL, pblk_bio_set);
		if (!int_bio) {
			pr_err("pblk: could not clone read bio\n");
			atomic_inc(&pblk->inflight_io);
			__pblk_end_io_read(pblk,  rqd, false);
			return ret;
		}
		*/
		// alloc a new bio
		struct bio *int_bio = bio_alloc(GFP_KERNEL, nr_secs);
		if (pblk_bio_add_pages(pblk, int_bio, GFP_KERNEL, nr_secs, DEFAULT_DEV_ID))
			return NVM_IO_ERR;
		if (int_bio->bi_vcnt != nr_secs)
			return NVM_IO_ERR;
		int_bio->bi_iter.bi_sector = 0;
		bio_set_op_attrs(int_bio, REQ_OP_READ, 0);

		rqd->bio = int_bio;
		r_ctx->private = bio;

		ret = pblk_submit_read_io(pblk, rqd, DEFAULT_DEV_ID);
		if (ret) {
			pr_err("pblk: read io submission failed\n");
			__pblk_end_io_read(pblk, rqd, false);
		}
		return NVM_IO_OK;
	}
	return ret;




	// The read bio request could be partially filled by the write buffer,
	// but there are some holes that need to be read from the drive.
	//pr_info("pblk: pblk-read.c %s: partial_read called\n", __func__);
	//return pblk_partial_read_bio(pblk, rqd, bio_init_idx, &read_bitmap);
}

static int read_ppalist_rq_gc(struct pblk *pblk, struct nvm_rq *rqd,
			      struct pblk_line *line, u64 *lba_list,
			      u64 *paddr_list_gc, unsigned int nr_secs)
{
	struct ppa_addr ppa_list_l2p[PBLK_MAX_REQ_ADDRS];
	struct ppa_addr ppa_gc;
	int valid_secs = 0;
	int i;

	pblk_lookup_l2p_rand(pblk, ppa_list_l2p, lba_list, nr_secs);

	for (i = 0; i < nr_secs; i++) {
		if (lba_list[i] == ADDR_EMPTY)
			continue;

		ppa_gc = addr_to_gen_ppa(pblk, paddr_list_gc[i], line->id);
		ppa_gc = pblk_set_ppa_dev_id(ppa_gc, line->dev_id);
		if (!pblk_ppa_comp(ppa_list_l2p[i], ppa_gc)) {
			paddr_list_gc[i] = lba_list[i] = ADDR_EMPTY;
			continue;
		}

		rqd->ppa_list[valid_secs++] = ppa_list_l2p[i];
	}

#ifdef CONFIG_NVM_DEBUG
	atomic_long_add(valid_secs, &pblk->inflight_reads);
#endif

	return valid_secs;
}

static int read_rq_gc(struct pblk *pblk, struct nvm_rq *rqd,
		      struct pblk_line *line, sector_t lba,
		      u64 paddr_gc)
{
	struct ppa_addr ppa_l2p, ppa_gc;
	int valid_secs = 0;

	if (lba == ADDR_EMPTY)
		goto out;

	/* logic error: lba out-of-bounds */
	if (lba >= pblk->rl.nr_secs) {
		WARN(1, "pblk: read lba out of bounds\n");
		goto out;
	}

	spin_lock(&pblk->trans_lock);
	ppa_l2p = pblk_trans_map_get(pblk, lba);
	spin_unlock(&pblk->trans_lock);

	ppa_gc = addr_to_gen_ppa(pblk, paddr_gc, line->id);
	ppa_gc = pblk_set_ppa_dev_id(ppa_gc, line->dev_id);
	if (!pblk_ppa_comp(ppa_l2p, ppa_gc))
		goto out;

	rqd->ppa_addr = ppa_l2p;
	valid_secs = 1;

#ifdef CONFIG_NVM_DEBUG
	atomic_long_inc(&pblk->inflight_reads);
#endif

out:
	return valid_secs;
}

int pblk_submit_read_gc(struct pblk *pblk, struct pblk_gc_rq *gc_rq)
{
	int dev_id = DEFAULT_DEV_ID;
	struct nvm_tgt_dev *dev = pblk->devs[dev_id];
	struct nvm_geo *geo = &dev->geo;
	struct bio *bio;
	struct nvm_rq rqd;
	int data_len;
	int ret = NVM_IO_OK;

	pr_err("pblk: pblk-read.c %s called here\n", __func__);

	memset(&rqd, 0, sizeof(struct nvm_rq));

	rqd.meta_list = nvm_dev_dma_alloc(dev->parent, GFP_KERNEL,
							&rqd.dma_meta_list);
    //size = pblk_dma_meta_size + pblk_dma_ppa_size; //add by kan
    //rqd.meta_list = dma_alloc_coherent(ctrl->dev, size, &rqd.dma_meta_list, GFP_KERNEL); //modify by kan
	
    if (!rqd.meta_list) {
        printk("pblk: meta list dma cannot alloc\n"); //add by kan
		return -ENOMEM;
    }

	if (gc_rq->nr_secs > 1) {
		rqd.ppa_list = rqd.meta_list + pblk_dma_meta_size;
		rqd.dma_ppa_list = rqd.dma_meta_list + pblk_dma_meta_size;

		gc_rq->secs_to_gc = read_ppalist_rq_gc(pblk, &rqd, gc_rq->line,
							gc_rq->lba_list,
							gc_rq->paddr_list,
							gc_rq->nr_secs);
		if (gc_rq->secs_to_gc == 1)
			rqd.ppa_addr = rqd.ppa_list[0];
	} else {
		gc_rq->secs_to_gc = read_rq_gc(pblk, &rqd, gc_rq->line,
							gc_rq->lba_list[0],
							gc_rq->paddr_list[0]);
	}



	if (!(gc_rq->secs_to_gc))
		goto out;

	data_len = (gc_rq->secs_to_gc) * geo->csecs;
	bio = pblk_bio_map_addr(pblk, gc_rq->data, gc_rq->secs_to_gc, data_len,
						PBLK_VMALLOC_META, GFP_KERNEL, dev_id);
	if (IS_ERR(bio)) {
		pr_err("pblk: could not allocate GC bio (%lu)\n", PTR_ERR(bio));
		goto err_free_dma;
	}

	bio->bi_iter.bi_sector = 0; /* internal bio */
	bio_set_op_attrs(bio, REQ_OP_READ, 0);

	rqd.opcode = NVM_OP_PREAD;
	rqd.nr_ppas = gc_rq->secs_to_gc;
	rqd.flags = pblk_set_read_mode(pblk, PBLK_READ_RANDOM);
	rqd.bio = bio;

	if (pblk_submit_io_sync(pblk, &rqd, dev_id)) {
		ret = -EIO;
		pr_err("pblk: GC read request failed\n");
		goto err_free_bio;
	}

	atomic_dec(&pblk->inflight_io);

	if (rqd.error) {
		atomic_long_inc(&pblk->read_failed_gc);
#ifdef CONFIG_NVM_DEBUG
		pblk_print_failed_rqd(pblk, &rqd, rqd.error);
#endif
	}

#ifdef CONFIG_NVM_DEBUG
	atomic_long_add(gc_rq->secs_to_gc, &pblk->sync_reads);
	atomic_long_add(gc_rq->secs_to_gc, &pblk->recov_gc_reads);
	atomic_long_sub(gc_rq->secs_to_gc, &pblk->inflight_reads);
#endif

out:
	nvm_dev_dma_free(dev->parent, rqd.meta_list, rqd.dma_meta_list);
	//dma_free_coherent(ctrl->dev, size, rqd.meta_list, rqd.dma_meta_list); //add by kan
    return ret;

err_free_bio:
	bio_put(bio);
err_free_dma:
	nvm_dev_dma_free(dev->parent, rqd.meta_list, rqd.dma_meta_list);
	//dma_free_coherent(ctrl->dev, size, rqd.meta_list, rqd.dma_meta_list); //add by kan
	return ret;
}
