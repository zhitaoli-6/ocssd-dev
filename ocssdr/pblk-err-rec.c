/*
 *
 */

#include "pblk.h"
//#include <linux/delay.h>

#define SLEEP_MS (2000)


static u64 ws_id = 0;

// ret: lines of err injected
int inject_line_err(struct pblk *pblk)
{
	struct pblk_err_rec *err_rec = &pblk->err_rec;
	struct pblk_line *line;
	int nr_injected = 2, inject = 1;
	int err_devs[] = {2, 1};
	int err_lines[] = {9, 10};
	int err_dev_id, err_line_id;
	int i;

	//pr_info("pblk: %s: do nothing now\n", __func__);

	for (i = 0; i < nr_injected; i++) {
		err_dev_id = err_devs[i];
		err_line_id = err_lines[i];
		line = &pblk->lines[err_dev_id][err_line_id];
		spin_lock(&line->lock);
		if (line->state != PBLK_LINESTATE_CLOSED) {
			inject = 0;
		}
		spin_unlock(&line->lock);
	}

	if (inject) {
		for (i = 0; i < nr_injected; i++) {
			err_dev_id = err_devs[i];
			err_line_id = err_lines[i];
			line = &pblk->lines[err_dev_id][err_line_id];
			spin_lock(&line->lock);
			if (line->state == PBLK_LINESTATE_CLOSED) {
				line->state = PBLK_LINESTATE_BAD;
				list_del(&line->list);
				list_add_tail(&line->list, &err_rec->err_line_list);
			}
			spin_unlock(&line->lock);
		}
	} else 
		return 0;
	return nr_injected;
}

static void pblk_rec_reader_kick(struct pblk_err_rec *err_rec)
{
	wake_up_process(err_rec->rec_r_ts);
}

static void pblk_rec_writer_kick(struct pblk_err_rec *err_rec)
{
	wake_up_process(err_rec->rec_w_ts);
}

static int pblk_err_monitor_run(struct pblk *pblk)
{
	//struct pblk_line_mgmt *l_mg;
	//struct pblk_line *line;
	struct pblk_err_rec *err_rec;
	//int i, nr_p_rec, nr_line;
	int ret = 0;
	err_rec = &pblk->err_rec;

	//pr_info("pblk: %s called\n", __func__);

	spin_lock(&err_rec->r_lock);
	/*
	nr_line = 0;
	for (i = 0; i < pblk->nr_dev; i++) {
		l_mg = pblk->l_mg[i];
		list_for_each_entry(line, &l_mg->err_read_list, list) {
			list_del(&line->list);
			list_add_tail(&line->list, &err_rec->err_line_list);
			nr_line++;
			break;
		}
		if (nr_line == nr_p_rec)
			break;
	}
	*/
	ret = inject_line_err(pblk);
	//pr_info("pblk: %s: inject err_line %d\n", __func__, ret);
	spin_unlock(&err_rec->r_lock);
	if (ret) {
		pblk_rec_reader_kick(err_rec);
	}
	return ret;
}

static int pblk_err_group_check(struct pblk *pblk, int gid)
{
	struct pblk_line_meta *lm = &pblk->lm;
	//struct pblk_line_mgmt *l_mg;
	struct pblk_md_line_group_set *set = &pblk->md_line_group_set;
	struct pblk_md_line_group *group;
	struct pblk_line *line;
	int dev_id, line_id;
	int i;

	if (gid >= set->cur_group) {
		pr_err("pblk: %s: err group gid %d > cur_gid %d\n",
				__func__, gid, set->cur_group);
		return -1;
	}

	group = &set->line_groups[gid];
	for (i = 0; i < group->nr_unit; i++) {
		dev_id = group->line_units[i].dev_id;
		line_id = group->line_units[i].line_id;
		line = &pblk->lines[dev_id][line_id];

		/*
		pr_info("pblk: %s: line %d of dev %d: smeta_len %d, smeta_sec %llu, emeta_len %d, emeta_ssec %llu\n",
				__func__, line_id, dev_id, lm->smeta_sec, line->smeta_ssec, lm->emeta_sec[0], line->emeta_ssec);
				*/

		if (line->smeta_ssec != 0) {
			pr_err("pblk: %s: line %d of dev %d smeta_ssec %llu\n",
					__func__, line_id, dev_id, line->smeta_ssec);
			return -1;
		}
		if (line->emeta_ssec != lm->sec_per_line - lm->emeta_sec[0]) {
			pr_err("pblk: %s: line %d of dev %d emeta_ssec %llu\n",
					__func__, line_id, dev_id, line->emeta_ssec);
			return -1;
		}
	}
	return 0;
}

void pblk_read_line_complete(struct kref *ref)
{
	struct pblk_err_r_rec_rq *rec_rq = container_of(ref, struct pblk_err_r_rec_rq, ref);
	complete(&rec_rq->wait);
}
void pblk_write_line_complete(struct kref *ref)
{
	struct pblk_err_w_rec_rq *rec_rq = container_of(ref, struct pblk_err_w_rec_rq, ref);
	complete(&rec_rq->wait);
}

void __pblk_end_io_read_rec_md(struct pblk_err_r_rec_rq *r_rec_rq, struct pblk_err_rec_ctx *rec_ctx)
{
	unsigned long *src, *dst;
	unsigned long data_len, long_len;
	int nr_child_io;
	int done = atomic_inc_return(&rec_ctx->completion_cnt);
	int i, j;
	//pr_info("pblk: %s: %d/%d done\n", __func__, done, rec_ctx->nr_child_io);
	if (done == rec_ctx->nr_child_io) {
		data_len = rec_ctx->data_len;
		long_len = data_len / sizeof(long);
		dst = rec_ctx->err_data;
		if (!dst) {
			pr_err("pblk: %s: missing info err_data\n", __func__);
			goto out;
		}
		//memset(rec_ctx->err_data, 0, data_len);
		nr_child_io = 0;
		for (i = 0; i < NVM_MD_MAX_DEV_CNT; i++) {
			if (rec_ctx->data[i]) {
				src = rec_ctx->data[i];
				for (j = 0; j < long_len; j++)
					dst[j] ^= src[j];
				nr_child_io++;
			}
		}
		if (nr_child_io != done) {
			pr_err("pblk: %s: unexpected parity calculation. %d/%d\n",
					__func__, nr_child_io, done);
			goto out;
		}
out:
		kfree(rec_ctx);
		kref_put(&r_rec_rq->ref, pblk_read_line_complete);
		return;
	}
}

void pblk_end_io_read_rec_child(struct nvm_rq *rqd)
{
	struct pblk_err_r_rec_rq *r_rec_rq= rqd->private;
	struct pblk *pblk = r_rec_rq->pblk;
	//struct nvm_tgt_dev *dev = rqd->dev;
	struct pblk_g_ctx *r_ctx = nvm_rq_to_pdu(rqd);
	struct bio *bio = rqd->bio;

	/*
	pr_info("pblk: %s: read_rec cbk: dev %d called\n",
			__func__, pblk_get_rq_dev_id(pblk, rqd));
			*/
	if (rqd->error) {
		pblk_log_read_err(pblk, rqd);
		// device read error handling: left to future work
	}
#ifdef CONFIG_NVM_DEBUG
	else
		WARN_ONCE(bio->bi_status, "pblk: corrupted read error\n");
#endif
	

	__pblk_end_io_read_rec_md(r_rec_rq, (struct pblk_err_rec_ctx *)r_ctx->private);

	//bio_put(rqd->bio);
	pblk_free_rqd(pblk, rqd, PBLK_READ);
	atomic_dec(&pblk->inflight_io);
}

static void pblk_end_io_rec_write(struct nvm_rq *rqd)
{
	struct pblk_err_w_rec_rq *w_rec_rq = rqd->private;
	struct pblk *pblk = w_rec_rq->pblk;

	int dev_id = pblk_get_rq_dev_id(pblk, rqd);
	if (dev_id < 0) {
		pr_err("pblk: %s rqd undefined dev\n", __func__);
		dev_id = DEFAULT_DEV_ID;
	}

	//pr_info("pblk: %s: cbk, dev %d\n", __func__, dev_id);

	pblk_up_page(pblk, rqd->ppa_list, rqd->nr_ppas, dev_id);

	pblk_free_rqd(pblk, rqd, PBLK_WRITE_INT);
	atomic_dec(&pblk->inflight_io);
	kref_put(&w_rec_rq->ref, pblk_write_line_complete);
}

static int pblk_alloc_rec_line(struct pblk *pblk)
{
	struct pblk_md_line_group_set *set = &pblk->md_line_group_set;
	struct pblk_md_line_group *group;

	unsigned long rec_bitmap;
	int rec_dev_id = -1, dev_id;
	int u;

	spin_lock(&set->lock);
	group = &set->line_groups[set->cur_group];

	rec_bitmap = set->rec_bitmap;
	for (u = 0; u < group->nr_unit; u++) {
		dev_id = group->line_units[u].dev_id;
		set_bit(dev_id, &rec_bitmap);
	}

	rec_dev_id = find_first_zero_bit(&rec_bitmap, NVM_MD_MAX_DEV_CNT);
	if (rec_dev_id >= pblk->nr_dev) {
		spin_unlock(&set->lock);
		pr_err("pblk: %s: can not alloc rec_line as target\n", __func__);
		return -1;
	}
	/*
	if (!test_bit(4, &set->rec_bitmap))
		rec_dev_id = 4;
		*/

	set_bit(rec_dev_id, &set->rec_bitmap);
	spin_unlock(&set->lock);
	return rec_dev_id;
}

static int pblk_rec_submit_write(struct pblk *pblk, struct pblk_line *line,
		struct pblk_err_w_rec_rq *w_rec_rq, int nr_secs, void *data)
{
	int dev_id = line->dev_id;
	struct nvm_tgt_dev *dev = pblk->devs[dev_id];
	struct nvm_geo *geo = &dev->geo;
	struct ppa_addr *ppa_list;
	struct pblk_sec_meta *meta_list;
	struct nvm_rq *rqd;
	struct bio *bio;
	dma_addr_t dma_ppa_list, dma_meta_list;
	__le64 *lba_list = emeta_to_lbas(pblk, line->emeta->buf);
	u64 w_ptr = line->cur_sec;
	int rq_ppas, rq_len;
	int i, j;
	int ret = 0;
    int meta_list_idx; //add by kan
    int meta_list_mod; //add by kan

	/*
	pr_info("pblk: %s: write to line %d of dev %d, nr_secs %d, cur_sec %d\n",
			__func__, line->id, dev_id, nr_secs, line->cur_sec);
			*/
	rq_ppas = nr_secs;
	rq_len = rq_ppas * geo->csecs;

	meta_list = nvm_dev_dma_alloc(dev->parent, GFP_KERNEL, &dma_meta_list);
    if (!meta_list) {
        pr_info("pblk: %s: meta list dma cannot alloc\n", __func__);
		ret = -ENOMEM;
		goto fail_free_rq;
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
	rqd->end_io = pblk_end_io_rec_write;
	rqd->private = w_rec_rq;
	rqd->dev = dev;
	
    for (i = 0; i < rqd->nr_ppas; ) {
		struct ppa_addr ppa;
		//int pos;

		w_ptr = pblk_alloc_page(pblk, line, pblk->min_write_pgs);
		ppa = addr_to_gen_ppa(pblk, w_ptr, line->id);
		//pos = pblk_ppa_to_pos(geo, ppa);

		for (j = 0; j < pblk->min_write_pgs; j++, i++, w_ptr++) {
			struct ppa_addr dev_ppa;
			__le64 addr_empty = cpu_to_le64(ADDR_EMPTY);

			dev_ppa = addr_to_gen_ppa(pblk, w_ptr, line->id);
			rqd->ppa_list[i] = dev_ppa;

			dev_ppa = pblk_set_ppa_dev_id(dev_ppa, dev_id);
			pblk_map_invalidate(pblk, dev_ppa);

            meta_list_idx = i / geo->ws_min; //add by kan
            meta_list_mod = dev_ppa.m.sec % geo->ws_min; //add by kan

			lba_list[w_ptr] = meta_list[meta_list_idx].lba[meta_list_mod] = addr_empty; //modify by kan
		}
	}

	//pr_info("pblk: %s: rec submit write prepare ok\n", __func__);

	kref_get(&w_rec_rq->ref);
	pblk_down_page(pblk, rqd->ppa_list, rqd->nr_ppas, dev_id);

	ret = pblk_submit_io(pblk, rqd, dev_id);
	//pr_info("pblk: %s: rec write submission ret %d\n", __func__, ret);
	if (ret) {
		pr_err("pblk: I/O submission failed: %d\n", ret);
		pblk_up_page(pblk, rqd->ppa_list, rqd->nr_ppas, dev_id);
		goto fail_free_bio;
	}
	
	return ret;

fail_free_bio:
	bio_put(bio);
fail_free_meta:
	nvm_dev_dma_free(dev->parent, meta_list, dma_meta_list);
	//dma_free_coherent(ctrl->dev, size, meta_list, dma_meta_list); //add by kan
fail_free_rq:
	return ret;
}

static void pblk_rec_line_ws(struct work_struct *work)
{
	struct pblk_line_ws *rec_line_ws = container_of(work,
			struct pblk_line_ws, ws);
	struct pblk *pblk = rec_line_ws->pblk;
	struct pblk_line *line = rec_line_ws->line;
	struct pblk_line *rec_line;
	struct pblk_line_meta *lm = &pblk->lm;
	struct nvm_tgt_dev *dev = pblk->devs[line->dev_id];
	struct nvm_geo *geo = &dev->geo;
	struct pblk_md_line_group_set *set = &pblk->md_line_group_set;
	struct pblk_md_line_group *group;
	struct pblk_err_rec *err_rec = &pblk->err_rec;
	struct nvm_rq *rqd;
	struct pblk_g_ctx *r_ctx;

	struct pblk_err_r_rec_rq *r_rec_rq = NULL;
	struct pblk_err_w_rec_rq *w_rec_rq = NULL;
	struct pblk_err_rec_ctx *rec_ctx;
	struct pblk_err_rec_write_t *task;
	struct bio *bio;

	//unsigned long IO_SIZE = PBLK_MAX_REQ_ADDRS;
	unsigned long IO_SIZE = pblk->min_write_pgs; // min_write_pgs: 8
	unsigned long W_SIZE = pblk->min_write_pgs; // min_write_pgs: 8
	unsigned long BATCH_SIZE = IO_SIZE * geo->all_luns * 8; // all_luns: 32
	unsigned long long LINE_LEN  = (unsigned long long)lm->sec_per_line*geo->csecs;
	size_t buf_len = (unsigned long long)geo->csecs * BATCH_SIZE; // pipeline: save memory

	void *p_data[NVM_MD_MAX_DEV_CNT]; // parity
	void *data_buf, *batch_buf;
	//void *w_buf, *r_buf;

	unsigned long s_jiff, e_jiff, jf1, jf2, jf3;
	unsigned long sub_r_cost = 0, wait_r_cost = 0;
	unsigned long sub_w_cost = 0, wait_w_cost = 0;
	unsigned long long off;
	unsigned long long line_data_sec;
	unsigned int nr_child_secs, batch_sec;

	struct ppa_addr dev_ppa;
	u64 s_addr, e_addr;
	int is_last_batch;
	int dev_id, err_dev_id, rec_dev_id;
	int gid, line_id;
	int d, u, j;
	int ret;
	
	pr_info("------------------------------------------------------\n");
	pr_info("pblk: %s: begin. line %d of dev %d ws id %llu!!!!\n",
			__func__, line->id, line->dev_id, (u64)rec_line_ws->priv);

	pr_info("pblk: %s: called, sleep for 5s!!!!!!!!!!!!!!!!!!!!\n",__func__);
	msleep(5000);

	s_jiff = jiffies;
	pr_info("pblk: %s: begin recover err line %d g_seq_nr %d of dev %d\n",
			__func__, line->id, line->g_seq_nr, line->dev_id);

	err_dev_id = line->dev_id;
	gid = line->g_seq_nr;
	group = &set->line_groups[gid];
	if (pblk_err_group_check(pblk, gid)) {
		ret = -1;
		goto out;
	}
	pr_info("pblk: %s: err line %d g_seq_nr %d of dev %d PASS group check\n",
			__func__, line->id, line->dev_id, line->g_seq_nr);
	
	line_data_sec = line->emeta_ssec - lm->smeta_sec;
	if (line_data_sec % W_SIZE) {
		pr_err("pblk: %s: line_data_sec mod W_SIZE not 0\n", __func__);
		ret = -1;
		goto out;
	}
	
	// alloc rec_line as dst
	if ((rec_dev_id = pblk_alloc_rec_line(pblk)) < 0) {
		ret = -1;
		goto out;
	}
	rec_line = pblk_line_get_data(pblk, rec_dev_id);
	pr_err("pblk: %s: err_line %d of dev %d -> rec_line %d of dev %d!!!!!!!!!\n",
			__func__, line->id, err_dev_id, rec_line->id, rec_dev_id);

	// alloc io buf
	//w_buf = vmalloc(LINE_LEN);
	data_buf = vmalloc(LINE_LEN);
	memset(data_buf, 0, LINE_LEN); 
	for (d = 0; d < pblk->nr_dev; d++) {
		p_data[d] = vmalloc(buf_len);
		if (!data_buf || !p_data[d]) {
			pr_err("pblk: %s: can not alloc data\n", __func__);
			ret = -ENOMEM;
			goto out;
		}
	}

	// write recov wait
	w_rec_rq = kmalloc(sizeof(struct pblk_err_w_rec_rq), GFP_KERNEL);
	if (!w_rec_rq) {
		ret = -ENOMEM;	
		goto free_buf;
	}
	w_rec_rq->pblk = pblk;
	init_completion(&w_rec_rq->wait);
	kref_init(&w_rec_rq->ref);

	// read recov wait
	r_rec_rq = kmalloc(sizeof(struct pblk_err_r_rec_rq), GFP_KERNEL);
	if (!r_rec_rq) {
		pr_err("pblk: %s: can not alloc r_rec_rq\n", __func__);
		ret = -ENOMEM;
		goto free_buf;
	}
	r_rec_rq->pblk = pblk;

	s_jiff = jiffies;
	s_addr = lm->smeta_sec;
	is_last_batch = 0;
	// read from parities
next_batch:
	init_completion(&r_rec_rq->wait);
	kref_init(&r_rec_rq->ref);

	batch_buf = data_buf+s_addr*geo->csecs;
	off = 0;
next_rq:
	jf1 = jiffies;
	e_addr = s_addr + IO_SIZE;
	if (e_addr > line->emeta_ssec)
		e_addr = line->emeta_ssec;
	nr_child_secs = e_addr - s_addr;
	//pr_info("pblk: %s: rec bad line (%llu, %llu)\n", __func__, s_addr, e_addr);;

	rec_ctx = kzalloc(sizeof(struct pblk_err_rec_ctx), GFP_KERNEL);
	if (!rec_ctx) {
		pr_err("pblk: %s: can not alloc err_rec_ctx\n",
				__func__);
		goto free_rq;
	}
	rec_ctx->err_data = batch_buf + off;
	rec_ctx->data_len = nr_child_secs * geo->csecs;
	rec_ctx->nr_child_io = group->nr_unit - 1;
	atomic_set(&rec_ctx->completion_cnt, 0);
	kref_get(&r_rec_rq->ref);

	for (u = 0; u < group->nr_unit; u++) {
		dev_id = group->line_units[u].dev_id;
		line_id = group->line_units[u].line_id;
		if (dev_id == err_dev_id)
			continue;
		/*
		pr_info("pblk: %s: prepare read from line %d dev %d\n",
				__func__, line_id, dev_id);
				*/

		rqd = pblk_alloc_rqd(pblk, PBLK_READ);

		rqd->dev = pblk->devs[dev_id];
		rqd->opcode = NVM_OP_PREAD;
		rqd->nr_ppas = nr_child_secs;
		rqd->private = r_rec_rq;
		rqd->end_io = pblk_end_io_read_rec_child;
		rqd->flags = pblk_set_read_mode(pblk, PBLK_READ_SEQUENTIAL);
		
		r_ctx = nvm_rq_to_pdu(rqd);
		r_ctx->private = rec_ctx;

		rec_ctx->data[dev_id] = p_data[dev_id];

		// fill rqd->bio
		bio = pblk_bio_map_addr(pblk, p_data[dev_id]+off, nr_child_secs, nr_child_secs*geo->csecs,
				PBLK_VMALLOC_META, GFP_KERNEL, dev_id);
		if (IS_ERR(bio)) {
			pr_err("pblk: %s: can not alloc bio of dev %d\n", __func__, dev_id);
			ret = PTR_ERR(bio);
			goto prepare_err;
		}
		bio->bi_iter.bi_sector = 0;
		bio_set_op_attrs(bio, REQ_OP_READ, 0);

		rqd->bio = bio;

		// fill rqd ppa_list
		rqd->meta_list = nvm_dev_dma_alloc(rqd->dev->parent, GFP_KERNEL,
								&rqd->dma_meta_list);
		if (!rqd->meta_list) {
			pr_err("pblk: not able to allocate ppa list\n");
			ret = -ENOMEM;
			goto prepare_err;
		}
		if (nr_child_secs > 1) {
			rqd->ppa_list = rqd->meta_list + pblk_dma_meta_size;
			rqd->dma_ppa_list = rqd->dma_meta_list + pblk_dma_meta_size;

			for (j = 0; j < nr_child_secs; j++) {
				dev_ppa = addr_to_gen_ppa(pblk, s_addr+j, line_id);
				rqd->ppa_list[j] = dev_ppa;
			}
		} else {
			rqd->ppa_addr = addr_to_gen_ppa(pblk, s_addr, line_id);
		}
		ret = pblk_submit_io(pblk, rqd, dev_id);
		/*
		pr_err("pblk: %s: read (from s_addr %llu) submission to dev %d ret %d\n",
				__func__, s_addr, dev_id, ret);
				*/
		if (ret) {
			goto submission_err;
		}
	}
	jf2 = jiffies;
	sub_r_cost += jf2 - jf1;

	s_addr = e_addr;
	off += rec_ctx->data_len;
	if (off < BATCH_SIZE * geo->csecs) {
		if(s_addr < line->emeta_ssec) {
			goto next_rq;
		}
	}

	/* ----------------------------BARRIER------------------------------- */
	kref_put(&r_rec_rq->ref, pblk_read_line_complete);
	if (!wait_for_completion_io_timeout(&r_rec_rq->wait,
				msecs_to_jiffies(PBLK_COMMAND_TIMEOUT_MS))) {
		pr_err("pblk: %s: rec read to addr %llu timeout\n", __func__, s_addr);
		ret = -ETIME;
		goto timeout;
	}
	jf3 = jiffies;
	wait_r_cost += jf3 - jf2;
	/*
	pr_info("pblk: %s: rec batch read to %llu sync\n",
			__func__, s_addr);
			*/

	// -----------------------ISSUE WRITE & READ--------------------------
	jf1 = jiffies;
	if (s_addr >= line->emeta_ssec)
		is_last_batch = 1;
	batch_sec = off / geo->csecs;
	//pr_info("pblk: %s: batch_sec %u s_addr %llu\n",
			//__func__, batch_sec, (u64)batch_buf - (u64)w_buf);

	//pr_info("pblk: %s: sleep 10s\n", __func__);
	//msleep(10000);

	spin_lock(&err_rec->w_lock);
	for (j = 0; j < batch_sec; j+=W_SIZE) {
		task = kmalloc(sizeof(struct pblk_err_rec_write_t), GFP_KERNEL);
		if (!task) {
			pr_err("pblk: %s: can not alloc write_task\n", __func__);
			ret = -ENOMEM;
			spin_unlock(&err_rec->w_lock);
			goto out;
		}
		task->line = rec_line;
		task->w_rec_rq = w_rec_rq;
		task->nr_secs = W_SIZE;
		task->data = batch_buf + j * geo->csecs;
		task->is_sync = 0;
		if (is_last_batch && j + W_SIZE >= batch_sec) 
			task->is_sync = 1;
		list_add_tail(&task->list, &err_rec->w_list);
	}
	spin_unlock(&err_rec->w_lock);
	pblk_rec_writer_kick(err_rec);
	jf2 = jiffies;
	sub_w_cost += jf2 - jf1;
	
	// next_batch
	if (s_addr < line->emeta_ssec) {
		goto next_batch;
	}
	// ----------------------------BARRIER-------------------------------
	if (!wait_for_completion_io_timeout(&w_rec_rq->wait,
				msecs_to_jiffies(PBLK_COMMAND_TIMEOUT_MS))) {
		pr_err("pblk: %s: wait for rec line write timeout\n", __func__);
		ret = -ETIME;
		goto timeout;
	}
	if (!pblk_line_is_full(rec_line)) {
		pr_err("pblk: %s: rec_line %d of dev %d not full: left %u\n",
				__func__, rec_line->id, rec_line->dev_id, rec_line->left_msecs);
		ret = -1;
	}
	pr_info("pblk: %s: rec write to line %d of dev %d sync\n",
			__func__, rec_line->id, rec_line->dev_id);

	e_jiff = jiffies;
	wait_w_cost = e_jiff - jf2;
	pr_info("pblk: recover line(read) bindwidth: %lu MB/s\n",
			(lm->sec_per_line*4)/((e_jiff-s_jiff)*1000/HZ));
	pr_info("pblk: total %lu, sub_r %lu, wait_r %lu; sub_w %lu, wait_w %lu\n",
			(e_jiff-s_jiff)*1000/HZ, (sub_r_cost*1000)/HZ,
			wait_r_cost*1000/HZ, sub_w_cost*1000/HZ, wait_w_cost*1000/HZ);

	ret = 0;
	goto free_rq;

timeout:
	pr_err("pblk: %s: err timeout\n", __func__);
submission_err:
	pr_err("pblk: %s: submission error\n", __func__);
prepare_err:
	pr_err("pblk: %s: prepare error\n", __func__);
free_rq:
	if (r_rec_rq)
		kfree(r_rec_rq);
	if (w_rec_rq)
		kfree(w_rec_rq);
free_buf:
	vfree(data_buf);
	for (d = 0; d < pblk->nr_dev; d++) {
		if (p_data[d])
			vfree(p_data[d]);
	}
out:
	kfree(rec_line_ws);
	pr_info("pblk: %s: end. line %d of dev %d ws id %llu!!!\n",
			__func__, line->id, line->dev_id, (u64)rec_line_ws->priv);
	pr_info("pblk: %s: ret %d\n", __func__, ret);
}

static int pblk_err_rec_read(struct pblk *pblk)
{
	struct pblk_err_rec *err_rec;
	struct pblk_line_ws *rec_line_ws;
	struct pblk_line *err_lines[NVM_MD_MAX_DEV_CNT];
	struct pblk_line *line, *tline;
	int nr_err_line, i;
	int ret = 0;

	pr_info("pblk: %s called\n", __func__);

	err_rec = &pblk->err_rec;

	spin_lock(&err_rec->r_lock);
	if (list_empty(&err_rec->err_line_list)) {
		spin_unlock(&err_rec->r_lock);
		return 1;
	}
	i = 0;
	list_for_each_entry_safe(line, tline, &err_rec->err_line_list, list) {
		list_del(&line->list);
		err_lines[i++] = line;
		if (i >= err_rec->nr_p_rec)
			break;
		spin_lock(&line->lock);
		if (line->state != PBLK_LINESTATE_BAD) {
			spin_unlock(&line->lock);
			pr_err("pblk: %s: line %d of %d state not BAD\n",
					__func__, line->id, line->dev_id);
			return 1;
		}
		spin_unlock(&line->lock);
	}
	nr_err_line = i;
	spin_unlock(&err_rec->r_lock);

	pr_info("pblk: %s: prepare recover %d line\n",
			__func__, nr_err_line);
	if (!nr_err_line)
		return 1;

	for (i = 0; i < nr_err_line; i++) {
		line = err_lines[i];
		pr_info("pblk: %s: found err line %d of dev %d!!!!!!!!!!!!!!!!\n",
				__func__, line->id, line->dev_id);
		rec_line_ws = kmalloc(sizeof(struct pblk_line_ws), GFP_KERNEL);
		if (!rec_line_ws) {
			pr_err("pblk: %s: can not alloc pblk_line_ws\n", __func__);
			return -1;
		}
		rec_line_ws->pblk = pblk;
		rec_line_ws->line = line;
		rec_line_ws->priv = (void *)ws_id;
		ws_id ++;

		INIT_WORK(&rec_line_ws->ws, pblk_rec_line_ws);
		queue_work(err_rec->reader_wq, &rec_line_ws->ws);
	}
	pr_info("pblk: %s: ret code %d\n", __func__, ret);
	return 1;
}

static int pblk_err_rec_write(struct pblk *pblk)
{
	struct pblk_err_rec *err_rec = &pblk->err_rec;
	struct pblk_err_rec_write_t *task, *ttask;
	LIST_HEAD(w_list);
	int ret = 0;

	//pr_info("pblk: %s: called\n", __func__);

	spin_lock(&err_rec->w_lock);
	if (list_empty(&err_rec->w_list)) {
		spin_unlock(&err_rec->w_lock);
		return 1;
	}
	list_cut_position(&w_list, &err_rec->w_list, err_rec->w_list.prev);
	spin_unlock(&err_rec->w_lock);
	
	list_for_each_entry_safe(task, ttask, &w_list, list) {
		ret = pblk_rec_submit_write(pblk, task->line, task->w_rec_rq,
				task->nr_secs, task->data);
		if (task->is_sync) {
			kref_put(&task->w_rec_rq->ref, pblk_write_line_complete);
		}
		list_del(&task->list);
		kfree(task);
		if (ret < 0) {
			pr_err("pblk: %s: submit write fail\n", __func__);
		}
	}
	return ret;
}

static int pblk_monitor_ts(void *data)
{
	struct pblk *pblk = data;
	while (!kthread_should_stop()) {
		pblk_err_monitor_run(pblk);
		//set_current_state(TASK_INTERRUPTIBLE);
		//io_schedule();
		msleep(SLEEP_MS);
	}
	return 1;
}

static int pblk_rec_r_ts(void *data)
{
	struct pblk *pblk = data;
	while (!kthread_should_stop()) {
		if(!pblk_err_rec_read(pblk))
			continue;
		set_current_state(TASK_INTERRUPTIBLE);
		io_schedule();
		//msleep(SLEEP_MS);
	}
	return 2;
}

static int pblk_rec_w_ts(void *data)
{
	struct pblk *pblk = data;
	while (!kthread_should_stop()) {
		if(!pblk_err_rec_write(pblk))
			continue;
		set_current_state(TASK_INTERRUPTIBLE);
		io_schedule();
	}
	return 3;
}

int pblk_err_rec_init(struct pblk *pblk)
{
	struct pblk_err_rec *err_rec = &pblk->err_rec;
	int ret;
	int nr_p_rec;
	
	if (!pblk_is_raid5(pblk)) {
		pr_err("pblk: %s: only raid5 supported\n", __func__);
		return -1;
	}

	nr_p_rec = pblk->nr_dev - pblk->stripe_size;
	if (nr_p_rec <= 0) {
		pr_info("pblk: %s: err_rec not supported\n", __func__);
		return -1;
	}
	err_rec->nr_p_rec = nr_p_rec;

	err_rec->monitor_ts = kthread_create(pblk_monitor_ts, pblk, "pblk-monitor-ts");
	if (IS_ERR(err_rec->monitor_ts)) {
		pr_err("pblk: could not allocate monitor kthread\n");
		return PTR_ERR(err_rec->monitor_ts);
	}

	err_rec->rec_r_ts = kthread_create(pblk_rec_r_ts, pblk, "pblk-err-recr-ts");
	if (IS_ERR(err_rec->rec_r_ts)) {
		pr_err("pblk: could not allocate reader kthread\n");
		ret = PTR_ERR(err_rec->rec_r_ts);
		goto fail_free_monitor_kthread;
	}

	err_rec->rec_w_ts = kthread_create(pblk_rec_w_ts, pblk, "pblk-err-recw-ts");
	if (IS_ERR(err_rec->rec_w_ts)) {
		pr_err("pblk: could not allocate writer kthread\n");
		ret = PTR_ERR(err_rec->rec_w_ts);
		goto fail_free_rec_r;
	}

	err_rec->reader_wq = alloc_workqueue("pblk-rec-line_wq",
					WQ_MEM_RECLAIM | WQ_UNBOUND, 2);
	if (!err_rec->reader_wq) {
		pr_err("pblk: could not allocate GC reader workqueue\n");
		ret = -ENOMEM;
		goto fail_free_rec_w;
	}
	
	spin_lock_init(&err_rec->r_lock);
	spin_lock_init(&err_rec->w_lock);
	INIT_LIST_HEAD(&err_rec->err_line_list);
	INIT_LIST_HEAD(&err_rec->w_list);

	wake_up_process(err_rec->monitor_ts);
	//wake_up_process(err_rec->rec_r_ts);
	//wake_up_process(err_rec->rec_w_ts);

	return 0;

fail_free_rec_w:
	kthread_stop(err_rec->rec_w_ts);
fail_free_rec_r:
	kthread_stop(err_rec->rec_r_ts);
fail_free_monitor_kthread:
	kthread_stop(err_rec->monitor_ts);

	return ret;
}

void pblk_err_rec_exit(struct pblk *pblk)
{
	struct pblk_err_rec *err_rec = &pblk->err_rec;
	int ret;
	if (err_rec->monitor_ts) {
		ret = kthread_stop(err_rec->monitor_ts);
		pr_info("pblk: %s: exit monitor_ts code ret: %d\n",
				__func__, ret);
	}

	if (err_rec->rec_r_ts) {
		ret = kthread_stop(err_rec->rec_r_ts);
		pr_info("pblk: %s: exit rec_r_ts code ret: %d\n",
				__func__, ret);
	}

	if (err_rec->rec_w_ts) {
		ret = kthread_stop(err_rec->rec_w_ts);
		pr_info("pblk: %s: exit rec_w_ts code ret: %d\n",
				__func__, ret);
	}
	flush_workqueue(err_rec->reader_wq);
	destroy_workqueue(err_rec->reader_wq);
}
