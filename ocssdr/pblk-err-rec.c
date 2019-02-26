/*
 *
 */

#include "pblk.h"
//#include <linux/delay.h>

#define SLEEP_MS (2000)


// ret: lines of err injected
int inject_line_err(struct pblk *pblk)
{
	struct pblk_line_mgmt *l_mg;
	struct pblk_line *line;
	struct pblk_err_rec *err_rec;
	int err_devs[] = {0, 1};
	int err_lines[] = {9, 9};
	int err_dev_id = err_devs[0];
	int err_line_id = err_lines[0];

	//pr_info("pblk: %s: do nothing now\n", __func__);
	err_rec = &pblk->err_rec;
	line = &pblk->lines[err_dev_id][err_line_id];

	spin_lock(&line->lock);
	if (line->state == PBLK_LINESTATE_CLOSED) {
		line->state = PBLK_LINESTATE_BAD;
		list_del(&line->list);
		list_add_tail(&line->list, &err_rec->err_line_list);
		spin_unlock(&line->lock);
		return 1;
	}
	spin_unlock(&line->lock);
	return 0;
}

static int pblk_err_monitor_run(struct pblk *pblk)
{
	struct pblk_line_mgmt *l_mg;
	struct pblk_line *line;
	struct pblk_err_rec *err_rec;
	int i, nr_p_rec, nr_line;
	int ret;

	//pr_info("pblk: %s called\n", __func__);

	err_rec = &pblk->err_rec;
	spin_lock(&err_rec->lock);
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
	spin_unlock(&err_rec->lock);
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

		pr_info("pblk: %s: line %d of dev %d: smeta_len %d, smeta_sec %llu, emeta_len %d, emeta_ssec %llu\n",
				__func__, line_id, dev_id, lm->smeta_sec, line->smeta_ssec, lm->emeta_sec[0], line->emeta_ssec);

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
	struct pblk_err_rec_rq *rec_rq = container_of(ref, struct pblk_err_rec_rq, ref);
	
	complete(&rec_rq->wait);
}

void __pblk_end_io_read_rec_md(struct pblk_err_rec_rq *rec_rq, struct pblk_err_rec_ctx *rec_ctx)
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
		memset(rec_ctx->err_data, 0, data_len);
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
		kref_put(&rec_rq->ref, pblk_read_line_complete);
		return;
	}
}

void pblk_end_io_read_rec_child(struct nvm_rq *rqd)
{
	struct pblk_err_rec_rq *rec_rq= rqd->private;
	struct pblk *pblk = rec_rq->pblk;
	struct nvm_tgt_dev *dev = rqd->dev;
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
	

	__pblk_end_io_read_rec_md(rec_rq, (struct pblk_err_rec_ctx *)r_ctx->private);

	//bio_put(rqd->bio);
	pblk_free_rqd(pblk, rqd, PBLK_READ);
	atomic_dec(&pblk->inflight_io);
}

static int pblk_err_rec_start(struct pblk *pblk, struct pblk_line **err_lines,
		int nr_err_line)
{
	struct pblk_line_meta *lm = &pblk->lm;
	struct nvm_tgt_dev *dev = pblk->devs[DEFAULT_DEV_ID];
	struct nvm_geo *geo = &dev->geo;
	struct pblk_md_line_group_set *set = &pblk->md_line_group_set;
	struct pblk_md_line_group *group;
	struct pblk_err_rec *err_rec;
	struct pblk_line *line;
	struct nvm_rq *rqd;
	struct pblk_g_ctx *r_ctx;

	struct pblk_err_rec_rq *rec_rq;
	struct pblk_err_rec_ctx *rec_ctx;
	struct bio *bio;

	void *err_data;
	void *p_data[NVM_MD_MAX_DEV_CNT]; // parity
	
	unsigned long s_jiff, e_jiff;
	unsigned long long off;

	unsigned int nr_child_secs;
	struct ppa_addr dev_ppa;
	u64 paddr, s_addr, e_addr;
	int dev_id, err_dev_id;
	int gid, line_id;
	int i, d, u, j;
	int ret;
	
	unsigned long batch_size = PBLK_MAX_REQ_ADDRS;
	size_t buf_len = (unsigned long long)geo->csecs * lm->sec_per_line;
	err_rec = &pblk->err_rec;

	for (i = 0; i < nr_err_line; i++) {
		pr_info("pblk: %s: err_line info: %d of dev %d\n",
				__func__, err_lines[i]->id, err_lines[i]->dev_id);
	}
	pr_info("pblk: %s: called, sleep for 8s!!!!!!!!!!!!!!!!!!!!\n",__func__);
	msleep(8000);

	for (i = 0; i < nr_err_line; i++) {
		s_jiff = jiffies;
		line = err_lines[i];
		pr_info("pblk: %s: begin recover err line %d g_seq_nr %d of dev %d\n",
				__func__, line->id, line->dev_id, line->g_seq_nr);

		err_dev_id = line->dev_id;
		gid = line->g_seq_nr;
		group = &set->line_groups[gid];
		if (pblk_err_group_check(pblk, gid)) 
			return -1;
		pr_info("pblk: %s: err line %d g_seq_nr %d of dev %d PASS group check\n",
				__func__, line->id, line->dev_id, line->g_seq_nr);

		for (d = 0; d < pblk->nr_dev; d++) {
			p_data[d] = vmalloc(buf_len);
			if (!p_data[d]) {
				pr_err("pblk: %s: can not alloc data\n", __func__);
				ret = -ENOMEM;
				return ret;
			}
		}
		err_data = p_data[err_dev_id];

		rec_rq = kmalloc(sizeof(struct pblk_err_rec_rq), GFP_KERNEL);
		if (!rec_rq) {
			pr_err("pblk: %s: can not alloc rec_rq\n", __func__);
			goto buf_err;
		}
		rec_rq->pblk = pblk;
		init_completion(&rec_rq->wait);
		kref_init(&rec_rq->ref);

		off = 0;
		s_addr = lm->smeta_sec;
next_rq:
		e_addr = s_addr + batch_size;
		if (e_addr > line->emeta_ssec)
			e_addr = line->emeta_ssec;
		nr_child_secs = e_addr - s_addr;

		rec_ctx = kzalloc(sizeof(struct pblk_err_rec_ctx), GFP_KERNEL);
		if (!rec_ctx) {
			pr_err("pblk: %s: can not alloc err_rec_ctx\n",
					__func__);
			goto rq_err;
		}
		rec_ctx->err_data = err_data + off;
		rec_ctx->data_len = nr_child_secs * geo->csecs;
		rec_ctx->nr_child_io = group->nr_unit - 1;
		atomic_set(&rec_ctx->completion_cnt, 0);
		kref_get(&rec_rq->ref);

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
			rqd->private = rec_rq;
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

		s_addr = e_addr;
		if(s_addr < line->emeta_ssec)  {
			goto next_rq;
			off += rec_ctx->data_len;
		}

		kref_put(&rec_rq->ref, pblk_read_line_complete);

		if (!wait_for_completion_io_timeout(&rec_rq->wait,
					msecs_to_jiffies(PBLK_COMMAND_TIMEOUT_MS))) {
			pr_err("pblk: %s: rec read from s_addr %llu timeout\n", __func__, s_addr);
			goto timeout;
		}

		e_jiff = jiffies;
		pr_info("pblk: recover line(read) bindwidth: %llu MB/s\n",
				((line->emeta_ssec-lm->smeta_sec)*4)/((e_jiff-s_jiff)*1000/HZ));

		kfree(rec_rq);
		for (i = 0; i < pblk->nr_dev; i++) {
			if (p_data[i])
				vfree(p_data[i]);
		}
		return 0;

timeout:
		pr_err("pblk: %s: err timeout\n", __func__);
prepare_err:
		pr_err("pblk: %s: prepare error\n", __func__);
rq_err:
		kfree(rec_rq);
buf_err:
		for (i = 0; i < pblk->nr_dev; i++) {
			if (p_data[i])
				vfree(p_data[i]);
		}
submission_err:
		pr_err("pblk: %s: submission error\n", __func__);
		return -1;
	}
}

static void pblk_err_rec_run(struct pblk *pblk)
{
	struct pblk_err_rec *err_rec;
	struct pblk_line *err_lines[NVM_MD_MAX_DEV_CNT];
	struct pblk_line *line, *tline;
	int nr_err_line, i;
	int ret = 0;

	//pr_info("pblk: %s called\n", __func__);

	err_rec = &pblk->err_rec;

	spin_lock(&err_rec->lock);
	if (list_empty(&err_rec->err_line_list)) {
		spin_unlock(&err_rec->lock);
		return;
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
			return;
		}
		spin_unlock(&line->lock);
	}
	nr_err_line = i;
	spin_unlock(&err_rec->lock);

	pr_info("pblk: %s: prepare recover %d line\n",
			__func__, nr_err_line);
	if (!nr_err_line)
		return;
	
	ret = pblk_err_rec_start(pblk, err_lines, nr_err_line);
	pr_info("pblk: %s: ret code %d\n", __func__, ret);
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

static int pblk_err_rec_ts(void *data)
{
	struct pblk *pblk = data;
	while (!kthread_should_stop()) {
		pblk_err_rec_run(pblk);
		//set_current_state(TASK_INTERRUPTIBLE);
		//schedule();
		msleep(SLEEP_MS);
	}
	return 2;
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
		pr_err("pblk: could not allocate GC main kthread\n");
		return PTR_ERR(err_rec->monitor_ts);
	}

	err_rec->err_rec_ts = kthread_create(pblk_err_rec_ts, pblk, "pblk-err-rec-ts");
	if (IS_ERR(err_rec->err_rec_ts)) {
		pr_err("pblk: could not allocate GC writer kthread\n");
		ret = PTR_ERR(err_rec->err_rec_ts);
		goto fail_free_monitor_kthread;
	}

	spin_lock_init(&err_rec->lock);
	INIT_LIST_HEAD(&err_rec->err_line_list);

	wake_up_process(err_rec->monitor_ts);
	wake_up_process(err_rec->err_rec_ts);

	return 0;

fail_free_rec_kthread:
	kthread_stop(err_rec->err_rec_ts);
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

	if (err_rec->err_rec_ts) {
		ret = kthread_stop(err_rec->err_rec_ts);
		pr_info("pblk: %s: exit err_rec_ts code ret: %d\n",
				__func__, ret);
	}
}
