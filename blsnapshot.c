#include <linux/module.h>
#include <linux/blkdev.h>
#include <linux/genhd.h>
#include <linux/kthread.h>
#include <linux/miscdevice.h>

#define COW_BLOCK_SIZE 4096
#define NUM_SEGMENTS(x, log_size) (((x) + (1<<(log_size)) - 1) >> (log_size))
#define ROUND_UP(x, chunk) ((((x) + (chunk) - 1) / (chunk)) * (chunk))
#define ROUND_DOWN(x, chunk) (((x) / (chunk)) * (chunk))
#define READ_MODE_COW_FILE 1
#define READ_MODE_BASE_DEVICE 2
#define READ_MODE_MIXED 3
#define SECTOR_SIZE 512
#define SECTORS_PER_PAGE (PAGE_SIZE / SECTOR_SIZE)
#define COW_SECTION_SIZE 4096
#define SECTORS_PER_BLOCK (COW_BLOCK_SIZE / SECTOR_SIZE)
#define SECTOR_TO_BLOCK(sect) ((sect) / SECTORS_PER_BLOCK)
#define MAX_CLONES_PER_BIO 10

struct setup_params {
	char *bdev_path; 
	char *cow_path; 
	unsigned long cow_size; 
};

struct bio_queue {
	struct bio_list bios;
	spinlock_t lock;
	wait_queue_head_t event;
};

struct bio_sector_map {
	struct bio *bio;
	sector_t sect;
	unsigned int size;
};

struct tracing_params {
	struct bio *orig_bio;
	struct snap_device *dev;
	atomic_t refs;
	struct bio_sector_map bio_sects[MAX_CLONES_PER_BIO];
};

struct cow_manager {
	struct file *filp; 
	uint64_t curr_pos; 
	unsigned int log_sect_pages; 
	unsigned long total_sects; 
	uint64_t **sects; 
};

struct snap_device {
	sector_t sd_sect_off; 
	struct gendisk *sd_gd; 
	struct request_queue *sd_queue; 
	struct block_device *sd_base_dev; 
	struct cow_manager *sd_cow;
	make_request_fn *sd_orig_mrf; 
	struct bio_queue sd_cow_bios; 
	struct task_struct *sd_cow_thread; 
	struct bio_queue sd_orig_bios; 
	struct task_struct *sd_mrf_thread; 
	atomic64_t sd_submitted_cnt; 
	atomic64_t sd_received_cnt; 
};

static long ctrl_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);
static int snap_open(struct block_device *bdev, fmode_t mode) {return 0;}
static void snap_release(struct gendisk *gd, fmode_t mode) {}

static const struct block_device_operations snap_ops = {
	.owner = THIS_MODULE,
	.open = snap_open,
	.release = snap_release,
};

static const struct file_operations snap_control_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = ctrl_ioctl,
	.compat_ioctl = ctrl_ioctl,
	.open = nonseekable_open,
	.llseek = noop_llseek,
};

static struct miscdevice snap_control_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "snapshot-ctl",
	.fops = &snap_control_fops,
};

static int major;
static struct snap_device *dev;

static void get_setup_params(const struct setup_params __user *in, char **bdev_path, char **cow_path, uint64_t *cow_size) {
	int ret;
	struct setup_params params;
	
	ret = copy_from_user(&params, in, sizeof(struct setup_params));
	*bdev_path = strndup_user(params.bdev_path, PAGE_SIZE);
	*cow_path = strndup_user(params.cow_path, PAGE_SIZE);
	*cow_size = params.cow_size;
}

static void path_get_absolute_pathname(const struct path *path, char **buf, int *len_res) {
	int  len;
	char *pathname, *page_buf, *final_buf = NULL;

	page_buf = (char *)__get_free_page(GFP_KERNEL);
	pathname = d_path(path, page_buf, PAGE_SIZE);
	len = page_buf + PAGE_SIZE - pathname;
	final_buf = kmalloc(len, GFP_KERNEL);
	strncpy(final_buf, pathname, len);
	free_page((unsigned long)page_buf);
	*buf = final_buf;
	if(len_res) *len_res = len;
}

static void file_allocate(struct file *f, uint64_t offset, uint64_t length) {
	char *page_buf = NULL;
	uint64_t i, write_count;
	char *abs_path = NULL;
	int abs_path_len;
	struct path path;
	struct inode *inode;

	path.mnt = f->f_path.mnt;
	path.dentry = f->f_path.dentry;
	path_get_absolute_pathname(&path, &abs_path, &abs_path_len);
	inode = file_inode(f);
	sb_start_write(inode->i_sb);
	f->f_op->fallocate(f, 0, offset, length);
	sb_end_write(inode->i_sb);
	page_buf = (char *)get_zeroed_page(GFP_KERNEL);
	write_count = NUM_SEGMENTS(length, PAGE_SHIFT);
	if(offset % PAGE_SIZE != 0) {
		kernel_write(f, page_buf, PAGE_SIZE - offset % PAGE_SIZE, offset);
		offset += PAGE_SIZE - (offset % PAGE_SIZE);
	}
	for(i = 0; i < write_count; i++) {
		kernel_write(f, page_buf, PAGE_SIZE, offset + PAGE_SIZE * i);
	}
	free_page((unsigned long)page_buf);
	kfree(abs_path);
}


static void cow_read_mapping(struct cow_manager *cm, uint64_t pos, uint64_t *out) {
	uint64_t sect_idx = pos;
	unsigned long sect_pos = do_div(sect_idx, COW_SECTION_SIZE);
	if(!cm->sects[sect_idx]) {
		*out = 0;
		return;
	}
	*out = cm->sects[sect_idx][sect_pos];
}

static void bio_queue_init(struct bio_queue *bq) {
	bio_list_init(&bq->bios);
	spin_lock_init(&bq->lock);
	init_waitqueue_head(&bq->event);
}

static void bio_queue_add(struct bio_queue *bq, struct bio *bio) {
	unsigned long flags;
	spin_lock_irqsave(&bq->lock, flags);
	bio_list_add(&bq->bios, bio);
	spin_unlock_irqrestore(&bq->lock, flags);
	wake_up(&bq->event);
}

static struct bio *bio_queue_dequeue(struct bio_queue *bq) {
	unsigned long flags;
	struct bio *bio;
	spin_lock_irqsave(&bq->lock, flags);
	bio = bio_list_pop(&bq->bios);
	spin_unlock_irqrestore(&bq->lock, flags);
	return bio;
}


static void tp_put(struct tracing_params *tp) {
	if(atomic_dec_and_test(&tp->refs)) {
		bio_queue_add(&tp->dev->sd_orig_bios, tp->orig_bio);
		kfree(tp);
	}
}

static inline struct inode *page_get_inode(struct page *pg) {
	if(!pg)
		return NULL;
	pg = compound_head(pg);
	if(PageAnon(pg))
		return NULL;
	if(!pg->mapping) 
		return NULL;
	return pg->mapping->host;
}

static int bio_needs_cow(struct bio *bio, struct inode *inode) {
	int iter;
	struct bio_vec *bvec;
	bio_for_each_segment(bvec, bio, iter)
		if(page_get_inode(bvec->bv_page) != inode) return 1;
	return 0;
}

static void on_bio_read_complete(struct bio *bio, int err) {
	unsigned short i;
	struct tracing_params *tp = bio->bi_private;
	struct snap_device *dev = tp->dev;

	bio_set_op_attrs(bio, REQ_OP_WRITE, 0);
	for(i = 0; i < MAX_CLONES_PER_BIO && tp->bio_sects[i].bio != NULL; i++) {
		if(bio == tp->bio_sects[i].bio) {
			bio->bi_sector = tp->bio_sects[i].sect - dev->sd_sect_off;
			bio->bi_size = tp->bio_sects[i].size;
			bio->bi_idx = 0;
			break;
		}
	}
	for(i = 0; i < bio->bi_vcnt; i++) {
		bio->bi_io_vec[i].bv_len = PAGE_SIZE;
		bio->bi_io_vec[i].bv_offset = 0;
	}
	bio->bi_private = dev;
	bio_queue_add(&dev->sd_cow_bios, bio);
	atomic64_inc(&dev->sd_received_cnt);
	tp_put(tp);
}


static int snap_read_bio_get_mode(const struct snap_device *dev, struct bio *bio, int *mode) {
	int start_mode = 0;
	int iter;
	struct bio_vec *bvec;
	unsigned int bytes;
	uint64_t mappging, curr_byte, curr_end_byte = bio->bi_sector * SECTOR_SIZE;
	bio_for_each_segment(bvec, bio, iter) {
		bytes = 0;
		while(bytes < bvec->bv_len) {
			curr_byte = curr_end_byte;
			curr_end_byte += min(COW_BLOCK_SIZE - (curr_byte % COW_BLOCK_SIZE), 
					     (uint64_t)bvec->bv_len);
			cow_read_mapping(dev->sd_cow, curr_byte / COW_BLOCK_SIZE, &mappging);
			if(!start_mode && mappging) {
				start_mode = READ_MODE_COW_FILE;
			} else if(!start_mode && !mappging) {
				start_mode = READ_MODE_BASE_DEVICE;
			} else if((start_mode == READ_MODE_COW_FILE && !mappging) || 
				  (start_mode == READ_MODE_BASE_DEVICE && mappging)) {
				*mode = READ_MODE_MIXED;
				return 0;
			}
			bytes += curr_end_byte - curr_byte;
		}
	}
	*mode = start_mode;
	return 0;
}

static void snap_handle_read_bio(const struct snap_device *dev, struct bio *bio) {
	int mode, iter;
	struct bio_vec *bvec;
	void *orig_private = bio->bi_private;
	bio_end_io_t *orig_end_io = bio->bi_end_io;
	char *data;
	uint64_t mappging, bytes_to_copy, block_off, bvec_off, bio_orig_sect = bio->bi_sector, cur_block, 
		cur_sect, bio_orig_idx = bio->bi_idx, bio_orig_size = bio->bi_size;
	
	bio->bi_bdev = dev->sd_base_dev;
	bio_set_op_attrs(bio, REQ_OP_READ, READ_SYNC);
	snap_read_bio_get_mode(dev, bio, &mode);
	if(mode != READ_MODE_COW_FILE)
		submit_bio_wait(0, bio);
	if(mode != READ_MODE_BASE_DEVICE) {
		bio->bi_idx = bio_orig_idx;
		bio->bi_size = bio_orig_size;
		bio->bi_sector = bio_orig_sect;
		cur_sect = bio->bi_sector;
		bio_for_each_segment(bvec, bio, iter) {
			data = kmap(bvec->bv_page);
			cur_block = cur_sect * SECTOR_SIZE / COW_BLOCK_SIZE;
			block_off = cur_sect * SECTOR_SIZE % COW_BLOCK_SIZE;
			bvec_off = bvec->bv_offset;
			while(bvec_off < bvec->bv_offset + bvec->bv_len) {
				bytes_to_copy = min(bvec->bv_offset + bvec->bv_len - bvec_off, 
										COW_BLOCK_SIZE - block_off);
				cow_read_mapping(dev->sd_cow, cur_block, &mappging);
				if(mappging) 
					kernel_read(dev->sd_cow->filp, mappging * COW_BLOCK_SIZE
						  + block_off, data + bvec_off, bytes_to_copy);
				cur_sect += bytes_to_copy / SECTOR_SIZE;
				cur_block = cur_sect * SECTOR_SIZE / COW_BLOCK_SIZE;
				block_off = cur_sect * SECTOR_SIZE % COW_BLOCK_SIZE;
				bvec_off += bytes_to_copy;
			}
			kunmap(bvec->bv_page);
		}
	}
	bio->bi_private = orig_private;
	bio->bi_end_io = orig_end_io;
	bio_endio(bio, 0);
}

static int snap_handle_write_bio(const struct snap_device *dev, struct bio *bio) {
	int iter, sect_pos, i;
	struct bio_vec *bvec;
	uint64_t block, group, mappging;
	
	bio_for_each_segment(bvec, bio, iter) {
		block = SECTOR_TO_BLOCK(bio->bi_sector) + iter;
		cow_read_mapping(dev->sd_cow, block, &mappging);
		if(mappging) 
			continue;
		group = block / COW_SECTION_SIZE;
		sect_pos = block % COW_SECTION_SIZE;
		if(!dev->sd_cow->sects[group]) 
			dev->sd_cow->sects[group] = (void*) __get_free_pages(GFP_KERNEL | __GFP_ZERO, 
									     dev->sd_cow->log_sect_pages);
		dev->sd_cow->sects[group][sect_pos] = dev->sd_cow->curr_pos;
		kernel_write(dev->sd_cow->filp, kmap(bvec->bv_page), COW_BLOCK_SIZE, 
							dev->sd_cow->curr_pos * COW_BLOCK_SIZE);
		dev->sd_cow->curr_pos++;
		kunmap(bvec->bv_page);
	}
	for(i = 0; i < bio->bi_vcnt; i++)
		if(bio->bi_io_vec[i].bv_page)
			__free_page(bio->bi_io_vec[i].bv_page);
	bio_put(bio);
	return 0;
}

static int snap_mrf_thread(void *data) {
	struct bio_queue *bq = &dev->sd_orig_bios;

	while(!kthread_should_stop() || !bio_list_empty(&bq->bios)) {
		wait_event_interruptible(bq->event, kthread_should_stop() || !bio_list_empty(&bq->bios));
		if(bio_list_empty(&bq->bios))
			continue;
		dev->sd_orig_mrf(bdev_get_queue(dev->sd_base_dev), bio_queue_dequeue(bq));
	}
	return 0;
}

static int snap_cow_thread(void *data) {
	struct bio_queue *bq = &dev->sd_cow_bios;
	struct bio *bio;
	
	while(!kthread_should_stop() || !bio_list_empty(&bq->bios) || 
	      atomic64_read(&dev->sd_submitted_cnt) != atomic64_read(&dev->sd_received_cnt)) {
		wait_event_interruptible(bq->event, kthread_should_stop() || !bio_list_empty(&bq->bios));
		if(bio_list_empty(&bq->bios))
			continue;
		bio = bio_queue_dequeue(bq);
		if(bio_data_dir(bio)) 
			snap_handle_write_bio(dev, bio);
		else
			snap_handle_read_bio(dev, bio);
	}
	return 0;
}

static int bio_make_read_clone(struct tracing_params *tp, struct bio *orig_bio, sector_t sect, 
			       unsigned int pages, struct bio **bio_out, unsigned int *bytes_added) {
	struct bio *new_bio;
	struct page *pg;
	unsigned int i, bytes, total = 0, actual_pages = pages > BIO_MAX_PAGES ? BIO_MAX_PAGES : pages;
	
	new_bio = bio_alloc(GFP_NOIO, actual_pages);
	atomic_inc(&tp->refs);
	new_bio->bi_private = tp;
	new_bio->bi_end_io = on_bio_read_complete;
	new_bio->bi_bdev = orig_bio->bi_bdev;
	new_bio->bi_sector = sect;
	new_bio->bi_idx = 0;
	bio_set_op_attrs(new_bio, REQ_OP_READ, 0);

	for(i = 0; i < actual_pages; i++) {
		pg = alloc_page(GFP_NOIO);
		bytes = bio_add_page(new_bio, pg, PAGE_SIZE, 0);
		if(bytes != PAGE_SIZE) { 
			__free_page(pg);
			break;
		}
		total += bytes;
	}
	*bytes_added = total;
	*bio_out = new_bio;
	return 0;
}

static void tracing_mrf(struct request_queue *q, struct bio *bio) {
	struct bio *new_bio = NULL;
	struct tracing_params *tp = NULL;
	sector_t start_sect, end_sect;
	unsigned int bytes, pages, i = 0;

	if(bio_data_dir(bio) && bio->bi_size) {
		if(!bio_needs_cow(bio, dev->sd_cow->filp->f_path.dentry->d_inode)) {
			dev->sd_orig_mrf(bdev_get_queue(bio->bi_bdev), bio);
			return;
		}
		start_sect = ROUND_DOWN(bio->bi_sector - dev->sd_sect_off, SECTORS_PER_BLOCK) + dev->sd_sect_off;
		end_sect = ROUND_UP(bio->bi_sector + (bio->bi_size / SECTOR_SIZE) - dev->sd_sect_off, 
				    SECTORS_PER_BLOCK) + dev->sd_sect_off;
		pages = (end_sect - start_sect) / SECTORS_PER_PAGE;
		tp = kzalloc(1 * sizeof(struct tracing_params), GFP_NOIO);
		tp->dev = dev;
		tp->orig_bio = bio;
		atomic_set(&tp->refs, 1);
	
	retry:
		bio_make_read_clone(tp, bio, start_sect, pages, &new_bio, &bytes);
		tp->bio_sects[i].bio = new_bio;
		tp->bio_sects[i].sect = new_bio->bi_sector;
		tp->bio_sects[i].size = new_bio->bi_size;
		atomic64_inc(&dev->sd_submitted_cnt);
		submit_bio(0, new_bio);
		if(bytes / PAGE_SIZE < pages) {
			start_sect += bytes / SECTOR_SIZE;
			pages -= bytes / PAGE_SIZE;
			i++;
			goto retry;
		}
		tp_put(tp);
	} else {
		dev->sd_orig_mrf(q, bio);
	}
}

static void snap_mrf(struct request_queue *q, struct bio *bio) {
	bio_queue_add(&dev->sd_cow_bios, bio);
}

static void set_mrf(make_request_fn *mrf) {
	freeze_bdev(dev->sd_base_dev);
	dev->sd_base_dev->bd_disk->queue->make_request_fn = mrf;
	thaw_bdev(dev->sd_base_dev, dev->sd_base_dev->bd_super);
}

static long ctrl_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
	char *bdev_path, *cow_path;
	unsigned int minor = 0;
	uint64_t sd_size, cow_size;

	get_setup_params((struct setup_params __user *)arg, &bdev_path, &cow_path, &cow_size);
	dev = kzalloc(sizeof(struct snap_device), GFP_KERNEL);
	bio_queue_init(&dev->sd_cow_bios);
	bio_queue_init(&dev->sd_orig_bios);
	dev->sd_base_dev = blkdev_get_by_path(bdev_path, FMODE_READ, NULL);
	if(dev->sd_base_dev->bd_contains != dev->sd_base_dev) { 
		dev->sd_sect_off = dev->sd_base_dev->bd_part->start_sect;
		sd_size = dev->sd_base_dev->bd_part->nr_sects;
	} else {
		dev->sd_sect_off = 0;
		sd_size = get_capacity(dev->sd_base_dev->bd_disk);
	}
	dev->sd_cow = kzalloc(sizeof(struct cow_manager), GFP_KERNEL);
	dev->sd_cow->filp = filp_open(cow_path, O_CREAT | O_TRUNC | O_RDWR | O_LARGEFILE, 0);
	dev->sd_cow->log_sect_pages = get_order(COW_SECTION_SIZE * 8);
	dev->sd_cow->total_sects = NUM_SEGMENTS(SECTOR_TO_BLOCK(sd_size), 
						dev->sd_cow->log_sect_pages + PAGE_SHIFT - 3);
	dev->sd_cow->curr_pos = dev->sd_cow->total_sects * COW_SECTION_SIZE * 8 / COW_BLOCK_SIZE;
	dev->sd_cow->sects = kzalloc(dev->sd_cow->total_sects * sizeof(void*), GFP_KERNEL);
	file_allocate(dev->sd_cow->filp, 0, cow_size * 1024 * 1024); 
	dev->sd_queue = blk_alloc_queue(GFP_KERNEL); 
	blk_queue_make_request(dev->sd_queue, snap_mrf);
	blk_set_stacking_limits(&dev->sd_queue->limits);
	bdev_stack_limits(&(dev->sd_queue)->limits, dev->sd_base_dev, 0);

	dev->sd_gd = alloc_disk(1);
	dev->sd_queue->queuedata = dev;
	dev->sd_gd->private_data = dev;
	dev->sd_gd->major = major;
	dev->sd_gd->first_minor = minor;
	dev->sd_gd->fops = &snap_ops;
	dev->sd_gd->queue = dev->sd_queue; 
	snprintf(dev->sd_gd->disk_name, 32, "snapshot%d", minor);
	set_capacity(dev->sd_gd, sd_size);
	set_disk_ro(dev->sd_gd, 1);
	add_disk(dev->sd_gd);

	dev->sd_mrf_thread = kthread_run(snap_mrf_thread, dev, "snapshot_snap_mrf%d", minor);
	atomic64_set(&dev->sd_submitted_cnt, 0);
	atomic64_set(&dev->sd_received_cnt, 0);
	dev->sd_cow_thread = kthread_run(snap_cow_thread, dev, "snapshot_snap_cow%d", minor);
	dev->sd_orig_mrf = bdev_get_queue(dev->sd_base_dev)->make_request_fn;
	set_mrf(tracing_mrf);
	return 0;
}

static void agent_exit(void) {
	unsigned long i;

	misc_deregister(&snap_control_device);
	if(dev) {
		set_mrf(dev->sd_orig_mrf);
		kthread_stop(dev->sd_cow_thread);
		kthread_stop(dev->sd_mrf_thread);
		if(dev->sd_gd->flags & GENHD_FL_UP)
			del_gendisk(dev->sd_gd);
		put_disk(dev->sd_gd);
		blk_cleanup_queue(dev->sd_queue);
		for(i = 0; i < dev->sd_cow->total_sects; i++)
			if(dev->sd_cow->sects[i])
				free_pages((unsigned long)dev->sd_cow->sects[i], dev->sd_cow->log_sect_pages);
		kfree(dev->sd_cow->sects);

		{ 
			struct inode *dir_inode = dev->sd_cow->filp->f_path.dentry->d_parent->d_inode;
			struct dentry *file_dentry = dev->sd_cow->filp->f_path.dentry;
			dget(file_dentry);
			igrab(dir_inode);
			vfs_unlink(dir_inode, file_dentry, NULL);
			filp_close(dev->sd_cow->filp, NULL);;
			iput(dir_inode);
			dput(file_dentry);
		}

		kfree(dev->sd_cow);
		blkdev_put(dev->sd_base_dev, FMODE_READ);
	}
	kfree(dev);
	unregister_blkdev(major, "snapshot");
}
module_exit(agent_exit);

static int __init agent_init(void) {
	major = register_blkdev(0, "snapshot");
	misc_register(&snap_control_device);
	return 0;
}
module_init(agent_init);

MODULE_LICENSE("GPL");

