/*
 * fs/sdcardfs/file.c
 *
 * Copyright (c) 2013 Samsung Electronics Co. Ltd
 *   Authors: Daeho Jeong, Woojoong Lee, Seunghwan Hyun,
 *               Sunghwan Yun, Sungjong Seo
 *
 * This program has been developed as a stackable file system based on
 * the WrapFS which written by
 *
 * Copyright (c) 1998-2011 Erez Zadok
 * Copyright (c) 2009     Shrikar Archak
 * Copyright (c) 2003-2011 Stony Brook University
 * Copyright (c) 2003-2011 The Research Foundation of SUNY
 *
 * This file is dual licensed.  It may be redistributed and/or modified
 * under the terms of the Apache 2.0 License OR version 2 of the GNU
 * General Public License.
 */

#include "sdcardfs.h"
#ifdef CONFIG_SDCARD_FS_FADV_NOACTIVE
#include <linux/backing-dev.h>
#endif
#include <linux/fs.h>
#include <linux/fsnotify.h>
#include <linux/pagemap.h>
#include <linux/splice.h>

static int sdcardfs_readdir(struct file *file, struct dir_context *ctx)
{
	int err;
	struct file *lower_file = NULL;
	struct dentry *dentry = file->f_path.dentry;

	lower_file = sdcardfs_lower_file(file);

	lower_file->f_pos = file->f_pos;
	err = iterate_dir(lower_file, ctx);
	file->f_pos = lower_file->f_pos;
	if (err >= 0)		/* copy the atime */
		fsstack_copy_attr_atime(d_inode(dentry),
					file_inode(lower_file));
	return err;
}

static long sdcardfs_unlocked_ioctl(struct file *file, unsigned int cmd,
				  unsigned long arg)
{
	long err = -ENOTTY;
	struct file *lower_file;
	const struct cred *saved_cred = NULL;
	struct dentry *dentry = file->f_path.dentry;
	struct sdcardfs_sb_info *sbi = SDCARDFS_SB(dentry->d_sb);

	lower_file = sdcardfs_lower_file(file);

	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;

	/* save current_cred and override it */
	saved_cred = override_fsids(sbi, SDCARDFS_I(file_inode(file))->data);
	if (!saved_cred) {
		err = -ENOMEM;
		goto out;
	}

	if (lower_file->f_op->unlocked_ioctl)
		err = lower_file->f_op->unlocked_ioctl(lower_file, cmd, arg);

	/* some ioctls can change inode attributes (EXT2_IOC_SETFLAGS) */
	if (!err)
		sdcardfs_copy_and_fix_attrs(file_inode(file),
				      file_inode(lower_file));
	revert_fsids(saved_cred);
out:
	return err;
}

#ifdef CONFIG_COMPAT
static long sdcardfs_compat_ioctl(struct file *file, unsigned int cmd,
				unsigned long arg)
{
	long err = -ENOTTY;
	struct file *lower_file;
	const struct cred *saved_cred = NULL;
	struct dentry *dentry = file->f_path.dentry;
	struct sdcardfs_sb_info *sbi = SDCARDFS_SB(dentry->d_sb);

	lower_file = sdcardfs_lower_file(file);

	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;

	/* save current_cred and override it */
	saved_cred = override_fsids(sbi, SDCARDFS_I(file_inode(file))->data);
	if (!saved_cred) {
		err = -ENOMEM;
		goto out;
	}

	if (lower_file->f_op->compat_ioctl)
		err = lower_file->f_op->compat_ioctl(lower_file, cmd, arg);

	revert_fsids(saved_cred);
out:
	return err;
}
#endif

static int sdcardfs_mmap(struct file *file, struct vm_area_struct *vma)
{
	int err = 0;
	const struct cred *saved_cred = NULL;
	struct file *lower_file = sdcardfs_lower_file(file);
	struct dentry *dentry = file->f_path.dentry;
	struct sdcardfs_sb_info *sbi = SDCARDFS_SB(dentry->d_sb);
	struct inode *inode = d_inode(dentry);

	if (!lower_file->f_op->mmap)
		return -ENODEV;

	if (WARN_ON(file != vma->vm_file))
		return -EIO;

	/* save current_cred and override it */
	saved_cred = override_fsids(sbi, SDCARDFS_I(inode)->data);
	if (!saved_cred)
		return -ENOMEM;

	vma_set_file(vma, lower_file);
	err = call_mmap(vma->vm_file, vma);
	revert_fsids(saved_cred);
	file_accessed(file);

	return err;
}

static int sdcardfs_open(struct inode *inode, struct file *file)
{
	int err = 0;
	struct file *lower_file = NULL;
	struct path lower_path;
	struct dentry *dentry = file->f_path.dentry;
	struct dentry *parent = dget_parent(dentry);
	struct sdcardfs_sb_info *sbi = SDCARDFS_SB(dentry->d_sb);
	const struct cred *saved_cred = NULL;

	/* don't open unhashed/deleted files */
	if (d_unhashed(dentry)) {
		err = -ENOENT;
		goto out_err;
	}

	if (!check_caller_access_to_name(d_inode(parent), &dentry->d_name)) {
		err = -EACCES;
		goto out_err;
	}

	/* save current_cred and override it */
	saved_cred = override_fsids(sbi, SDCARDFS_I(inode)->data);
	if (!saved_cred) {
		err = -ENOMEM;
		goto out_err;
	}

	file->private_data =
		kzalloc(sizeof(struct sdcardfs_file_info), GFP_KERNEL);
	if (!SDCARDFS_F(file)) {
		err = -ENOMEM;
		goto out_revert_cred;
	}

	/* open lower object and link sdcardfs's file struct to lower's */
	sdcardfs_get_lower_path(file->f_path.dentry, &lower_path);
	lower_file = dentry_open(&lower_path, file->f_flags, current_cred());
	path_put(&lower_path);
	if (IS_ERR(lower_file)) {
		err = PTR_ERR(lower_file);
		lower_file = sdcardfs_lower_file(file);
		if (lower_file) {
			sdcardfs_set_lower_file(file, NULL);
			fput(lower_file); /* fput calls dput for lower_dentry */
		}
	} else {
		sdcardfs_set_lower_file(file, lower_file);
	}

	if (err)
		kfree(SDCARDFS_F(file));
	else
		sdcardfs_copy_and_fix_attrs(inode, sdcardfs_lower_inode(inode));

out_revert_cred:
	revert_fsids(saved_cred);
out_err:
	dput(parent);
	return err;
}

static int sdcardfs_flush(struct file *file, fl_owner_t id)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = sdcardfs_lower_file(file);
	if (lower_file && lower_file->f_op && lower_file->f_op->flush) {
		filemap_write_and_wait(file->f_mapping);
		err = lower_file->f_op->flush(lower_file, id);
	}

	return err;
}

/* release all lower object references & free the file info structure */
static int sdcardfs_file_release(struct inode *inode, struct file *file)
{
	struct file *lower_file;

	lower_file = sdcardfs_lower_file(file);
	if (lower_file) {
		sdcardfs_set_lower_file(file, NULL);
		fput(lower_file);
	}

	kfree(SDCARDFS_F(file));
	return 0;
}

static int sdcardfs_fsync(struct file *file, loff_t start, loff_t end,
			int datasync)
{
	int err;
	struct file *lower_file;
	struct path lower_path;
	struct dentry *dentry = file->f_path.dentry;

	err = __generic_file_fsync(file, start, end, datasync);
	if (err)
		goto out;

	lower_file = sdcardfs_lower_file(file);
	sdcardfs_get_lower_path(dentry, &lower_path);
	err = vfs_fsync_range(lower_file, start, end, datasync);
	sdcardfs_put_lower_path(dentry, &lower_path);
out:
	return err;
}

static int sdcardfs_fasync(int fd, struct file *file, int flag)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = sdcardfs_lower_file(file);
	if (lower_file->f_op && lower_file->f_op->fasync)
		err = lower_file->f_op->fasync(fd, lower_file, flag);

	return err;
}

/*
 * Sdcardfs cannot use generic_file_llseek as ->llseek, because it would
 * only set the offset of the upper file.  So we have to implement our
 * own method to set both the upper and lower file offsets
 * consistently.
 */
static loff_t sdcardfs_file_llseek(struct file *file, loff_t offset, int whence)
{
	int err;
	struct file *lower_file;

	err = generic_file_llseek(file, offset, whence);
	if (err < 0)
		goto out;

	lower_file = sdcardfs_lower_file(file);
	err = generic_file_llseek(lower_file, offset, whence);

out:
	return err;
}

#define SDCARDFS_IOCB_MASK                                                  \
	(IOCB_APPEND | IOCB_DSYNC | IOCB_HIPRI | IOCB_NOWAIT | IOCB_SYNC)

/*
 * Sdcardfs read_iter, redirect modified iocb to lower read_iter
 */
ssize_t sdcardfs_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	int err;
	const struct cred *saved_cred = NULL;
	struct file *file = iocb->ki_filp, *lower_file;
	struct dentry *dentry = file->f_path.dentry;
	struct inode *inode = file_inode(file);
	struct sdcardfs_sb_info *sbi = SDCARDFS_SB(dentry->d_sb);


	lower_file = sdcardfs_lower_file(file);
	if (!lower_file->f_op->read_iter) {
		err = -EINVAL;
		goto out;
	}

	get_file(lower_file); /* prevent lower_file from being released */
	/* save current_cred and override it */
	saved_cred = override_fsids(sbi, SDCARDFS_I(inode)->data);
	if (!saved_cred) {
		err = -ENOMEM;
		goto out;
	}

	err = vfs_iter_read(lower_file, iter, &iocb->ki_pos,
		iocb_to_rw_flags(iocb->ki_flags, SDCARDFS_IOCB_MASK));
	fput(lower_file);
	/* update upper inode atime as needed */
	if (err >= 0 || err == -EIOCBQUEUED)
		fsstack_copy_attr_atime(file->f_path.dentry->d_inode,
					file_inode(lower_file));
	revert_fsids(saved_cred);
out:
	return err;
}

/*
 * Sdcardfs write_iter, redirect modified iocb to lower write_iter
 */
ssize_t sdcardfs_write_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	int err;
	const struct cred *saved_cred = NULL;
	struct file *file = iocb->ki_filp, *lower_file;
	struct inode *inode = file_inode(file);
	struct dentry *dentry = file->f_path.dentry;
	struct sdcardfs_sb_info *sbi = SDCARDFS_SB(dentry->d_sb);


	lower_file = sdcardfs_lower_file(file);
	if (!lower_file->f_op->write_iter) {
		err = -EINVAL;
		goto out;
	}

	get_file(lower_file); /* prevent lower_file from being released */
	file_start_write(lower_file);
	/* save current_cred and override it */
	saved_cred = override_fsids(sbi, SDCARDFS_I(inode)->data);
	if (!saved_cred) {
		err = -ENOMEM;
		goto out;
	}

	err = vfs_iter_write(lower_file, iter, &iocb->ki_pos,
		iocb_to_rw_flags(iocb->ki_flags, SDCARDFS_IOCB_MASK));
	file_end_write(lower_file);
	fput(lower_file);
	/* update upper inode times/sizes as needed */
	if (err >= 0 || err == -EIOCBQUEUED) {
		if (sizeof(loff_t) > sizeof(long))
			inode_lock(inode);
		fsstack_copy_inode_size(inode, file_inode(lower_file));
		fsstack_copy_attr_times(inode, file_inode(lower_file));
		if (sizeof(loff_t) > sizeof(long))
			inode_unlock(inode);
	}
	revert_fsids(saved_cred);
out:
	return err;
}

static ssize_t sdcardfs_splice_read(struct file *in, loff_t *ppos,
	struct pipe_inode_info *pipe, size_t len, unsigned int flags)
{
	ssize_t ret;
	const struct cred *saved_cred = NULL;
	struct file *lower_file = sdcardfs_lower_file(in);
	struct dentry *dentry = in->f_path.dentry;
	struct sdcardfs_sb_info *sbi = SDCARDFS_SB(dentry->d_sb);
	struct inode *inode = file_inode(in);

	get_file(lower_file); /* prevent lower_file from being released */
	/* save current_cred and override it */
	saved_cred = override_fsids(sbi, SDCARDFS_I(inode)->data);
	if (!saved_cred) {
		ret = -ENOMEM;
		goto out_err;
	}

	ret = vfs_splice_read(lower_file, ppos, pipe, len, flags);
	fput(lower_file);
	/* update upper inode atime as needed */
	if (ret >= 0 || ret == -EIOCBQUEUED)
		fsstack_copy_attr_atime(in->f_path.dentry->d_inode,
					file_inode(lower_file));
	revert_fsids(saved_cred);
out_err:
	return ret;
}

static ssize_t sdcardfs_splice_write(struct pipe_inode_info *pipe,
	struct file *out, loff_t *ppos, size_t len, unsigned int flags)
{
	ssize_t ret;
	const struct cred *saved_cred = NULL;
	struct file *lower_file = sdcardfs_lower_file(out);
	struct inode *inode = file_inode(out);
	struct dentry *dentry = out->f_path.dentry;
	struct sdcardfs_sb_info *sbi = SDCARDFS_SB(dentry->d_sb);


	get_file(lower_file); /* prevent lower_file from being released */
	file_start_write(lower_file);
	/* save current_cred and override it */
	saved_cred = override_fsids(sbi, SDCARDFS_I(inode)->data);
	if (!saved_cred) {
		ret = -ENOMEM;
		goto out_err;
	}

	ret = iter_file_splice_write(pipe, lower_file, ppos, len, flags);
	file_end_write(lower_file);
	fput(lower_file);

	if (ret >= 0 || ret == -EIOCBQUEUED) {
		if (sizeof(loff_t) > sizeof(long))
			inode_lock(inode);
		fsstack_copy_inode_size(inode, file_inode(lower_file));
		fsstack_copy_attr_times(inode, file_inode(lower_file));
		if (sizeof(loff_t) > sizeof(long))
			inode_unlock(inode);
	}
	revert_fsids(saved_cred);
out_err:
	return ret;
}

const struct file_operations sdcardfs_main_fops = {
	.llseek		= generic_file_llseek,
	.unlocked_ioctl	= sdcardfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= sdcardfs_compat_ioctl,
#endif
	.mmap		= sdcardfs_mmap,
	.open		= sdcardfs_open,
	.flush		= sdcardfs_flush,
	.release	= sdcardfs_file_release,
	.fsync		= sdcardfs_fsync,
	.fasync		= sdcardfs_fasync,
	.read_iter	= sdcardfs_read_iter,
	.write_iter	= sdcardfs_write_iter,
	.splice_read	= sdcardfs_splice_read,
	.splice_write	= sdcardfs_splice_write,
};

/* trimmed directory options */
const struct file_operations sdcardfs_dir_fops = {
	.llseek		= sdcardfs_file_llseek,
	.read		= generic_read_dir,
	.iterate_shared	= sdcardfs_readdir,
	.unlocked_ioctl	= sdcardfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= sdcardfs_compat_ioctl,
#endif
	.open		= sdcardfs_open,
	.release	= sdcardfs_file_release,
	.flush		= sdcardfs_flush,
	.fsync		= sdcardfs_fsync,
	.fasync		= sdcardfs_fasync,
};

MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
