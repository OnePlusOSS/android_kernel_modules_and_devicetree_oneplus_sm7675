/************************************************************************************
 **OPLUS Mobile Comm Corp
 ** File: - kernel-4.4\drivers\soc\oplus\oplus_custom\oplus_custom.c
 ** OPLUS_BUG_STABILITY
 ** Copyright (C), 2008-2017, OPLUS Mobile Comm Corp., Ltd
 **
 ** Description:
 **      oplus_custom.c (sw23)
 **
 ** Version: 1.0
 ** Date created: 18:03:11,07/02/2017
 ** TAG: BSP.bootloader.bootflow
 ** --------------------------- Revision History: --------------------------------
 **  <author>      <data>            <desc>
 **  Bin.Li       2017/05/25        create the file
 **  Bin.Li       2017/05/27        Add for 6763 oplus_custom path
 ************************************************************************************/
#include <linux/sched.h>
#include <asm/uaccess.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/of.h>
#include <linux/slab.h>
#include <linux/blkdev.h>
#include <linux/sysfs.h>
#include <linux/syscalls.h>
#include <linux/unistd.h>

#include "oplus_custom.h"

#define OPLUSCUSTOM_FILE "/dev/block/by-name/oplus_custom"

#define OPLUSCUSTOM_SYNC_TIME 1000
#define RETRY_COUNT_FOR_GET_DEVICE 50
#define WAITING_FOR_GET_DEVICE     100


struct opluscustom_data{
	struct delayed_work 		sync_work;
	/* struct mutex 				wr_lock; */
	int 						change_flag;
	int 						inited;
	unsigned int				trytime;
	struct proc_dir_entry 		*proc_oplusCustom;
	TOplusCustConfigInf 			ConfigInf;
};

static struct opluscustom_data *gdata = NULL;

struct block_device *get_opluscustom_partition_bdev(void)
{
	struct block_device *bdev = NULL;
	int retry_wait_for_device = RETRY_COUNT_FOR_GET_DEVICE;
	dev_t dev;

	while(retry_wait_for_device--) {
		if (lookup_bdev(OPLUSCUSTOM_FILE, &dev)) {
			printk("failed to get oplus_custom bdev!\n");
			return NULL;
		}
		if(dev != 0) {
			bdev = blkdev_get_by_dev(dev, BLK_OPEN_READ | BLK_OPEN_WRITE | BLK_OPEN_EXCL, THIS_MODULE, NULL);
			if (!IS_ERR(bdev)) {
				printk("success to get dev block\n");
				return bdev;
			}
		}
		printk("Failed to get dev block, retry %d\n", retry_wait_for_device);
		msleep_interruptible(WAITING_FOR_GET_DEVICE);
	}
	printk("Failed to get dev block final\n");
	return NULL;
}

static int opluscustom_read(struct opluscustom_data *data)
{
	TOplusCustConfigInf *pConfigInf = &data->ConfigInf;
	struct block_device *bdev = NULL;
	struct file dev_map_file;
	struct kiocb kiocb;
	struct iov_iter iter;
	struct kvec iov;
	int read_size = 0;
	int ret = 0;

	bdev = get_opluscustom_partition_bdev();
	if (!bdev) {
		printk(" %s: bdev get failed\n", __func__);
		return -1;
	}

	memset(&dev_map_file, 0, sizeof(struct file));

	dev_map_file.f_mapping = bdev->bd_inode->i_mapping;
	dev_map_file.f_flags = O_DSYNC | __O_SYNC | O_NOATIME;
	dev_map_file.f_inode = bdev->bd_inode;

	init_sync_kiocb(&kiocb, &dev_map_file);
	kiocb.ki_pos = 0; /* start header offset */
	iov.iov_base = (void *)pConfigInf;
	iov.iov_len = sizeof(*pConfigInf);
	iov_iter_kvec(&iter, READ, &iov, 1, sizeof(*pConfigInf));

	read_size = generic_file_read_iter(&kiocb, &iter);
	printk("read_size %d\n", read_size);
	/* filp_close(&dev_map_file, NULL); */

	if (read_size <= 0) {
		printk("read failed\n");
		ret = -1;
		goto do_blkdev_put;
	}

	if(D_OPLUS_CUST_PART_MAGIC_NUM != pConfigInf->nmagicnum1) {
		printk("opluscustom_read OPLUS_CUSTOM partition is illegal nmagicnum1:0x%x!\n", pConfigInf->nmagicnum1);
	}
	if(D_OPLUS_CUST_PART_CONFIG_MAGIC_NUM != pConfigInf->nmagicnum2) {
		printk("opluscustom_read OPLUS_CUSTOM partition with error config magic number nmagicnum2:0x%x!\n", pConfigInf->nmagicnum2);
	}

do_blkdev_put:
	if (bdev) {
		blkdev_put(bdev, THIS_MODULE);
		bdev = NULL;
		printk("Put device\n");
	}

	return ret;
}

static int blkdev_fsync(struct file *filp, loff_t start, loff_t end,
		int datasync)
{
	struct inode *bd_inode = filp->f_mapping->host;
	struct block_device *bdev = I_BDEV(bd_inode);
	int error;

	error = file_write_and_wait_range(filp, start, end);
	if (error)
		return error;

	/*
	 * There is no need to serialise calls to blkdev_issue_flush with
	 * i_mutex and doing so causes performance issues with concurrent
	 * O_SYNC writers to a block device.
	 */
	error = blkdev_issue_flush(bdev);
	if (error == -EOPNOTSUPP)
		error = 0;

	return error;
}

static int opluscustom_write(struct opluscustom_data *data)
{
	TOplusCustConfigInf *pConfigInf = &data->ConfigInf;
	struct block_device *bdev = NULL;
	struct file dev_map_file;
	struct kiocb kiocb;
	struct iov_iter iter;
	struct kvec iov;
	const struct file_operations f_op = {.fsync = blkdev_fsync};
	int ret = 0;

	if(D_OPLUS_CUST_PART_MAGIC_NUM != pConfigInf->nmagicnum1) {
		printk("opluscustom_write magic num is illegal nmagicnum1:0x%x!\n", pConfigInf->nmagicnum1);
	}
	if(D_OPLUS_CUST_PART_CONFIG_MAGIC_NUM != pConfigInf->nmagicnum2) {
		printk("opluscustom_write magic num is illegal nmagicnum2:0x%x!\n", pConfigInf->nmagicnum2);
	}

	bdev = get_opluscustom_partition_bdev();
	if (!bdev) {
		printk(" %s: bdev get failed\n", __func__);
		return 0;
	}

	memset(&dev_map_file, 0, sizeof(struct file));

	dev_map_file.f_mapping = bdev->bd_inode->i_mapping;
	dev_map_file.f_flags = O_DSYNC | __O_SYNC | O_NOATIME;
	dev_map_file.f_inode = bdev->bd_inode;

	init_sync_kiocb(&kiocb, &dev_map_file);
	kiocb.ki_pos = 0; /* start header offset */
	iov.iov_base = (void *)pConfigInf;
	iov.iov_len = sizeof(*pConfigInf);
	iov_iter_kvec(&iter, WRITE, &iov, 1, sizeof(*pConfigInf));

	ret = generic_write_checks(&kiocb, &iter);
	if (ret > 0)
		ret = generic_perform_write(&kiocb, &iter);

	if (ret > 0) {
		dev_map_file.f_op = &f_op;
		kiocb.ki_pos += ret;
		ret = generic_write_sync(&kiocb, ret);
		if (ret < 0) {
		/* filp_close(&dev_map_file, NULL); */
			printk("Write sync failed\n");
		}
	}
	/* filp_close(&dev_map_file, NULL); */

	if (bdev) {
		blkdev_put(bdev, THIS_MODULE);
		bdev = NULL;
		printk("Put device\n");
	}

	return ret;
}

static void oplus_custome_sync_work(struct work_struct *work)
{
	int change_flag_old = 0;
	int rc = 0;
	struct delayed_work *dwork = to_delayed_work(work);
	struct opluscustom_data *data =
		container_of(dwork, struct opluscustom_data, sync_work);

	printk("oplus_custome_sync_work is called\n");
	if(!data->inited) {
		if(data->trytime > 100) {
			printk("oplus_custome_sync_work:timeout trytime = %d\n", data->trytime);
			return;
		}

		rc = opluscustom_read(data);
		printk("oplus_custome_sync_work:rc = %d\n", rc);
		if(rc == 0) {
			data->inited = 1;
		}
		else {
			data->trytime++;
			schedule_delayed_work(&data->sync_work, msecs_to_jiffies(OPLUSCUSTOM_SYNC_TIME));
			return;
		}
	}
	if(data->change_flag > 0) {
		change_flag_old = data->change_flag;
		opluscustom_write(data); /* sync back */
		data->change_flag -= change_flag_old;
		if(data->change_flag < 0) {
			printk("oplus_custome_sync_work erro data->change_flag can not < 0 \n");
		}
	}
	if(data->change_flag > 0)
		schedule_delayed_work(&data->sync_work, msecs_to_jiffies(OPLUSCUSTOM_SYNC_TIME));
}

static int opluscustom_sync_init(void)
{
	int rc = -1;
	struct opluscustom_data *data = NULL;

	if(gdata) {
		printk("%s:just can be call one time\n", __func__);
		return 0;
	}

	data = kzalloc(sizeof(struct opluscustom_data), GFP_KERNEL);
	if(data == NULL) {
		rc = -ENOMEM;
		printk("%s:kzalloc fail %d\n", __func__, rc);
		return rc;
	}
	/* mutex_init(&data->wr_lock); */
	INIT_DELAYED_WORK(&data->sync_work, oplus_custome_sync_work);
	gdata = data;
	schedule_delayed_work(&data->sync_work, msecs_to_jiffies(OPLUSCUSTOM_SYNC_TIME));
	return 0;
}

static ssize_t nPlUsbEnumEnabled_read_proc(struct file *file, char __user *buf,
		size_t count, loff_t *off)
{
	char page[256] = {0};
	int len = 0;

	if(!gdata) {
		return -ENOMEM;
	}

	if(!gdata->inited) {
		return -ENOENT;
	}

	len = sprintf(page, "%d", gdata->ConfigInf.nplusbenumenabled);

	if(len > *off)
		len -= *off;
	else
		len = 0;

	if(copy_to_user(buf, page, (len < count ? len : count))) {
		return -EFAULT;
	}
	*off += len < count ? len : count;
	return (len < count ? len : count);
}

static ssize_t nPlUsbEnumEnabled_write_proc(struct file *file, const char __user *buf,
		size_t count, loff_t *off)

{
	char page[256] = {0};
	unsigned int input = 0;

	if(!gdata) {
		return -ENOMEM;
	}

	if(!gdata->inited) {
		return -ENOENT;
	}

	if (count > 256)
		count = 256;
	if(count > *off)
		count -= *off;
	else
		count = 0;

	if (copy_from_user(page, buf, count))
		return -EFAULT;
	*off += count;

	if (sscanf(page, "%u", &input) != 1) {
		count = -EINVAL;
		return count;
	}

	if(input != gdata->ConfigInf.nplusbenumenabled) {
		gdata->ConfigInf.nplusbenumenabled = input;
		gdata->change_flag++;
		if(gdata->change_flag == 1) {
			schedule_delayed_work(&gdata->sync_work, msecs_to_jiffies(OPLUSCUSTOM_SYNC_TIME));
		}
	}

	return count;
}

static struct proc_ops nPlUsbEnumEnabled_proc_fops = {
	.proc_read = nPlUsbEnumEnabled_read_proc,
	.proc_write = nPlUsbEnumEnabled_write_proc,
};

static ssize_t rpmb_enable_read_proc(struct file *file, char __user *buf,
		size_t count, loff_t *off)
{
	char page[256] = {0};
	int len = 0;

	if(!gdata) {
		return -ENOMEM;
	}

	if(!gdata->inited) {
		return -ENOENT;
	}

	len = sprintf(page, "%d", gdata->ConfigInf.rpmb_enable == RPMB_ENABLE_MAGIC);

	if(len > *off)
		len -= *off;
	else
		len = 0;

	if(copy_to_user(buf, page, (len < count ? len : count))) {
		return -EFAULT;
	}
	*off += len < count ? len : count;
	return (len < count ? len : count);
}

static ssize_t rpmb_enable_write_proc(struct file *file, const char __user *buf,
		size_t count, loff_t *off)

{
	char page[256] = {0};
	unsigned int input = 0;

	if(!gdata) {
		return -ENOMEM;
	}

	if(!gdata->inited) {
		return -ENOENT;
	}

	if (count > 256)
		count = 256;
	if(count > *off)
		count -= *off;
	else
		count = 0;

	if (copy_from_user(page, buf, count))
		return -EFAULT;
	*off += count;

	if (sscanf(page, "%u", &input) != 1) {
		count = -EINVAL;
		return count;
	}

	if(input != 0) {
		gdata->ConfigInf.rpmb_enable = RPMB_ENABLE_MAGIC;
		gdata->change_flag++;
		if(gdata->change_flag == 1) {
			schedule_delayed_work(&gdata->sync_work, 0);
		}
		/* wait 1s for emmc write */
		msleep(1000);
	}

	return count;
}


static struct proc_ops rpmb_enable_proc_fops = {
	.proc_read = rpmb_enable_read_proc,
	.proc_write = rpmb_enable_write_proc,
};

static ssize_t rpmb_key_provisioned_read_proc(struct file *file, char __user *buf,
		size_t count, loff_t *off)
{
	char page[256] = {0};
	int len = 0;

	if(!gdata) {
		return -ENOMEM;
	}

	if(!gdata->inited) {
		return -ENOENT;
	}

	printk("rpmb key provisioned magic 0x%x\n", gdata->ConfigInf.rpmb_key_provisioned);

	len = sprintf(page, "%d", gdata->ConfigInf.rpmb_key_provisioned == RPMB_KEY_PROVISIONED);

	if(len > *off)
		len -= *off;
	else
		len = 0;

	if(copy_to_user(buf, page, (len < count ? len : count))) {
		return -EFAULT;
	}
	*off += len < count ? len : count;
	return (len < count ? len : count);
}

static struct proc_ops rpmb_key_provisioned_proc_fops = {
	.proc_read = rpmb_key_provisioned_read_proc,
	.proc_write = NULL,
};

static ssize_t nUsbAutoSwitch_read_proc(struct file *file, char __user *buf,
		size_t count, loff_t *off)
{
	char page[256] = {0};
	int len = 0;

	if(!gdata) {
		return -ENOMEM;
	}

	if(!gdata->inited) {
		return -ENOENT;
	}

	len = sprintf(page, "%d", gdata->ConfigInf.nusbautoswitch);

	if(len > *off)
		len -= *off;
	else
		len = 0;

	if(copy_to_user(buf, page, (len < count ? len : count))) {
		return -EFAULT;
	}
	*off += len < count ? len : count;
	return (len < count ? len : count);
}


static ssize_t nUsbAutoSwitch_write_proc(struct file *file, const char __user *buf,
		size_t count, loff_t *off)

{
	char page[256] = {0};
	unsigned int input = 0;

	if(!gdata) {
		return -ENOMEM;
	}

	if(!gdata->inited) {
		return -ENOENT;
	}

	if (count > 256)
		count = 256;
	if(count > *off)
		count -= *off;
	else
		count = 0;

	if (copy_from_user(page, buf, count))
		return -EFAULT;
	*off += count;
	sscanf(page, "%u", &input);

	if (input != 1 && input != 10 && input != 0) {
		count = -EINVAL;
		return count;
	}

	if(input != gdata->ConfigInf.nusbautoswitch) {
		if (input == 10) { /* bit1-3 use for auto enum bootrom control, if input==0xA, auto enum bootrom */
			gdata->ConfigInf.nusbautoswitch = (gdata->ConfigInf.nusbautoswitch)|(input&0x0E);
		} else {
			gdata->ConfigInf.nusbautoswitch = input;
		}
		printk("%d opluscustom_write nUsbAutoSwitch = 0x%x \n", __LINE__, gdata->ConfigInf.nusbautoswitch);

		gdata->change_flag++;
		if(gdata->change_flag == 1) {
			schedule_delayed_work(&gdata->sync_work, msecs_to_jiffies(OPLUSCUSTOM_SYNC_TIME));
		}
	}

	return count;
}


static struct proc_ops nUsbAutoSwitch_proc_fops = {
	.proc_read = nUsbAutoSwitch_read_proc,
	.proc_write = nUsbAutoSwitch_write_proc,
};


static ssize_t Sensor_read_proc(struct file *file, char __user *buf,
		size_t count, loff_t *off)
{
	char page[256] = {0};
	int len = 0;

	if(!gdata) {
		return -ENOMEM;
	}

	if(!gdata->inited) {
		return -ENOENT;
	}

	if((SENSOR_BUF_SIZE - *off > 256) || (SENSOR_BUF_SIZE - *off < 0)) {
		return len;
	}

	len = SENSOR_BUF_SIZE;

	if(len > *off) {
		len -= *off;
	}
	else {
		len = 0;
		return len;
	}
	if(SENSOR_BUF_SIZE - *off > 0) {
		memcpy(page, &gdata->ConfigInf.Sensor[*off], SENSOR_BUF_SIZE - *off);
		if(copy_to_user(buf, page, (len < count ? len : count))) {
			return -EFAULT;
		}
	}
	*off += len < count ? len : count;
	return (len < count ? len : count);
}


static ssize_t Sensor_write_proc(struct file *file, const char __user *buf,
		size_t count, loff_t *off)

{
	char page[256] = {0};
	int i;

	if(!gdata) {
		return -ENOMEM;
	}

	if(!gdata->inited) {
		return -ENOENT;
	}

	if((SENSOR_BUF_SIZE - *off > 256) || (SENSOR_BUF_SIZE - *off < 0)) {
		return 0;
	}

	if (count > 256)
		count = 256;

	if(count > *off) {
		count -= *off;
	}
	else {
		count = 0;
		return count;
	}

	if(count > 0) {
		if (copy_from_user(page, buf, count))
			return -EFAULT;
		for(i = *off;i < SENSOR_BUF_SIZE;i++) {
			if(gdata->ConfigInf.Sensor[i] != page[i]) {
				memcpy(&gdata->ConfigInf.Sensor[*off], page, count);
				gdata->change_flag++;
				if(gdata->change_flag == 1) {
					schedule_delayed_work(&gdata->sync_work, msecs_to_jiffies(OPLUSCUSTOM_SYNC_TIME));
				}
				break;
			}
		}
		*off += count;
	}

	return count;
}

static loff_t Sensor_llseek(struct file *file, loff_t offset, int whence)
{
	return file->f_pos;
}

static struct proc_ops Sensor_proc_fops = {
	.proc_read = Sensor_read_proc,
	.proc_write = Sensor_write_proc,
	.proc_lseek = Sensor_llseek,
};

static ssize_t DownloadTime_read_proc(struct file *file, char __user *buf,
		size_t count, loff_t *off)
{
	char page[256] = {0};
	int len = 0;

	if(!gdata) {
		return -ENOMEM;
	}

	if(!gdata->inited) {
		return -ENOENT;
	}

	if((DOWNLOADTIME_BUF_SIZE - *off > 256) || (DOWNLOADTIME_BUF_SIZE - *off < 0)) {
		return len;
	}

	len = DOWNLOADTIME_BUF_SIZE;

	if(len > *off) {
		len -= *off;
	}
	else {
		len = 0;
		return len;
	}
	if(DOWNLOADTIME_BUF_SIZE - *off > 0) {
		memcpy(page, &gdata->ConfigInf.DownloadTime[*off], DOWNLOADTIME_BUF_SIZE - *off);
		if(copy_to_user(buf, page, (len < count ? len : count))) {
			return -EFAULT;
		}
	}
	*off += len < count ? len : count;
	return (len < count ? len : count);
}


static struct proc_ops DownloadTime_proc_fops = {
	.proc_read = DownloadTime_read_proc,
	.proc_write = NULL,
};

static int __init opluscustom_init(void)
{
	int rc = 0;
	struct proc_dir_entry *pentry;

	rc = opluscustom_sync_init();
	if(rc < 0)
		return rc;



	if(gdata == NULL) {
		return rc;
	}

	if(gdata->proc_oplusCustom) {
		printk("proc_oplusCustom has alread inited\n");
		return 0;
	}

	gdata->proc_oplusCustom = proc_mkdir("oplusCustom", NULL);
	if(!gdata->proc_oplusCustom) {
		pr_err("can't create oplusCustom proc\n");
		rc = -EFAULT;
		return rc;
	}
	pentry = proc_create("nPlUsbEnumEnabled", 0664, gdata->proc_oplusCustom,
		&nPlUsbEnumEnabled_proc_fops);
	if(!pentry) {
		pr_err("create nPlUsbEnumEnabled proc failed.\n");
		rc = -EFAULT;
		return rc;
	}
	pentry = proc_create("nUsbAutoSwitch", 0666, gdata->proc_oplusCustom,
		&nUsbAutoSwitch_proc_fops);
	if(!pentry) {
		pr_err("create nUsbAutoSwitch proc failed.\n");
		rc = -EFAULT;
		return rc;
	}
	pentry = proc_create("Sensor", 0664, gdata->proc_oplusCustom,
		&Sensor_proc_fops);
	if(!pentry) {
		pr_err("create Sensor proc failed.\n");
		rc = -EFAULT;
		return rc;
	}
	pentry = proc_create("DownloadTime", 0444, gdata->proc_oplusCustom,
		&DownloadTime_proc_fops);
	if(!pentry) {
		pr_err("create DownloadTime proc failed.\n");
		rc = -EFAULT;
		return rc;
	}

	pentry = proc_create("rpmb_enable", 0666, gdata->proc_oplusCustom,
		&rpmb_enable_proc_fops);
	if(!pentry) {
		pr_err("create rpmb_enable proc failed.\n");
		rc = -EFAULT;
		return rc;
	}

	pentry = proc_create("rpmb_key_provisioned", 0444, gdata->proc_oplusCustom,
		&rpmb_key_provisioned_proc_fops);
	if(!pentry) {
		pr_err("create rpmb_key_provisioned proc failed.\n");
		rc = -EFAULT;
		return rc;
	}

	return 0;
}

late_initcall(opluscustom_init);

MODULE_DESCRIPTION("OPLUS custom version");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Joshua");
