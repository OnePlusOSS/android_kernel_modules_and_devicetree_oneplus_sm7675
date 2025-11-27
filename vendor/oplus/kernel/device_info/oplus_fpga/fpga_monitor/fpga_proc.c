#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/regmap.h>
#include <linux/i2c.h>
#include <linux/mutex.h>
#include <linux/of_gpio.h>
#include <linux/gpio.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/delay.h>
#include <linux/soc/qcom/smem.h>
#include <linux/clk.h>
#include <linux/pinctrl/consumer.h>
#if IS_ENABLED(CONFIG_OPLUS_FPGA_NOTIFY)
#include <soc/oplus/fpga_notify.h>
#endif
#include "fpga_monitor.h"
#include "fpga_mid.h"
#include "fpga_common_api.h"
#include "fpga_proc.h"
#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/poll.h>
#include <linux/kfifo.h>
#include <linux/ktime.h>

static DEFINE_MUTEX(fpga_read_op_mutex);
static DEFINE_MUTEX(fpga_wakeup_op_mutex);
static DEFINE_MUTEX(fpga_poll_wait_mutex);

static DECLARE_WAIT_QUEUE_HEAD(fpga_wait_queue);

DECLARE_KFIFO(fpga_poll_fifo, uint64_t, FPGA_FIFO_ELEMENT_MAX);

void fpga_poll_wakeup(struct fpga_mnt_pri *mnt_pri, uint64_t type)
{
	int ret = 0;
	static uint64_t old_time_ns = 0;
	uint64_t current_time_ns = 0;
	if (!mnt_pri) {
		FPGA_ERR("error:file_inode.\n");
		return;
	}
	mutex_lock(&fpga_wakeup_op_mutex);
	current_time_ns = ktime_get_ns();
	if ((current_time_ns - old_time_ns) > FPGA_FIFO_TIMEOUT_MAX) {
		if(!kfifo_is_empty(&fpga_poll_fifo)) {
			kfifo_reset(&fpga_poll_fifo);
			FPGA_INFO("fpga_poll_fifo kfifo_reset\n");
		}
	}
	ret = kfifo_put(&fpga_poll_fifo, type);
	if (!ret) {
		FPGA_ERR("fpga_poll_fifo put fail, fifo is full\n");
	} else {
		FPGA_INFO("fpga_poll_wakeup %llx\r\n", type);
	}
	wake_up_interruptible(&fpga_wait_queue);
	old_time_ns = current_time_ns;
	mutex_unlock(&fpga_wakeup_op_mutex);
}

static ssize_t fpga_err_info_write(struct file *file, const char __user *buffer, size_t count, loff_t *p_pos)
{
	struct fpga_mnt_pri *mnt_pri = PDE_DATA(file_inode(file));
	uint64_t mode = 0;
	char buf_op[FPGA_BUF_OP_MAX_ADD] = { 0 };

	if (!mnt_pri) {
		FPGA_ERR("error:file_inode.\n");
		return -EINVAL;
	}
	if (count > FPGA_BUF_OP_MAX_ADD - 1) {
		FPGA_ERR("error:buffer too large.\n");
		return -EINVAL;
	}

	if (copy_from_user(buf_op, buffer, count)) {
		FPGA_ERR("error:copy_from_user failed.\n");
		return -EFAULT;
	}
	buf_op[FPGA_BUF_OP_MAX_ADD - 1] = '\0';
	if (sscanf(buf_op, "%llx", &mode) != 1) {
		FPGA_ERR("error:invalid data format.\n");
		return -EINVAL;
	}

	fpga_poll_wakeup(mnt_pri, mode);

	return count;
}

static ssize_t fpga_err_info_read(struct file *file, char __user *buf, size_t count, loff_t *p_pos)
{
	struct fpga_mnt_pri *mnt_pri = PDE_DATA(file_inode(file));
	int ret = 0;
	uint64_t excep_type = 0;

	if (!mnt_pri) {
		FPGA_ERR("error:file_inode.\n");
		return -EINVAL;
	}
	mutex_lock(&fpga_read_op_mutex);
	ret = kfifo_get(&fpga_poll_fifo, &excep_type);
	if (!ret) {
		FPGA_INFO("fpga_poll_fifo get fail, fifo is empty\n");
	}
	ret = simple_read_from_buffer(buf, count, p_pos, &excep_type, sizeof(excep_type));
	FPGA_INFO("fpga_poll_wakeup %llx\r\n", excep_type);
	mutex_unlock(&fpga_read_op_mutex);
	return ret;
}
static __poll_t fpga_err_info_poll(struct file *file, poll_table *wait)
{
	struct fpga_mnt_pri *mnt_pri = PDE_DATA(file_inode(file));
	__poll_t mask = 0;
	uint64_t mode = 0;

	if (!mnt_pri) {
		FPGA_ERR("error:file_inode.\n");
		return mask;
	}
	poll_wait(file, &fpga_wait_queue, wait);
	mutex_lock(&fpga_poll_wait_mutex);
	if (kfifo_peek(&fpga_poll_fifo, &mode) != 0)
		mask |= EPOLLIN | EPOLLRDNORM;
	mutex_unlock(&fpga_poll_wait_mutex);
	return mask;
}

static const struct proc_ops proc_fops = {
	.proc_write = fpga_err_info_write,
	.proc_read  = fpga_err_info_read,
	.proc_poll  = fpga_err_info_poll,
	.proc_open  = simple_open,
	.proc_lseek = default_llseek,
};
static void fault_inject_power_off(struct fpga_power_data *hw_data)
{
	// hw fault inject, vcccore down, delay 1ms, vccio down
	fpga_powercontrol_vcccore(hw_data, false);
	mdelay(1);
	fpga_powercontrol_vccio(hw_data, false);
}

static void fault_inject_power_on(struct fpga_power_data *hw_data)
{
	fpga_powercontrol_vccio(hw_data, true);
	mdelay(1);
	fpga_powercontrol_vcccore(hw_data, true);
}

/*
pull fpga error gpio down to generate error code.
*/
void fpga_gen_errcode(struct fpga_mnt_pri *mnt_pri)
{
	struct fpga_power_data *pdata = NULL;

	if (!mnt_pri) {
		FPGA_ERR("mnt_pri is null\n");
		return;
	}

	FPGA_INFO("enter.\n");
	pdata = &mnt_pri->hw_data;
	gpio_direction_output(pdata->fpga_err_gpio, 0);
	pinctrl_select_state(pdata->pinctrl, pdata->fpga_err_low);
	msleep(100);
	gpio_direction_output(pdata->fpga_err_gpio, 1);
	pinctrl_select_state(pdata->pinctrl, pdata->fpga_err_high);
}

static int fpga_info_func(struct seq_file *s, void *v)
{
	struct fpga_mnt_pri *info = (struct fpga_mnt_pri *) s->private;

	seq_printf(s, "Device m version:\t\t0x%08x\n", info->version_m);
	seq_printf(s, "Device s version:\t\t0x%08x\n", info->version_s);
	seq_printf(s, "Device fw_path:\t\t%s\n", info->fw_path);

	return 0;
}

static int fpga_info_open(struct inode *inode, struct file *file)
{
	return single_open(file, fpga_info_func, PDE_DATA(inode));
}

DECLARE_PROC_OPS(fpga_info_node_fops, fpga_info_open, seq_read, NULL, single_release);

static ssize_t proc_fpga_status_read(struct file *file,
				     char __user *user_buf, size_t count, loff_t *ppos)
{
	int ret = 0;
	struct fpga_mnt_pri *mnt_pri = PDE_DATA(file_inode(file));
	char page[PAGESIZE] = {0};
	int status = 0;
	u8 buf[FPGA_REG_MAX_ADD] = {0};

	if (!mnt_pri) {
		FPGA_ERR("error:file_inode.\n");
		return ret;
	}

	memset(buf, 0, sizeof(buf));
	ret = fpga_i2c_read(mnt_pri, FPGA_REG_ADDR, buf, FPGA_REG_MAX_ADD);
	if (ret < 0) {
		FPGA_ERR("fpga i2c read failed: ret %d\n", ret);
		status = 1;
	} else {
		if (buf[REG_SLAVER_ERR] == REG_SLAVER_ERR_CODE) {
			status = 1;
		} else {
			status = 0;
		}
	}

	snprintf(page, PAGESIZE - 1, "%d\n", status);

	ret = simple_read_from_buffer(user_buf, count, ppos, page, strlen(page));
	return ret;
}

DECLARE_PROC_OPS(fpga_status_node_fops, simple_open, proc_fpga_status_read, NULL, NULL);

static ssize_t fpga_ault_injec_read(struct file *file,
				     char __user *user_buf, size_t count, loff_t *ppos)
{
	int ret = 0;
	struct fpga_mnt_pri *mnt_pri = PDE_DATA(file_inode(file));
	char page[PAGESIZE] = {0};
	int status = 1;

	if (!mnt_pri) {
		FPGA_ERR("error:file_inode.\n");
		snprintf(page, PAGESIZE - 1, "%d\n", status);
		return ret;
	}

	snprintf(page, PAGESIZE - 1, "%d\n", mnt_pri->hw_control_rst);
	mnt_pri->hw_control_rst = 0;

	ret = simple_read_from_buffer(user_buf, count, ppos, page, strlen(page));
	return ret;
}

static ssize_t fpga_fault_injec_write(struct file *file,
				     const char __user *buffer, size_t count, loff_t *ppos)
{
	int ret = 0;
	int mode = 0;
	int voltage = 0;
	char buf[10] = {0};
	struct fpga_mnt_pri *mnt_pri = PDE_DATA(file_inode(file));
	struct fpga_power_data *pdata = NULL;

	if (!mnt_pri) {
		FPGA_ERR("error:file_inode.\n");
		mnt_pri->hw_control_rst = 1;
		return count;
	}

	pdata = &mnt_pri->hw_data;

	if (count > 8) {
		FPGA_ERR("error:count:%lu.\n",count);
		mnt_pri->hw_control_rst = 1;
		return count;
	}

	if (copy_from_user(buf, buffer, count)) {
		FPGA_ERR("read proc input error.\n");
		mnt_pri->hw_control_rst = 1;
		return count;
	}

	sscanf(buf, "%d,%d", &mode, &voltage);

	FPGA_INFO("mode:%d,voltage %d\n", mode, voltage);

	mutex_lock(&mnt_pri->mutex);
	switch (mode) {
	case GEN_ERR_CODE:
		FPGA_INFO("GEN_ERR_CODE start\n");
		fpga_gen_errcode(mnt_pri);
		break;
	case RST_CONTROL:
		FPGA_INFO("RESET_CONTROL\n");
		gpio_direction_output(pdata->rst_gpio, 0);
		pinctrl_select_state(pdata->pinctrl, pdata->fpga_rst_sleep);
		break;
	case POWER_CONTROL:
		FPGA_INFO("POWER_CONTROL\n");
		fault_inject_power_off(pdata);
		break;
	case VCC_CORE_CONTROL:
		FPGA_INFO("VCC_CORE_CONTROL\n");
		mnt_pri->power_ready = false;
		mnt_pri->hw_data.vcc_core_volt = voltage;
		fpga_power_uninit(mnt_pri);
		fpga_power_init(mnt_pri);

		fault_inject_power_on(pdata);

		msleep(300);
		mnt_pri->power_ready = true;
		break;
	case VCC_IO_CONTROL:
		FPGA_INFO("VCC_IO_CONTROL\n");
		mnt_pri->power_ready = false;
		mnt_pri->hw_data.vcc_io_volt = voltage;
		fpga_power_uninit(mnt_pri);
		fpga_power_init(mnt_pri);

		fault_inject_power_on(pdata);

		msleep(300);
		mnt_pri->power_ready = true;
		break;
#if FPGA_POWER_DEBUG
	case POWER_CONTROL_PROBE_STOP:
		mnt_pri->power_debug_work_count = 0;
		cancel_delayed_work_sync(&mnt_pri->power_debug_work);
		FPGA_INFO("POWER_CONTROL_PROBE_STOP\n");
		break;

	case POWER_CONTROL_PROBE_START:
		queue_delayed_work(mnt_pri->power_debug_wq, &mnt_pri->power_debug_work, msecs_to_jiffies(100));
		FPGA_INFO("POWER_CONTROL_PROBE_START\n");
		break;
#endif
	case ATCMD_POWER_ON:
		fault_inject_power_on(pdata);
		msleep(300);
		mnt_pri->power_ready = true;
		FPGA_INFO("ATCMD_POWER_ON\n");
		break;
	case ATCMD_POWER_OFF:
		fault_inject_power_off(pdata);
		mnt_pri->power_ready = false;
		FPGA_INFO("ATCMD_POWER_OFF\n");
		break;
	default:
		break;
	}
	mutex_unlock(&mnt_pri->mutex);
	mnt_pri->hw_control_rst = ret;

	return count;
}

DECLARE_PROC_OPS(fpga_ault_injec_fops, simple_open, fpga_ault_injec_read, fpga_fault_injec_write, NULL);

static ssize_t fpga_monitor_time_read(struct file *file,
				     char __user *user_buf, size_t count, loff_t *ppos)
{
	int ret = 0;
	struct fpga_mnt_pri *mnt_pri = PDE_DATA(file_inode(file));
	char page[PAGESIZE] = {0};
	int status = 1;

	if (!mnt_pri) {
		FPGA_ERR("error:file_inode.\n");
		snprintf(page, PAGESIZE - 1, "%d\n", status);
		return ret;
	}

	snprintf(page, PAGESIZE - 1, "%d\n", mnt_pri->fpga_monitor_time);

	ret = simple_read_from_buffer(user_buf, count, ppos, page, strlen(page));
	return ret;
}

static ssize_t fpga_monitor_time_write(struct file *file,
				     const char __user *buffer, size_t count, loff_t *ppos)
{
	char buf[10] = {0};
	u32 rus_fpga_monitor_time = 0;
	struct fpga_mnt_pri *mnt_pri = PDE_DATA(file_inode(file));

	if (!mnt_pri) {
		FPGA_ERR("error:file_inode.\n");
		return -EINVAL;
	}

	FPGA_ERR("current heartbeat_switch is %d\n", mnt_pri->heartbeat_switch);
	if (mnt_pri->heartbeat_switch == 0) {   // current rus heartbeat switch is off, don't set monitor time
		FPGA_ERR("current heartbeat_switch is rus 0, so don't set monitor_time.\n");
		return -EINVAL;
	}

	if (copy_from_user(buf, buffer, min(count, sizeof(buf) - 1))) {
		FPGA_ERR("read proc input error.\n");
		return -EFAULT;
	}

	buf[min(count, sizeof(buf) - 1)] = '\0';
	if (sscanf(buf, "%u", &rus_fpga_monitor_time) != 1) {
		FPGA_ERR("error:invalid data format.\n");
		return -EINVAL;
	}

	if ((rus_fpga_monitor_time > 0) && (rus_fpga_monitor_time < FPGA_MONITOR_WORK_MAX_TIME)) {   /* rus set the new heatbeat period */
		FPGA_INFO("rus_fpga_monitor_time is valid, set rus_fpga_monitor_time is %u.\n", rus_fpga_monitor_time);
		mnt_pri->fpga_monitor_time = rus_fpga_monitor_time;
	}

	return count;
}
DECLARE_PROC_OPS(fpga_monitor_time_fops, simple_open, fpga_monitor_time_read, fpga_monitor_time_write, NULL);


static ssize_t fpga_heartbeat_switch_read(struct file *file,
							char __user *user_buf, size_t count, loff_t *ppos)
{
	int ret = 0;
	struct fpga_mnt_pri *mnt_pri = PDE_DATA(file_inode(file));
	char page[PAGESIZE] = {0};
	int status = 1;

	if (!mnt_pri) {
		FPGA_ERR("error:file_inode.\n");
		snprintf(page, PAGESIZE - 1, "%d\n", status);
		return ret;
	}

	FPGA_INFO("fpga_heartbeat_switch_read mnt_pri->heartbeat_switch is %d\n", mnt_pri->heartbeat_switch);
	snprintf(page, PAGESIZE - 1, "%d\n", mnt_pri->heartbeat_switch);

	ret = simple_read_from_buffer(user_buf, count, ppos, page, strlen(page));
	return ret;
}

static ssize_t fpga_heartbeat_switch_write(struct file *file,
				     const char __user *buffer, size_t count, loff_t *ppos)
{
	struct fpga_mnt_pri *mnt_pri = PDE_DATA(file_inode(file));
	int fpga_switch = -1;   // defalut value is -1, invalid
	char buf[10] = { 0 };

	if (!mnt_pri) {
		FPGA_ERR("error:file_inode.\n");
		return -EINVAL;
	}

	if (copy_from_user(buf, buffer, min(count, sizeof(buf) - 1))) {
		FPGA_ERR("error:copy_from_user failed.\n");
		return -EFAULT;
	}
	buf[min(count, sizeof(buf) - 1)] = '\0';
	if (sscanf(buf, "%d", &fpga_switch) != 1) {
		FPGA_ERR("error:invalid data format.\n");
		return -EINVAL;
	}

	FPGA_INFO("fpga_heartbeat_switch_write  WXY fpga_switch is %d\n", fpga_switch);
	if (fpga_switch == 0) {   /* stop heartbeat work */
		FPGA_INFO("RUS fpga_switch stop, cancel work.\n");
		mnt_pri->heartbeat_switch = 0;
		cancel_delayed_work_sync(&mnt_pri->hb_work);
	} else if (fpga_switch == 1) {   /* start heartbeat work */
		FPGA_INFO("RUS fpga_switch start, restart work.\n");
		mnt_pri->heartbeat_switch = 1;
		queue_delayed_work(mnt_pri->hb_workqueue, &mnt_pri->hb_work, msecs_to_jiffies(1000));
	}

	return count;
}
DECLARE_PROC_OPS(fpga_heartbeat_switch_fops, simple_open, fpga_heartbeat_switch_read, fpga_heartbeat_switch_write, NULL);

static int proc_dump_register_read_func(struct seq_file *s, void *v)
{
	int ret = 0;
	u8 *page = NULL;
	u8 _buf[PAGESIZE] = {0};
	u8 reg_buf[FPGA_REG_MAX_ADD] = {0};
	int i = 0;
	struct fpga_mnt_pri *mnt_pri = (struct fpga_mnt_pri *) s->private;
	struct fpga_power_data *pdata = NULL;
	struct fpga_status_t *status = &mnt_pri->status;
	struct fpga_status_t *all_status = &mnt_pri->all_status;

	if (!mnt_pri) {
		FPGA_ERR("error:file_inode.\n");
		seq_printf(s, "%s error:file_inode.\n", __func__);
		return ret;
	}

	pdata = &mnt_pri->hw_data;

	if (!mnt_pri->bus_ready) {
		FPGA_ERR("bus not ready! exit\n");
		seq_printf(s, "%s, bus not ready! exit\n", __func__);
		return 0;
	}

	memset(reg_buf, 0, sizeof(reg_buf));
	ret = fpga_i2c_read(mnt_pri, FPGA_REG_ADDR, reg_buf, FPGA_REG_MAX_ADD);
	if (ret < 0) {
		FPGA_ERR("fpga i2c read failed: ret %d\n", ret);
		seq_printf(s, "fpga i2c read failed: ret %d\n", ret);
		return 0;
	}

	page = (u8 *)kzalloc(2048, GFP_KERNEL);
	if (!page) {
		seq_printf(s, "proc_dump_register_read_func : kzalloc page error\n");
		return 0;
	}

	for (i = 0; i < FPGA_REG_MAX_ADD; i++) {
		memset(_buf, 0, sizeof(_buf));
		snprintf(_buf, sizeof(_buf), "reg 0x%x:0x%x\n", i, reg_buf[i]);
		strlcat(page, _buf, 2048);
	}

	seq_printf(s, "%s\n", page);
	kfree(page);

	seq_printf(s, "m_io_rx = %llu\n", status->m_io_rx_err_cnt);
	seq_printf(s, "m_i2c_rx = %llu\n", status->m_i2c_rx_err_cnt);
	seq_printf(s, "m_spi_rx = %llu\n", status->m_spi_rx_err_cnt);
	seq_printf(s, "s_io_rx = %llu\n", status->s_io_rx_err_cnt);
	seq_printf(s, "s_i2c_rx = %llu\n", status->s_i2c_rx_err_cnt);
	seq_printf(s, "s_spi_rx = %llu\n", status->s_spi_rx_err_cnt);

	seq_printf(s, "all_m_io_rx = %llu\n", all_status->m_io_rx_err_cnt);
	seq_printf(s, "all_m_i2c_rx = %llu\n", all_status->m_i2c_rx_err_cnt);
	seq_printf(s, "all_m_spi_rx = %llu\n", all_status->m_spi_rx_err_cnt);
	seq_printf(s, "all_s_io_rx = %llu\n", all_status->s_io_rx_err_cnt);
	seq_printf(s, "all_s_i2c_rx = %llu\n", all_status->s_i2c_rx_err_cnt);
	seq_printf(s, "all_s_spi_rx = %llu\n", all_status->s_spi_rx_err_cnt);

	return 0;
}

static int dump_register_open(struct inode *inode, struct file *file)
{
	return single_open(file, proc_dump_register_read_func, PDE_DATA(inode));
}

DECLARE_PROC_OPS(fpga_dump_info_fops, dump_register_open, seq_read, NULL, single_release);

int fpga_proc_create(struct fpga_mnt_pri *mnt_pri)
{
	struct proc_dir_entry *d_entry;
	INIT_KFIFO(fpga_poll_fifo);
	d_entry = proc_create_data("info", S_IRUGO, mnt_pri->pr_entry, &fpga_info_node_fops, mnt_pri);
	if (d_entry == NULL) {
		FPGA_ERR("Couldn't create fpga info proc data\n");
		return -EINVAL;
	}
	d_entry = proc_create_data("status", S_IRUGO, mnt_pri->pr_entry, &fpga_status_node_fops, mnt_pri);
	if (d_entry == NULL) {
		FPGA_ERR("Couldn't create fpga status proc data\n");
		return -EINVAL;
	}
	d_entry = proc_create_data("hw_control", (S_IRUGO | S_IWUGO), mnt_pri->pr_entry, &fpga_ault_injec_fops, mnt_pri);
	if (d_entry == NULL) {
		FPGA_ERR("Couldn't create fpga hw_contorl proc data\n");
		return -EINVAL;
	}
	d_entry = proc_create_data("dump_info", S_IRUGO, mnt_pri->pr_entry, &fpga_dump_info_fops, mnt_pri);
	if (d_entry == NULL) {
		FPGA_ERR("Couldn't create fpga dump_info proc data\n");
		return -EINVAL;
	}
	d_entry= proc_create_data("errinfoto_op", (S_IRUGO | S_IWUGO), mnt_pri->pr_entry, &proc_fops, mnt_pri);
	if (d_entry == NULL) {
		FPGA_ERR("Couldn't create fpga errinfoto_op proc data\n");
		return -EINVAL;
	}

	d_entry= proc_create_data("monitor_time", (S_IRUGO | S_IWUGO), mnt_pri->pr_entry, &fpga_monitor_time_fops, mnt_pri);
	if (d_entry == NULL) {
		FPGA_ERR("Couldn't create fpga errinfoto_op proc data\n");
		return -EINVAL;
	}

	d_entry= proc_create_data("heartbeat_switch", (S_IRUGO | S_IWUGO), mnt_pri->pr_entry, &fpga_heartbeat_switch_fops, mnt_pri);
	if (d_entry == NULL) {
		FPGA_ERR("Couldn't create fpga errinfoto_op proc data\n");
		return -EINVAL;
	}
	return 0;
}