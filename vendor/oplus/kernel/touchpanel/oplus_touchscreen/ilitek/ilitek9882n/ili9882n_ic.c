/*
 * ILITEK Touch IC driver
 *
 * Copyright (C) 2011 ILI Technology Corporation.
 *
 * Author: Dicky Chiang <dicky_chiang@ilitek.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#include "ili9882n.h"

#define PROTOCL_VER_NUM     8
static struct ilitek_protocol_info protocol_info[PROTOCL_VER_NUM] = {
    /* length -> fw, protocol, tp, key, panel, core, func, window, cdc, mp_info */
    [0] = {PROTOCOL_VER_500, 4, 4, 14, 30, 5, 5, 2, 8, 3, 8},
    [1] = {PROTOCOL_VER_510, 4, 3, 14, 30, 5, 5, 3, 8, 3, 8},
    [2] = {PROTOCOL_VER_520, 4, 4, 14, 30, 5, 5, 3, 8, 3, 8},
    [3] = {PROTOCOL_VER_530, 9, 4, 14, 30, 5, 5, 3, 8, 3, 8},
    [4] = {PROTOCOL_VER_540, 9, 4, 14, 30, 5, 5, 3, 8, 15, 8},
    [5] = {PROTOCOL_VER_550, 9, 4, 14, 30, 5, 5, 3, 8, 15, 14},
    [6] = {PROTOCOL_VER_560, 9, 4, 14, 30, 5, 5, 3, 8, 15, 14},
    [7] = {PROTOCOL_VER_570, 9, 4, 14, 30, 5, 5, 3, 8, 15, 14},
};

#define FUNC_CTRL_NUM   22
static struct ilitek_ic_func_ctrl func_ctrl[FUNC_CTRL_NUM] = {
    /* cmd[3] = cmd, func, ctrl */
    [0] = {"sense", {0x1, 0x1, 0x0}, 3},
    [1] = {"sleep", {0x1, 0x2, 0x0}, 3},
    [2] = {"glove", {0x1, 0x6, 0x0}, 3},
    [3] = {"stylus", {0x1, 0x7, 0x0}, 3},
    [4] = {"tp_scan_mode", {0x1, 0x8, 0x0}, 3},
    [5] = {"lpwg", {0x1, 0xA, 0x0}, 3},
    [6] = {"gesture", {0x1, 0xB, 0x3F}, 3},
    [7] = {"phone_cover", {0x1, 0xC, 0x0}, 3},
    [8] = {"finger_sense", {0x1, 0xF, 0x0}, 3},
    [9] = {"phone_cover_window", {0xE, 0x0, 0x0}, 3},
    [10] = {"proximity", {0x1, 0x10, 0x0}, 3},
    [11] = {"plug", {0x1, 0x11, 0x0}, 3},
    [12] = {"edge_palm", {0x1, 0x12, 0x0}, 3},
    [13] = {"lock_point", {0x1, 0x13, 0x0}, 3},
    [14] = {"active", {0x1, 0x14, 0x0}, 3},
    [15] = {"freq_scan", {0x01, 0x15, 0x00}, 3},
    [16] = {"gesture_demo_en", {0x1, 0x16, 0x0}, 3},
    [17] = {"ear_phone", {0x1, 0x17, 0x0}, 3},
    [18] = {"tp_recore", {0x1, 0x18, 0x0}, 3},
    [19] = {"idle", {0x1, 0x19, 0x0}, 3},
    [20] = {"knock_en", {0x1, 0xA, 0x8, 0x03, 0x0, 0x0}, 6},
    [21] = {"int_trigger", {0x1, 0x1B, 0x0}, 3},
};

#define CHIP_SUP_NUM    5
static u32 ic_sup_list[CHIP_SUP_NUM] = {
    [0] = ILI9881_CHIP,
    [1] = ILI7807_CHIP,
    [2] = ILI9881N_AA,
    [3] = ILI9881O_AA,
    [4] = ILI9882_CHIP
};

static int ilitek_tddi_ic_check_support(u32 pid, u16 id)
{
    int i = 0;

    for (i = 0; i < CHIP_SUP_NUM; i++) {
        if ((pid == ic_sup_list[i]) || (id == ic_sup_list[i])) {
            break;
        }
    }

    if (i >= CHIP_SUP_NUM) {
        ILI_INFO("ERROR, ILITEK CHIP(0x%x) Not found !!\n", pid);
    }

    ILI_INFO("ILITEK CHIP %X found.\n", pid);
    ilits9882n->chip->pid = pid;
    ilits9882n->chip->reset_key = 0x00019878;
    ilits9882n->chip->wtd_key = 0x9881;

    if (((pid & 0xFFFFFF00) == ILI9881N_AA) || ((pid & 0xFFFFFF00) == ILI9881O_AA)) {
        ilits9882n->chip->dma_reset = ENABLE;
    } else {
        ilits9882n->chip->dma_reset = DISABLE;
    }

    ilits9882n->chip->no_bk_shift = RAWDATA_NO_BK_SHIFT;
    ilits9882n->chip->max_count = 0x1FFFF;
    return 0;
}

int ili9882n_ice_mode_bit_mask_write(u32 addr, u32 mask, u32 value)
{
    int ret = 0;
    u32 data = 0;

    if (ili9882n_ice_mode_read(addr, &data, sizeof(u32)) < 0) {
        ILI_ERR("Read data error\n");
        return -1;
    }

    data &= (~mask);
    data |= (value & mask);
    ILI_DBG("mask value data = %x\n", data);
    ret = ili9882n_ice_mode_write(addr, data, sizeof(u32));

    if (ret < 0) {
        ILI_ERR("Failed to re-write data in ICE mode, ret = %d\n", ret);
    }

    return ret;
}

int ili9882n_ice_mode_write(u32 addr, u32 data, int len)
{
    int ret = 0, i;
    u8 txbuf[64] = {0};

    if (!atomic_read(&ilits9882n->ice_stat)) {
        ILI_ERR("ice mode not enabled\n");
        return -1;
    }

    txbuf[0] = 0x25;
    txbuf[1] = (char)((addr & 0x000000FF) >> 0);
    txbuf[2] = (char)((addr & 0x0000FF00) >> 8);
    txbuf[3] = (char)((addr & 0x00FF0000) >> 16);

    for (i = 0; i < len; i++) {
        txbuf[i + 4] = (char)(data >> (8 * i));
    }

    ret = ilits9882n->wrapper(txbuf, len + 4, NULL, 0, OFF, OFF);

    if (ret < 0) {
        ILI_ERR("Failed to write data in ice mode, ret = %d\n", ret);
    }

    return ret;
}

int ili9882n_ice_mode_read(u32 addr, u32 *data, int len)
{
    int ret = 0;
    u8 *rxbuf = NULL;
    u8 txbuf[4] = {0};

    if (!atomic_read(&ilits9882n->ice_stat)) {
        ILI_ERR("ice mode not enabled\n");
        return -1;
    }

    txbuf[0] = 0x25;
    txbuf[1] = (char)((addr & 0x000000FF) >> 0);
    txbuf[2] = (char)((addr & 0x0000FF00) >> 8);
    txbuf[3] = (char)((addr & 0x00FF0000) >> 16);
    ret = ilits9882n->wrapper(txbuf, sizeof(txbuf), NULL, 0, OFF, OFF);

    if (ret < 0) {
        goto out;
    }

    rxbuf = kcalloc(len, sizeof(u8), GFP_KERNEL);

    if (ERR_ALLOC_MEM(rxbuf)) {
        ILI_ERR("Failed to allocate rxbuf, %ld\n", PTR_ERR(rxbuf));
        ret = -ENOMEM;
        goto out;
    }

    ret = ilits9882n->wrapper(NULL, 0, rxbuf, len, OFF, OFF);

    if (ret < 0) {
        goto out;
    }

    if (len == sizeof(u8)) {
        *data = rxbuf[0];
    } else {
        *data = (rxbuf[0] | rxbuf[1] << 8 | rxbuf[2] << 16 | rxbuf[3] << 24);
    }

out:

    if (ret < 0) {
        ILI_ERR("Failed to read data in ice mode, ret = %d\n", ret);
    }

    ili_kfree((void **)&rxbuf);
    return ret;
}

int ili9882n_ice_mode_ctrl(bool enable, bool mcu)
{
    int ret = 0;
    u8 cmd_open[4] = {0x25, 0x62, 0x10, 0x18};
    u8 cmd_close[4] = {0x1B, 0x62, 0x10, 0x18};
    ILI_INFO("%s ICE mode, mcu on = %d\n", (enable ? "Enable" : "Disable"), mcu);

    if (enable) {
        if (atomic_read(&ilits9882n->ice_stat)) {
            ILI_INFO("ice mode already enabled\n");
            return 0;
        }

        if (mcu) {
            cmd_open[0] = 0x1F;
        }

        atomic_set(&ilits9882n->ice_stat, ENABLE);

        if (ilits9882n->wrapper(cmd_open, sizeof(cmd_open), NULL, 0, OFF, OFF) < 0) {
            ILI_ERR("write ice mode cmd error\n");
            atomic_set(&ilits9882n->ice_stat, DISABLE);
        }

        ilits9882n->pll_clk_wakeup = false;
    } else {
        if (!atomic_read(&ilits9882n->ice_stat)) {
            ILI_INFO("ice mode already disabled\n");
            return 0;
        }

        ret = ilits9882n->wrapper(cmd_close, sizeof(cmd_close), NULL, 0, OFF, OFF);

        if (ret < 0) {
            ILI_ERR("Exit to ICE Mode failed !!\n");
            atomic_set(&ilits9882n->ice_stat, ENABLE);
        } else {
            atomic_set(&ilits9882n->ice_stat, DISABLE);
            ilits9882n->pll_clk_wakeup = true;
        }
    }

    return ret;
}


int ili9882n_ic_func_ctrl(const char *name, int ctrl)
{
    int i = 0, ret;

    if (strcmp(name, func_ctrl[1].name) == 0) {
        ilits9882n->sleep_type = ctrl;
    }

    for (i = 0; i < FUNC_CTRL_NUM; i++) {
        if (ipio_strcmp(name, func_ctrl[i].name) == 0) {
            if (strlen(name) != strlen(func_ctrl[i].name)) {
                continue;
            }

            break;
        }
    }

    if (i >= FUNC_CTRL_NUM) {
        ILI_ERR("Not found function ctrl, %s\n", name);
        ret = -1;
        goto out;
    }

    if (ilits9882n->protocol->ver == PROTOCOL_VER_500) {
        ILI_ERR("Non support function ctrl with protocol v5.0\n");
        ret = -1;
        goto out;
    }

    if (ilits9882n->protocol->ver >= PROTOCOL_VER_560) {
        if (ipio_strcmp(func_ctrl[i].name, "gesture") == 0 ||
            ipio_strcmp(func_ctrl[i].name, "phone_cover_window") == 0) {
            ILI_INFO("Non support %s function ctrl\n", func_ctrl[i].name);
            ret = -1;
            goto out;
        }
    }

    func_ctrl[i].cmd[2] = ctrl;
    ILI_INFO("func = %s, len = %d, cmd = 0x%x, 0%x, 0x%x\n", func_ctrl[i].name, func_ctrl[i].len,
             func_ctrl[i].cmd[0], func_ctrl[i].cmd[1], func_ctrl[i].cmd[2]);
    ret = ilits9882n->wrapper(func_ctrl[i].cmd, func_ctrl[i].len, NULL, 0, OFF, OFF);

    if (ret < 0) {
        ILI_ERR("Write TP function failed\n");
    }

out:
    return ret;
}

int ili9882n_ic_code_reset(bool mcu)
{
    int ret;
    bool ice = atomic_read(&ilits9882n->ice_stat);

    if (!ice)
        if (ili9882n_ice_mode_ctrl(ENABLE, mcu) < 0) {
            ILI_ERR("Enable ice mode failed before code reset\n");
        }

    ret = ili9882n_ice_mode_write(0x40040, 0xAE, 1);

    if (ret < 0) {
        ILI_ERR("ic code reset failed\n");
    }

    if (!ice)
        if (ili9882n_ice_mode_ctrl(DISABLE, mcu) < 0) {
            ILI_ERR("Enable ice mode failed after code reset\n");
        }

    return ret;
}

int ili9882n_ic_whole_reset(bool mcu)
{
    int ret = 0;
    bool ice = atomic_read(&ilits9882n->ice_stat);

    if (!ice)
        if (ili9882n_ice_mode_ctrl(ENABLE, mcu) < 0) {
            ILI_ERR("Enable ice mode failed before chip reset\n");
        }

    ILI_INFO("ic whole reset key = 0x%x, edge_delay = %d\n",
             ilits9882n->chip->reset_key, ilits9882n->rst_edge_delay);
    ret = ili9882n_ice_mode_write(ilits9882n->chip->reset_addr, ilits9882n->chip->reset_key, sizeof(u32));

    if (ret < 0) {
        ILI_ERR("ic whole reset failed\n");
        goto out;
    }

    /* Need accurate power sequence, do not change it to msleep */
    mdelay(ilits9882n->rst_edge_delay);
out:

    if (!ice)
        if (ili9882n_ice_mode_ctrl(DISABLE, mcu) < 0) {
            ILI_ERR("Enable ice mode failed after chip reset\n");
        }

    return ret;
}

static void ilitek_tddi_ic_wr_pack(int packet)
{
    int retry = 100;
    u32 reg_data = 0;

    while (retry--) {
        if (ili9882n_ice_mode_read(0x73010, &reg_data, sizeof(u8)) < 0) {
            ILI_ERR("Read 0x73010 error\n");
        }

        if ((reg_data & 0x02) == 0) {
            ILI_INFO("check ok 0x73010 read 0x%X retry = %d\n", reg_data, retry);
            break;
        }

        mdelay(10);
    }

    if (retry <= 0) {
        ILI_INFO("check 0x73010 error read 0x%X\n", reg_data);
    }

    if (ili9882n_ice_mode_write(0x73000, packet, 4) < 0) {
        ILI_ERR("Write %x at 0x73000\n", packet);
    }
}

static u32 ilitek_tddi_ic_rd_pack(int packet)
{
    int retry = 100;
    u32 reg_data = 0;
    ilitek_tddi_ic_wr_pack(packet);

    while (retry--) {
        if (ili9882n_ice_mode_read(0x4800A, &reg_data, sizeof(u8)) < 0) {
            ILI_ERR("Read 0x4800A error\n");
        }

        if ((reg_data & 0x02) == 0x02) {
            ILI_INFO("check  ok 0x4800A read 0x%X retry = %d\n", reg_data, retry);
            break;
        }

        mdelay(10);
    }

    if (retry <= 0) {
        ILI_INFO("check 0x4800A error read 0x%X\n", reg_data);
    }

    if (ili9882n_ice_mode_write(0x4800A, 0x02, 1) < 0) {
        ILI_ERR("Write 0x2 at 0x4800A\n");
    }

    if (ili9882n_ice_mode_read(0x73016, &reg_data, sizeof(u8)) < 0) {
        ILI_ERR("Read 0x73016 error\n");
    }

    return reg_data;
}

void ili9882n_ic_set_ddi_reg_onepage(u8 page, u8 reg, u8 data, bool mcu)
{
    u32 setpage = 0x1FFFFF00 | page;
    u32 setreg = 0x1F000100 | (reg << 16) | data;
    bool ice = atomic_read(&ilits9882n->ice_stat);
    ILI_INFO("setpage =  0x%X setreg = 0x%X\n", setpage, setreg);

    if (!ice)
        if (ili9882n_ice_mode_ctrl(ENABLE, mcu) < 0) {
            ILI_ERR("Enable ice mode failed before writing ddi reg\n");
        }

    /*TDI_WR_KEY*/
    ilitek_tddi_ic_wr_pack(0x1FFF9527);
    /*Switch to Page*/
    ilitek_tddi_ic_wr_pack(setpage);
    /* Page*/
    ilitek_tddi_ic_wr_pack(setreg);
    /*TDI_WR_KEY OFF*/
    ilitek_tddi_ic_wr_pack(0x1FFF9500);

    if (!ice)
        if (ili9882n_ice_mode_ctrl(DISABLE, mcu) < 0) {
            ILI_ERR("Disable ice mode failed after writing ddi reg\n");
        }
}

void ili9882n_ic_get_ddi_reg_onepage(u8 page, u8 reg, u8 *data, bool mcu)
{
    u32 setpage = 0x1FFFFF00 | page;
    u32 setreg = 0x2F000100 | (reg << 16);
    bool ice = atomic_read(&ilits9882n->ice_stat);
    ILI_INFO("setpage = 0x%X setreg = 0x%X\n", setpage, setreg);

    if (!ice)
        if (ili9882n_ice_mode_ctrl(ENABLE, mcu) < 0) {
            ILI_ERR("Enable ice mode failed before reading ddi reg\n");
        }

    /*TDI_WR_KEY*/
    ilitek_tddi_ic_wr_pack(0x1FFF9527);
    /*Set Read Page reg*/
    ilitek_tddi_ic_wr_pack(setpage);
    /*TDI_RD_KEY*/
    ilitek_tddi_ic_wr_pack(0x1FFF9487);

    /*( *( __IO uint8 *)    (0x4800A) ) =0x2*/
    if (ili9882n_ice_mode_write(0x4800A, 0x02, 1) < 0) {
        ILI_ERR("Write 0x2 at 0x4800A\n");
    }

    *data = ilitek_tddi_ic_rd_pack(setreg);
    ILI_INFO("check page = 0x%X, reg = 0x%X, read 0x%X\n", page, reg, *data);
    /*TDI_RD_KEY OFF*/
    ilitek_tddi_ic_wr_pack(0x1FFF9400);
    /*TDI_WR_KEY OFF*/
    ilitek_tddi_ic_wr_pack(0x1FFF9500);

    if (!ice)
        if (ili9882n_ice_mode_ctrl(DISABLE, mcu) < 0) {
            ILI_ERR("Disable ice mode failed after reading ddi reg\n");
        }
}


void ili9882n_ic_get_pc_counter(int stat)
{
    bool ice = atomic_read(&ilits9882n->ice_stat);
    u32 pc = 0, pc_addr = ilits9882n->chip->pc_counter_addr;
    u32 latch = 0, latch_addr = ilits9882n->chip->pc_latch_addr;
    int ret = 0;
    ILI_DBG("stat = %d\n", stat);

    if (!ice) {
        if (stat == DO_SPI_RECOVER) {
            ret = ili9882n_ice_mode_ctrl(ENABLE, OFF);
        } else {
            ret = ili9882n_ice_mode_ctrl(ENABLE, ON);
        }

        if (ret < 0) {
            ILI_ERR("Enable ice mode failed while reading pc counter\n");
        }
    }

    if (ili9882n_ice_mode_read(ilits9882n->chip->pc_counter_addr, &pc, sizeof(u32)) < 0) {
        ILI_ERR("Read pc conter error\n");
    }

    if (ili9882n_ice_mode_read(ilits9882n->chip->pc_latch_addr, &latch, sizeof(u32)) < 0) {
        ILI_ERR("Read pc latch error\n");
    }

    ilits9882n->fw_pc = pc;
    ilits9882n->fw_latch = latch;
    ILI_ERR("Read counter (addr: 0x%x) = 0x%x, latch (addr: 0x%x) = 0x%x\n",
            pc_addr, ilits9882n->fw_pc, latch_addr, ilits9882n->fw_latch);

    /* Avoid screen abnormal. */
    if (stat == DO_SPI_RECOVER) {
        atomic_set(&ilits9882n->ice_stat, DISABLE);
        return;
    }

    if (!ice) {
        if (ili9882n_ice_mode_ctrl(DISABLE, ON) < 0) {
            ILI_ERR("Disable ice mode failed while reading pc counter\n");
        }
    }
}

int ili9882n_ic_int_trigger_ctrl(bool pulse)
{
    /* It's supported by fw, and the level will be kept at high until data was already prepared. */
    if (ili9882n_ic_func_ctrl("int_trigger", pulse) < 0) {
        ILI_ERR("Write CMD error, set back to <%s> trigger\n", ilits9882n->int_pulse ? "Level" : "Pulse");
        return -1;
    }

    ilits9882n->int_pulse = pulse;
    ILI_INFO("INT Trigger = %s\n", ilits9882n->int_pulse ? "Level" : "Pulse");
    return 0;
}

int ili9882n_ic_check_int_level(bool level)
{
    int timer = 3000;
    int gpio = ilits9882n->tp_int;

    /*
     * If callers have a trouble to use the gpio that is passed by vendors,
     * please utlises a physical gpio number instead or call a help from them.
     */

    while (--timer > 0) {
        if (level) {
            if (gpio_get_value(gpio)) {
                ILI_DBG("INT high detected.\n");
                return 0;
            }
        } else {
            if (!gpio_get_value(gpio)) {
                ILI_DBG("INT low detected.\n");;
                return 0;
            }
        }

        mdelay(1);
    }

    ILI_ERR("Error! INT level no detected.\n");
    return -1;
}

int ili9882n_ic_check_int_pulse(bool pulse)
{
    if (!wait_event_interruptible_timeout(ilits9882n->inq, !atomic_read(&ilits9882n->cmd_int_check),
                                          msecs_to_jiffies(ilits9882n->wait_int_timeout))) {
        ILI_ERR("Error! INT pulse no detected. Timeout = %d ms\n", ilits9882n->wait_int_timeout);
        atomic_set(&ilits9882n->cmd_int_check, DISABLE);
        return -1;
    }

    ILI_DBG("INT pulse detected.\n");
    return 0;
}

int ili9882n_ic_check_busy(int count, int delay)
{
    u8 cmd[2] = {0};
    u8 busy = 0, rby = 0;
    cmd[0] = P5_X_READ_DATA_CTRL;
    cmd[1] = P5_X_CDC_BUSY_STATE;

    if (ilits9882n->actual_tp_mode == P5_X_FW_AP_MODE) {
        rby = 0x41;
    } else if (ilits9882n->actual_tp_mode == P5_X_FW_TEST_MODE) {
        rby = 0x51;
    } else {
        ILI_ERR("Unknown TP mode (0x%x)\n", ilits9882n->actual_tp_mode);
        return -EINVAL;
    }

    ILI_INFO("read byte = %x, delay = %d\n", rby, delay);

    do {
        mdelay(delay);

        if (ilits9882n->wrapper(cmd, sizeof(cmd), NULL, 0, OFF, OFF) < 0) {
            ILI_ERR("Write check busy cmd failed\n");
        }

        if (ilits9882n->wrapper(&cmd[1], sizeof(u8), &busy, sizeof(u8), ON, OFF) < 0) {
            ILI_ERR("Read check busy failed\n");
        }

        ILI_DBG("busy = 0x%x\n", busy);

        if (busy == rby) {
            ILI_INFO("Check busy free\n");
            return 0;
        }
    } while (--count > 0);

    ILI_ERR("Check busy (0x%x) timeout !\n", busy);
    ili9882n_ic_get_pc_counter(0);
    return -1;
}

int ili9882n_ic_get_core_ver(void)
{
    int i = 0, ret = 0;
    u8 cmd[2] = {0}, buf[10] = {0};
    ilits9882n->protocol->core_ver_len = P5_X_CORE_VER_FOUR_LENGTH;

    if (ilits9882n->info_from_hex) {
        buf[1] = ilits9882n->fw_info[68];
        buf[2] = ilits9882n->fw_info[69];
        buf[3] = ilits9882n->fw_info[70];
        buf[4] = ilits9882n->fw_info[71];
        goto out;
    }

    do {
        if (i == 0) {
            cmd[0] = P5_X_READ_DATA_CTRL;
            cmd[1] = P5_X_GET_CORE_VERSION_NEW;
        } else {
            cmd[0] = P5_X_READ_DATA_CTRL;
            cmd[1] = P5_X_GET_CORE_VERSION;
            ilits9882n->protocol->core_ver_len = P5_X_CORE_VER_THREE_LENGTH;
        }

        if (ilits9882n->wrapper(cmd, sizeof(cmd), NULL, 0, OFF, OFF) < 0) {
            ILI_ERR("Write core ver cmd failed\n");
        }

        if (ilits9882n->wrapper(&cmd[1], sizeof(u8), buf, ilits9882n->protocol->core_ver_len, ON, OFF) < 0) {
            ILI_ERR("Read core ver (0x%x) failed\n", cmd[1]);
        }

        ILI_DBG("header = 0x%x\n", buf[0]);

        if (buf[0] == P5_X_GET_CORE_VERSION ||
            buf[0] == P5_X_GET_CORE_VERSION_NEW) {
            break;
        }
    } while (++i < 2);

    if (buf[0] == P5_X_GET_CORE_VERSION) {
        buf[4] = 0;
    }

    if (i >= 2) {
        ILI_ERR("Invalid header (0x%x)\n", buf[0]);
        ret = -EINVAL;
    }

out:
    ILI_INFO("Core version = %d.%d.%d.%d\n", buf[1], buf[2], buf[3], buf[4]);
    ilits9882n->chip->core_ver = buf[1] << 24 | buf[2] << 16 | buf[3] << 8 | buf[4];
    return ret;
}

void ili9882n_fw_uart_ctrl(u8 ctrl)
{
    u8 cmd[4] = {0};

    if (ctrl > 1) {
        ILI_INFO("Unknown cmd, ignore\n");
        return;
    }

    ILI_INFO("%s UART mode\n", ctrl ? "Enable" : "Disable");
    cmd[0] = P5_X_I2C_UART;
    cmd[1] = 0x3;
    cmd[2] = 0;
    cmd[3] = ctrl;

    if (ilits9882n->wrapper(cmd, sizeof(cmd), NULL, 0, OFF, OFF) < 0) {
        ILI_INFO("Write fw uart cmd failed\n");
        return;
    }
}

int ili9882n_ic_get_fw_ver(void)
{
    int ret = 0;
    u8 cmd[2] = {0};
    u8 buf[10] = {0};
    char dev_version[MAX_DEVICE_VERSION_LENGTH] = {0};

    if (ilits9882n->info_from_hex) {
        buf[1] = ilits9882n->fw_info[48];
        buf[2] = ilits9882n->fw_info[49];
        buf[3] = ilits9882n->fw_info[50];
        buf[4] = ilits9882n->fw_info[51];
        buf[5] = ilits9882n->fw_mp_ver[0];
        buf[6] = ilits9882n->fw_mp_ver[1];
        buf[7] = ilits9882n->fw_mp_ver[2];
        buf[8] = ilits9882n->fw_mp_ver[3];
        goto out;
    }

    cmd[0] = P5_X_READ_DATA_CTRL;
    cmd[1] = P5_X_GET_FW_VERSION;

    if (ilits9882n->wrapper(cmd, sizeof(cmd), NULL, 0, OFF, OFF) < 0) {
        ILI_ERR("Write pre cmd failed\n");
        ret = -EINVAL;
        goto out;
    }

    if (ilits9882n->wrapper(&cmd[1], sizeof(u8), buf, ilits9882n->protocol->fw_ver_len, ON, OFF) < 0) {
        ILI_ERR("Write fw version cmd failed\n");
        ret = -EINVAL;
        goto out;
    }

    if (buf[0] != P5_X_GET_FW_VERSION) {
        ILI_ERR("Invalid firmware ver\n");
        ret = -1;
    }

out:
    ILI_INFO("Firmware version = %d.%d.%d.%d\n", buf[1], buf[2], buf[3], buf[4]);
    ILI_INFO("Firmware MP version = %d.%d.%d.%d\n", buf[5], buf[6], buf[7], buf[8]);
    ilits9882n->chip->fw_ver = buf[1] << 24 | buf[2] << 16 | buf[3] << 8 | buf[4];
    ilits9882n->chip->fw_mp_ver = buf[5] << 24 | buf[6] << 16 | buf[7] << 8 | buf[8];
    snprintf(dev_version, MAX_DEVICE_VERSION_LENGTH, "%02X", buf[3]);

    if (ilits9882n->ts->panel_data.manufacture_info.version) {
        u8 ver_len = 0;

        if (ilits9882n->ts->panel_data.vid_len == 0) {
            ver_len = strlen(ilits9882n->ts->panel_data.manufacture_info.version);

            //strlcpy(&(ilits9882n->ts->panel_data.manufacture_info.version[12]), dev_version, 3);
            if (ver_len <= 11) {
                snprintf(ilits9882n->ts->panel_data.manufacture_info.version + 9, sizeof(dev_version),"%s", dev_version);
            } else {
                strlcpy(&ilits9882n->ts->panel_data.manufacture_info.version[12], dev_version, 3);
            }
        } else {
            ver_len = ilits9882n->ts->panel_data.vid_len;

            if (ver_len > MAX_DEVICE_VERSION_LENGTH - 4) {
                ver_len = MAX_DEVICE_VERSION_LENGTH - 4;
            }

            strlcpy(&ilits9882n->ts->panel_data.manufacture_info.version[ver_len],
                    dev_version, MAX_DEVICE_VERSION_LENGTH - ver_len);
        }
    }

    ILI_INFO("manufacture_info.version: %s\n", ilits9882n->ts->panel_data.manufacture_info.version);
    return ret;
}

int ili9882n_ic_get_panel_info(void)
{
    if ((ilits9882n->ts->resolution_info.max_x != 0 && ilits9882n->ts->resolution_info.max_y != 0)) {
        ILI_INFO("use kit default resolution\n");
        ilits9882n->panel_wid = ilits9882n->ts->resolution_info.max_x;
        ilits9882n->panel_hei = ilits9882n->ts->resolution_info.max_y;
        ilits9882n->trans_xy = (ilits9882n->chip->core_ver >= CORE_VER_1430
                           && (ilits9882n->rib.nReportByPixel > 0)) ? ON : OFF;
    } else {
        ILI_INFO("Invalid panel info, use default resolution\n");
        ilits9882n->panel_wid = TOUCH_SCREEN_X_MAX;
        ilits9882n->panel_hei = TOUCH_SCREEN_Y_MAX;
        ilits9882n->trans_xy = OFF;
    }

    ILI_INFO("Panel info: width = %d, height = %d\n", ilits9882n->panel_wid, ilits9882n->panel_hei);
    ILI_INFO("Transfer touch coordinate = %s\n", ilits9882n->trans_xy ? "ON" : "OFF");
    return 0;
}

int ili9882n_ic_get_tp_info(void)
{
    int ret = 0;
    u8 cmd[2] = {0};
    u8 buf[20] = {0};

    if (ilits9882n->info_from_hex  && (ilits9882n->chip->core_ver >= CORE_VER_1410)) {
        buf[1] = ilits9882n->fw_info[5];
        buf[2] = ilits9882n->fw_info[7];
        buf[3] = ilits9882n->fw_info[8];
        buf[4] = ilits9882n->fw_info[9];
        buf[5] = ilits9882n->fw_info[10];
        buf[6] = ilits9882n->fw_info[11];
        buf[7] = ilits9882n->fw_info[12];
        buf[8] = ilits9882n->fw_info[14];
        buf[11] = buf[7];
        buf[12] = buf[8];
        goto out;
    }

    cmd[0] = P5_X_READ_DATA_CTRL;
    cmd[1] = P5_X_GET_TP_INFORMATION;

    if (ilits9882n->wrapper(cmd, sizeof(cmd), NULL, 0, OFF, OFF) < 0) {
        ILI_ERR("Write tp info pre cmd failed\n");
        ret = -EINVAL;
        goto out;
    }

    ret = ilits9882n->wrapper(&cmd[1], sizeof(u8), buf, ilits9882n->protocol->tp_info_len, ON, OFF);

    if (ret < 0) {
        ILI_ERR("Read tp info error\n");
        goto out;
    }

    if (buf[0] != P5_X_GET_TP_INFORMATION) {
        ILI_ERR("Invalid tp info\n");
        ret = -1;
        goto out;
    }

out:
    ilits9882n->min_x = buf[1];
    ilits9882n->min_y = buf[2];
    ilits9882n->max_x = buf[4] << 8 | buf[3];
    ilits9882n->max_y = buf[6] << 8 | buf[5];
    ilits9882n->xch_num = buf[7];
    ilits9882n->ych_num = buf[8];
    ilits9882n->stx = buf[11];
    ilits9882n->srx = buf[12];
    ILI_INFO("TP Info: min_x = %d, min_y = %d, max_x = %d, max_y = %d\n", ilits9882n->min_x, ilits9882n->min_y,
             ilits9882n->max_x, ilits9882n->max_y);
    ILI_INFO("TP Info: xch = %d, ych = %d, stx = %d, srx = %d\n", ilits9882n->xch_num, ilits9882n->ych_num,
             ilits9882n->stx, ilits9882n->srx);
    return ret;
}

static void ilitek_tddi_ic_check_protocol_ver(u32 pver)
{
    int i = 0;

    if (ilits9882n->protocol->ver == pver) {
        ILI_DBG("same procotol version, do nothing\n");
        return;
    }

    for (i = 0; i < PROTOCL_VER_NUM - 1; i++) {
        if (protocol_info[i].ver == pver) {
            ilits9882n->protocol = &protocol_info[i];
            ILI_INFO("update protocol version = %x\n", ilits9882n->protocol->ver);
            return;
        }
    }

    ILI_ERR("Not found a correct protocol version in list, use newest version\n");
    ilits9882n->protocol = &protocol_info[PROTOCL_VER_NUM - 1];
}

int ili9882n_ic_get_protocl_ver(void)
{
    int ret = 0;
    u8 cmd[2] = {0};
    u8 buf[10] = {0};
    u32 ver;

    if (ilits9882n->info_from_hex) {
        buf[1] = ilits9882n->fw_info[72];
        buf[2] = ilits9882n->fw_info[73];
        buf[3] = ilits9882n->fw_info[74];
        goto out;
    }

    cmd[0] = P5_X_READ_DATA_CTRL;
    cmd[1] = P5_X_GET_PROTOCOL_VERSION;

    if (ilits9882n->wrapper(cmd, sizeof(cmd), NULL, 0, OFF, OFF) < 0) {
        ILI_ERR("Write protocol ver pre cmd failed\n");
        ret = -EINVAL;
        goto out;
    }

    if (ilits9882n->wrapper(&cmd[1], sizeof(u8), buf, ilits9882n->protocol->pro_ver_len, ON, OFF) < 0) {
        ILI_ERR("Read protocol version error\n");
        ret = -EINVAL;
        goto out;
    }

    if (buf[0] != P5_X_GET_PROTOCOL_VERSION) {
        ILI_ERR("Invalid protocol ver\n");
        ret = -1;
        goto out;
    }

out:
    ver = buf[1] << 16 | buf[2] << 8 | buf[3];
    ilitek_tddi_ic_check_protocol_ver(ver);
    ILI_INFO("Protocol version = %d.%d.%d\n", ilits9882n->protocol->ver >> 16,
             (ilits9882n->protocol->ver >> 8) & 0xFF, ilits9882n->protocol->ver & 0xFF);
    return ret;
}
int ili9882n_ic_get_info(void)
{
    int ret = 0;

    if (!atomic_read(&ilits9882n->ice_stat)) {
        ILI_ERR("ice mode doesn't enable\n");
        return -1;
    }

    if (ili9882n_ice_mode_read(ilits9882n->chip->pid_addr, &ilits9882n->chip->pid, sizeof(u32)) < 0) {
        ILI_ERR("Read chip pid error\n");
    }

    if (ili9882n_ice_mode_read(ilits9882n->chip->otp_addr, &ilits9882n->chip->otp_id, sizeof(u32)) < 0) {
        ILI_ERR("Read otp id error\n");
    }

    if (ili9882n_ice_mode_read(ilits9882n->chip->ana_addr, &ilits9882n->chip->ana_id, sizeof(u32)) < 0) {
        ILI_ERR("Read ana id error\n");
    }

    //ilits9882n->chip->pid = ilits9882n->chip->pid;
    ilits9882n->chip->id = ilits9882n->chip->pid >> 16;
    ilits9882n->chip->type = (ilits9882n->chip->pid & 0x0000FF00) >> 8;
    ilits9882n->chip->ver = ilits9882n->chip->pid & 0xFF;
    ilits9882n->chip->otp_id &= 0xFF;
    ilits9882n->chip->ana_id &= 0xFF;
    ILI_INFO("CHIP: PID = %x\n", (ilits9882n->chip->pid >> 8));
    ret = ilitek_tddi_ic_check_support(ilits9882n->chip->pid, ilits9882n->chip->id);
    return ret;
}

int ili9882n_ic_dummy_check(void)
{
    int ret = 0;
    u32 wdata = 0xA55A5AA5;
    u32 rdata = 0;

    if (!atomic_read(&ilits9882n->ice_stat)) {
        ILI_ERR("ice mode doesn't enable\n");
        return -1;
    }

    if (ili9882n_ice_mode_write(WDT9_DUMMY2, wdata, sizeof(u32)) < 0) {
        ILI_ERR("Write dummy error\n");
    }

    if (ili9882n_ice_mode_read(WDT9_DUMMY2, &rdata, sizeof(u32)) < 0) {
        ILI_ERR("Read dummy error\n");
    }

    if (rdata != wdata) {
        ILI_ERR("Dummy check incorrect, rdata = %x wdata = %x \n", rdata, wdata);
        return -1;
    }

    ILI_INFO("Ilitek IC check successe\n");
    return ret;
}

static struct ilitek_ic_info chip;

void ili9882n_ic_init(void)
{
    chip.pid_addr =         TDDI_PID_ADDR;
    chip.pc_counter_addr =      TDDI_PC_COUNTER_ADDR;
    chip.pc_latch_addr =        TDDI_PC_LATCH_ADDR;
    chip.otp_addr =         TDDI_OTP_ID_ADDR;
    chip.ana_addr =         TDDI_ANA_ID_ADDR;
    chip.reset_addr =       TDDI_CHIP_RESET_ADDR;
    ilits9882n->protocol = &protocol_info[PROTOCL_VER_NUM - 1];
    ilits9882n->chip = &chip;
}
