#ifndef __KEYBOARD_CORE__H__
#define __KEYBOARD_CORE__H__

#include <linux/ioctl.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/input.h>
#include <linux/workqueue.h>
#include <linux/timer.h>
#include <linux/interrupt.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/platform_device.h>
#include <linux/gpio.h>
//#include <mt-plat/aee.h>
#include <linux/atomic.h>
#include <linux/kernel.h>
#include <linux/delay.h>
//#include <mt-plat/mtk_boot_common.h>
#include <linux/hid.h>
#include <linux/hid-debug.h>
#include <linux/kthread.h>
#include <linux/device.h>
#include <linux/mod_devicetable.h>

#include <linux/fcntl.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/interrupt.h>
#include <linux/tty.h>
#include <linux/tty_driver.h>
#include <linux/tty_flip.h>
#include <linux/uio.h>

#include <linux/regulator/consumer.h>


#include <linux/of_gpio.h>
#include <linux/of_irq.h>
// #include "../../gpio/gpiolib.h"

#include <linux/hrtimer.h>
#include <linux/ktime.h>
#include <linux/iio/consumer.h>
#include <linux/workqueue.h>
#include <linux/pogo_common.h>

#define WAKEUP_NAME "pogo_wakeup"
#define KEYBOARD_NAME "pogo_keyboard"
#define TOUCHPAD_NAME "pogo_touchpad"
#define KEYBOARD_CORE_NAME "tinno,pogo_keyboard"

#define KEYBOARD_TTY_NAME   "ttyHS5"
#define KEYBOARD_TTY_MAJAR  491
#define KEYBOARD_TTY_MINOR  5
#define KEYBOARD_TTY_DEBUG_MAJAR  511
#define KEYBOARD_TTY_DEBUG_MINOR  0

#define TOUCH_FINGER_MAX 4

#define CONFIG_TOUCH_SCREEN //macro to enable touch screen mode for keyboard touchpad, or else mouse mode by default.
#ifdef CONFIG_TOUCH_SCREEN
#define TOUCH_X_MAX    1839 //2560//2998//2944 //1079 //800  //2560
#define TOUCH_Y_MAX    2799 //1600//1771//1840 //2407 //1280 //1536

#define KEYBOARD_TOUCH_X_MAX    2560  //2560//2998//2944 //1079 //800  //2560
#define KEYBOARD_TOUCH_Y_MAX    1600  //1600//1771//1840 //2407 //1280 //1536
#else
#define TOUCH_X_MAX    2560 //2998//2944 //1079 //800  //2560
#define TOUCH_Y_MAX    1600 //1771//1840 //2407 //1280 //1536
#endif

#define UART_BUFFER_SIZE 256

#define CONFIG_KEYBOARD_DEBUG
#define CONFIG_KEYBOARD_ERR
#define CONFIG_KEYBOARD_INFO


//#define CONFIG_ADC_SUPPORT
//#define CONFIG_PLUG_SUPPORT // use hall sensor for keyboard attachment detection, or else use drx low signal from keyboard.

#define CONFIG_POWER_CTRL_SUPPORT

#define CONFIG_BOARD_V4_SUPPORT

#define CONFIG_KB_DEBUG_FS     // enable keyboard debugging file nodes.

#define KB_TAG   "POGO_KB:"
#ifdef CONFIG_KEYBOARD_INFO
#define kb_info(fmt, args...)   printk(KERN_ERR KB_TAG fmt,##args)
#else
#define kb_info(fmt, args...)   do { } while (0)
#endif


#ifdef CONFIG_KEYBOARD_DEBUG
static bool pogo_debug_en = true;
#else
static bool pogo_debug_en = false;
#endif
#define kb_debug(fmt, args...)  do {\
                                    if(pogo_debug_en)\
                                        printk(KERN_ERR KB_TAG fmt,##args);\
                                } while (0)




#ifdef CONFIG_KEYBOARD_ERR
#define kb_err(fmt, args...)   printk(KERN_ERR KB_TAG fmt,##args)
#else
#define kb_err(fmt, args...)   do { } while (0)
#endif


#define KEYBOARD_CONNECT_STATUS         (1<<0) // keyboard is attached.
#define KEYBOARD_POWER_ON_STATUS        (1<<1) // lcd is on.
#define KEYBOARD_CAPSLOCK_ON_STATUS     (1<<2)
#define KEYBOARD_MUTEDISABLE_ON_STATUS  (1<<3)
#define KEYBOARD_MICDISABLE_ON_STATUS   (1<<4)



#define LED_MIC_MUTE            0x0b

#define KEY_LOCKSCREEN          0x280
#define KEY_SWITCHLANUAGE       0x282
#define KEY_MICDISABLE          0x283
#define KEY_TOUCHPANELMUTE      0x284
#define KEY_GLOBALSEARCH        0x285
#define KEY_FULLSCREEN          0x286
#define KEY_SPLITSCREEN         0x287
#define KEY_SUPERINTCON         0x289
#define KEY_CUSTOMERAPP1        0x28a
#define KEY_CUSTOMERAPP2        0x28b
#define KEY_KB_ENABLE           0x28e
#define KEY_KB_DISABLE          0x28f



// CRC types

#define CRC_TYPE_CCITT     0
#define CRC_TYPE_IBM       1

// Polynomial = X^16 + X^12 + X^5 + 1
#define  POLYNOMIAL_CCITT   0x1021

// Polynomial = X^16 + X^15 + X^2 + 1
#define  POLYNOMIAL_IBM    0x8005

//  CRC init value
#define  CRC_CCITT_INIT_VAL   0x1D0F
// #define  CRC_IBM_INIT_VAL     0x69F2
#define  CRC_IBM_INIT_VAL     0xC596


enum{
    KEYBOARD_PLUG_IN_EVENT =  0x01,
    KEYBOARD_PLUG_OUT_EVENT,
    KEYBOARD_HOST_LCD_ON_EVENT,
    KEYBOARD_HOST_LCD_OFF_EVENT,

    KEYBOARD_CAPSLOCK_ON_EVENT,
    KEYBOARD_CAPSLOCK_OFF_EVENT,
    KEYBOARD_MUTEDISABLE_ON_EVENT,
    KEYBOARD_MUTEDISABLE_OFF_EVENT,

    KEYBOARD_MICDISABLE_ON_EVENT,
    KEYBOARD_MICDISABLE_OFF_EVENT,
    KEYBOARD_HOST_RX_GPIO_EVENT,
    KEYBOARD_HOST_RX_UART_EVENT,

    KEYBOARD_POWER_ON_EVENT,  // turn on vcc for keyboard
    KEYBOARD_POWER_OFF_EVENT, // turn off vcc for keyboard
    KEYBOARD_HOST_CHECK_EVENT,
    KEYBOARD_TEST_EVENT,
};

enum {
    KEYBOARD_UART_OPEN_START_TYPE = 0x01,
    KEYBOARD_UART_OPEN_END_TYPE,
    KEYBOARD_UART_WRITE_START_TYPE,
    KEYBOARD_UART_WRITE_END_TYPE,
};

enum {
    KEYBOARD_UART_RX_CLEAR_TYPE = 0x00,
    KEYBOARD_UART_RX_SET_TYPE,
    KEYBOARD_UART_RX_GPIO_TYPE,
};

enum {
    KEYBOARD_UART_RECV_DEFAULT = 0x00,
    KEYBOARD_UART_RECV_START,
    KEYBOARD_UART_RECV_END,
};



struct touch_event{
    unsigned int x;
    unsigned int y;
    unsigned char id;
    unsigned char area;
    unsigned char is_down;
    unsigned char is_left;
    unsigned char is_right;
};

typedef int (*pogo_keyboard_callback_t)(unsigned char event);


struct pogo_keyboard_data{
    struct input_dev *input_pogo_keyboard;
    unsigned char old[8];
    unsigned char new[8];
    bool is_down; // tracking last/latest key state(true means key is pressed or else released).
    unsigned int down_code; // tracking last/latest key code being pressed.

    /* struct input_dev *input_mm_pogo_keyboard;*/
    unsigned char mm_old[4];
    unsigned char mm_new[4];
    bool is_mmdown; // indicating last/latest multimedia key state(true means key is pressed or else released).
    unsigned int down_mmcode;  // tracking last/latest multimedia key code being pressed.

    struct input_dev *input_touchpad;
    unsigned char data[22];   //len(1Byte)+key(1Byte)+fingers(20Byte). touch packet
    unsigned char  touch_down;
    unsigned char  touch_temp;
    struct touch_event event;

    struct input_dev *input_wakeup;

    struct notifier_block pogo_keyboard_notify;
    unsigned char write_buf[UART_BUFFER_SIZE];
    unsigned char read_buf[UART_BUFFER_SIZE];
    unsigned char write_check_buf[UART_BUFFER_SIZE];
    unsigned char recv_dma_buf[UART_BUFFER_SIZE];
    int recv_len;
    int recv_status;

    int read_flag;
    int read_len;

    int write_len;

    struct task_struct *pogo_keyboard_task;
    int flag;

    //int power_status;
    struct platform_device *plat_dev;
    struct pinctrl *pinctrl;
    struct pinctrl_state *uart_tx_set;
    struct pinctrl_state *uart_tx_clear;
    struct pinctrl_state *uart_rx_set;
    struct pinctrl_state *uart_rx_clear;
    struct pinctrl_state *uart_rx_gpio_pin;
    struct pinctrl_state *uart_wake_gpio_pin;
    struct pinctrl_state *uart_wake_clear;
    struct pinctrl_state *pogo_gpio_clear;
    struct pinctrl_state *pogo_power_enable;
    struct pinctrl_state *pogo_power_disable;
    //int status;
    struct regulator *vcc_reg;
    atomic_t vcc_on;
    int power_en_gpio;
    int plug_gpio;
    int plug_irq;

    int tx_gpio;
    int tx_en_gpio;

    int uart_rx_gpio;
    int uart_rx_gpio_irq;
    int uart_rx_mode;

    int uart_wake_gpio;
    int uart_wake_gpio_irq;

    int uart_tx_gpio;
    pogo_keyboard_callback_t call_back;
    struct mutex mutex;
    unsigned char pogo_keyboard_status;
    unsigned char pogo_keyboard_events;
    unsigned char new_event;

    struct file *file_client;
    struct uart_port *port;
    struct hrtimer plug_timer; // timer for first keyboard attachment detection after system init.
    struct hrtimer check_timer;// timer for monitoring keyboard heartbeat report periodically.
    bool is_resumed;
    int edge_count;
    int disconnect_count; // numbers of heartbeat packet for plug-out detection after keyboard initialization complete.
    int plug_in_count; // numbers of heartbeat packet for plug-out detection before keyboard initialization complete.

    struct drm_panel *active_panel;
    void *notifier_cookie;

    bool lcd_notify_reg;
    struct delayed_work lcd_notify_reg_work;
};


extern struct pogo_keyboard_data *pogo_keyboard_client;
extern char TAG[60];

void pogo_keyboard_show_buf(void *buf, int count);

int pogo_keyboard_input_init(void);
int pogo_keyboard_input_report(char *buf);
int pogo_keyboard_mm_input_report(char *buf);
int pogo_keyboard_input_power_key_report(void);
int pogo_keyboard_input_wakeup_init(void);

void pogo_keyboard_led_process(int code, int value);
void pogo_keyboard_led_report(int key_value);

int touchpad_input_init(void);
int touchpad_input_report(char *buf);

extern ssize_t pogo_tty_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos);



#endif
