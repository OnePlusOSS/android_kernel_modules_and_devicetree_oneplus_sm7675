#include "pogo_keyboard.h"
#include <linux/input/mt.h>


void reset_tool_buttons(struct input_dev *input_dev)
{
    input_report_key(input_dev, BTN_TOOL_FINGER, 0);
    input_report_key(input_dev, BTN_TOOL_DOUBLETAP, 0);
    input_report_key(input_dev, BTN_TOOL_TRIPLETAP, 0);
    input_report_key(input_dev, BTN_TOOL_QUADTAP, 0);
    input_report_key(input_dev, BTN_TOOL_QUINTTAP, 0);
}

static void report_tool_button(struct input_dev *input_dev, int finger_count)
{
    switch (finger_count) {
        case 1:
            input_report_key(input_dev, BTN_TOOL_FINGER, 1);
            kb_debug("%s %d 1-finger detected\n", __func__, __LINE__);
            break;
        case 2:
            input_report_key(input_dev, BTN_TOOL_DOUBLETAP, 1);
            kb_debug("%s %d 2-finger gesture detected\n", __func__, __LINE__);
            break;
        case 3:
            input_report_key(input_dev, BTN_TOOL_TRIPLETAP, 1);
            kb_debug("%s %d 3-finger gesture detected\n", __func__, __LINE__);
            break;
        case 4:
            input_report_key(input_dev, BTN_TOOL_QUADTAP, 1);
            kb_debug("%s %d 4-finger gesture detected\n", __func__, __LINE__);
            break;
        case 5:
            input_report_key(input_dev, BTN_TOOL_QUINTTAP, 1);
            kb_debug("%s %d 5-finger gesture detected\n", __func__, __LINE__);
            break;
        default:
            break;
    }
}

static void process_button_events(struct input_dev *input_dev,
                               struct touch_event *event,
                               struct touch_event *temp)
{
    /* left button */
    if (temp->is_left || (event->is_left && !temp->is_left)) {
        event->is_left = temp->is_left;
        input_report_key(input_dev, BTN_MOUSE, temp->is_left);
    }

    /* right button */
    if (temp->is_right || (event->is_right && !temp->is_right)) {
        event->is_right = temp->is_right;
        input_report_key(input_dev, BTN_RIGHT, temp->is_right);
    }
}

int touchpad_input_report(char *buf)
{
    struct input_dev *input_dev = pogo_keyboard_client->input_touchpad;
    struct touch_event *event = &pogo_keyboard_client->event;
    struct touch_event temp;
    char *data = pogo_keyboard_client->touchpad_data;
    int i = 0, j = 0;
    int fingers = 0;
    int len = 0;
    int offset = 0;
    unsigned char palm = 0;
    unsigned int xarea = 0;

    int finger_count = 0;

    if (!buf || !input_dev) {
        return -EINVAL;
    }

    len = buf[0];
    fingers = buf[len - 1];

    if(len > sizeof(pogo_keyboard_client->touchpad_data)) {
        kb_err("%s %d data overflow\n", __func__, __LINE__);
        return 0;
    }
    if ((!memcmp(data, &buf[1], fingers * 5)) && (!memcmp(&data[len - 1], &buf[len], 1))) {
        //kb_debug("%s %d data repeat, len:%d\n", __func__, __LINE__, len);
        return 0;
    }

    memset(&temp, 0, sizeof(temp));
    memcpy(data, &buf[1], len);
    temp.is_left = data[len - 1] & 0x01;
    temp.is_right = (data[len - 1] >> 1) & 0x01;

    for (j = 0; j < fingers; j++) {
        offset = 5 * j;
        temp.id = data[offset + 0] >> 4 & 0xf;
        temp.is_down = data[offset + 0] >> 1 & 0x01;
        palm = data[offset + 0] & 0x03;
        temp.x = data[offset + 1] | data[offset + 2] << 8;
        temp.y = data[offset + 3] | data[offset + 4] << 8;
        xarea = pogo_keyboard_client->touchpad_x_max / 3;
        temp.area = (temp.x > xarea && temp.x < 2 * xarea) ? 1 : 0;

        kb_debug("%s %d id:%d, down:%d, left:%d, right:%d, x:%d, y:%d, palm:%d, %s\n",
            __func__, __LINE__, temp.id, temp.is_down, temp.is_left, temp.is_right,
            temp.x, temp.y, palm, (temp.area == 1) ? "B" : "A");

        input_mt_slot(input_dev, temp.id);
        if (temp.is_down) {
            input_mt_report_slot_state(input_dev, MT_TOOL_FINGER, true);
            input_report_key(input_dev, BTN_TOUCH, 1);
            pogo_keyboard_client->touch_down |= BIT(temp.id);
            pogo_keyboard_client->touch_temp |= BIT(temp.id);
            input_report_abs(input_dev, ABS_MT_POSITION_X, temp.x);
            input_report_abs(input_dev, ABS_MT_POSITION_Y, temp.y);
            finger_count++;
            //kb_debug("%s %d finger down\n", __func__, __LINE__);
        } else {
            input_mt_report_slot_state(input_dev, MT_TOOL_FINGER, false);
            pogo_keyboard_client->touch_down &= ~BIT(temp.id);
            if (unlikely(pogo_keyboard_client->touch_down ^ pogo_keyboard_client->touch_temp)) {
                for (i = 0; i < TOUCH_FINGER_MAX; i++) {
                    if (BIT(i) & (pogo_keyboard_client->touch_down ^ pogo_keyboard_client->touch_temp)) {  //finger change
                        input_mt_slot(input_dev, i);
                        input_mt_report_slot_state(input_dev, MT_TOOL_FINGER, false);

                        kb_debug("%s %d finger change id:%d\n", __func__, __LINE__, i);
                    }
                }
            }

            if (!pogo_keyboard_client->touch_down) {    //finger all up
                input_report_key(input_dev, BTN_TOUCH, 0);
                reset_tool_buttons(input_dev);
                pogo_keyboard_client->touch_temp = 0;
                pogo_keyboard_client->touch_down = 0;
                pogo_keyboard_client->prev_finger_count = 0;
                kb_debug("%s %d finger all up, finger%d\n", __func__, __LINE__, j);
                goto sync_report;
            }
            //kb_debug("%s %d finger up\n", __func__, __LINE__);
        }
    }
    if (pogo_keyboard_client->prev_finger_count != finger_count) {
        reset_tool_buttons(input_dev);
        pogo_keyboard_client->prev_finger_count = finger_count;
        report_tool_button(input_dev, pogo_keyboard_client->prev_finger_count);
    }

sync_report:
    if (fingers > 0) {
        process_button_events(input_dev, event, &temp);
    }
    input_sync(input_dev);
    //kb_debug("%s %d input end\n", __func__, __LINE__);

    return 0;
}

int touchpad_input_init(void)
{
    int ret = 0;
    struct input_dev *input_dev = input_allocate_device();

    if (pogo_keyboard_client == NULL) {
        kb_err("%s %d pogo_keyboard_client is null!!!\n", __func__, __LINE__);
        return -EINVAL;
    }

    if (!input_dev) {
        kb_err("%s %d input_allocate_device err\n", __func__, __LINE__);
        return -ENOMEM;
    }
    input_dev->name = TOUCHPAD_NAME;
    input_dev->phys = TOUCHPAD_NAME"_phys";
    input_dev->id.bustype = BUS_HOST;
    input_dev->id.vendor = 0x22d9;
    input_dev->id.product = 0x3869;
    input_dev->id.product =
            pogo_keyboard_client->pogo_id_product? pogo_keyboard_client->pogo_id_product : 0x3869;
    input_dev->id.version = 0x0010;

    set_bit(EV_ABS, input_dev->evbit);
    set_bit(EV_KEY, input_dev->evbit);
    set_bit(ABS_X, input_dev->absbit);
    set_bit(ABS_Y, input_dev->absbit);
    set_bit(ABS_PRESSURE, input_dev->absbit);
    set_bit(BTN_TOUCH, input_dev->keybit);

    set_bit(ABS_MT_TRACKING_ID, input_dev->absbit);
    set_bit(ABS_MT_TOUCH_MAJOR, input_dev->absbit);
    set_bit(ABS_MT_TOUCH_MINOR, input_dev->absbit);
    set_bit(ABS_MT_POSITION_X, input_dev->absbit);
    set_bit(ABS_MT_POSITION_Y, input_dev->absbit);


    set_bit(BTN_MOUSE, input_dev->keybit);
    set_bit(BTN_RIGHT, input_dev->keybit);
    set_bit(BTN_TOOL_FINGER, input_dev->keybit);

    if (pogo_keyboard_client->touchpad_x_max == 0 || pogo_keyboard_client->touchpad_y_max == 0) {
        pogo_keyboard_client->touchpad_x_max = TOUCH_X_MAX;
        pogo_keyboard_client->touchpad_y_max = TOUCH_Y_MAX;
    }

    input_set_abs_params(input_dev, ABS_MT_POSITION_X, 0, pogo_keyboard_client->touchpad_x_max, 0, 0);
    input_set_abs_params(input_dev, ABS_MT_POSITION_Y, 0, pogo_keyboard_client->touchpad_y_max, 0, 0);
    input_set_abs_params(input_dev, ABS_X, 0, pogo_keyboard_client->touchpad_x_max, 0, 0);
    input_set_abs_params(input_dev, ABS_Y, 0, pogo_keyboard_client->touchpad_y_max, 0, 0);
    input_set_abs_params(input_dev, ABS_MT_TOUCH_MAJOR, 0, 100, 0, 0);
    input_set_abs_params(input_dev, ABS_MT_TOUCH_MINOR, 0, 100, 0, 0);
    input_abs_set_res(input_dev, ABS_X, pogo_keyboard_client->touchpad_x_max);
    input_abs_set_res(input_dev, ABS_Y, pogo_keyboard_client->touchpad_y_max);
    input_set_abs_params(input_dev, ABS_PRESSURE, 0, 255, 0, 0);
    input_set_abs_params(input_dev, ABS_MT_TRACKING_ID, 65535, 0, 0, 0);

    input_dev->absinfo[ABS_MT_POSITION_X].resolution = pogo_keyboard_client->touchpad_x_resolution;
    input_dev->absinfo[ABS_MT_POSITION_Y].resolution = pogo_keyboard_client->touchpad_y_resolution;
#ifdef CONFIG_TOUCH_SCREEN
    set_bit(INPUT_PROP_DIRECT, input_dev->propbit);
#endif
    set_bit(INPUT_PROP_POINTER, input_dev->propbit);
    set_bit(INPUT_PROP_BUTTONPAD, input_dev->propbit);
    input_mt_init_slots(input_dev, TOUCH_FINGER_MAX, INPUT_MT_POINTER);

    ret = input_register_device(input_dev);
    if (ret) {
        input_free_device(input_dev);
        kb_err("%s %d input_register_device err\n", __func__, __LINE__);
        return ret;
    }
    pogo_keyboard_client->input_touchpad = input_dev;
    kb_debug("%s %d ok\n", __func__, __LINE__);
    return 0;
}
