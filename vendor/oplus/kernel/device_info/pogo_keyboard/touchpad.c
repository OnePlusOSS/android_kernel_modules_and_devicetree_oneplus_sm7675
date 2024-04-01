#include "pogo_keyboard.h"
#include <linux/input/mt.h>


int touchpad_input_report(char *buf){
    struct input_dev *input_dev = pogo_keyboard_client->input_touchpad;
    struct touch_event *event =  &pogo_keyboard_client->event;
    struct touch_event temp;
    char *data = pogo_keyboard_client->data;
    int i = 0, j = 0;
    int fingers = 0;
    int len = 0;
    int offset = 0;
    if(!buf){
        return -EINVAL;
    }
    if(!input_dev)
        return -EINVAL;

    len = 20; // max len of touch packet is 21 bytes but buf passed in excludes the first cmd byte.
    fingers = buf[len-2];//(buf[0] - 1)/5;
    //len = fingers * 5 + 2;
    if(!memcmp(data, buf, len)){
            kb_debug("%s %d data repeat,no do finger:%d len:%d!\n",__func__,__LINE__,fingers,len);
            return 0;
    }

    memset(&temp, 0 , sizeof(temp));
    memcpy(data, buf, len);
    temp.is_left =  data[len-1] & 0x01;//(data[0] & 0x04) >> 2;
    temp.is_right =  (data[len-1]>>1) & 0x01;//(data[1] & 0x08) >> 3;
    temp.area = 0x09;
    for(j = 0; j < fingers; j++){
        offset = 1 + 5 * j;
        temp.id = data[offset + 0]>>4 & 0xf;
        temp.is_down = data[offset+ 0]>>1 & 0x01;
        temp.x = data[offset+ 1] | data[offset+ 2]<<8;
        temp.y = data[offset+ 3] | data[offset+ 4]<<8;
        //temp.x = temp.x * TOUCH_X_MAX / 2560;
        //temp.y = temp.y * TOUCH_Y_MAX / 1536;

        kb_debug("%s %d id:%d,down:%d,left:%d,right:%d,x:%d,y:%d,area:%d offset:%d\n",
        __func__,__LINE__,temp.id,temp.is_down,temp.is_left,temp.is_right,temp.x,temp.y,temp.area,offset);
        input_mt_slot(input_dev, temp.id);
        if(temp.is_down){
            input_mt_report_slot_state(input_dev, MT_TOOL_FINGER, true);
            //input_report_key(input_dev, BTN_TOOL_FINGER, 1);
            pogo_keyboard_client->touch_down |= BIT(temp.id);
            pogo_keyboard_client->touch_temp |= BIT(temp.id);
#ifdef CONFIG_TOUCH_SCREEN
            input_report_abs(input_dev, ABS_MT_POSITION_X, temp.y * TOUCH_X_MAX / KEYBOARD_TOUCH_Y_MAX);
            input_report_abs(input_dev, ABS_MT_POSITION_Y, temp.x * TOUCH_Y_MAX / KEYBOARD_TOUCH_X_MAX);
#else
            input_report_abs(input_dev, ABS_MT_POSITION_X, temp.x);
            input_report_abs(input_dev, ABS_MT_POSITION_Y, TOUCH_Y_MAX-temp.y);
#endif
            input_report_key(input_dev, BTN_TOUCH, 1);
			pogo_keyboard_input_power_key_report();
            kb_debug("%s %d finger down\n",__func__,__LINE__);

        }else{
            input_mt_report_slot_state(input_dev, MT_TOOL_FINGER, false);
            //input_report_key(input_dev, BTN_TOOL_FINGER, 0);
            pogo_keyboard_client->touch_down &= ~BIT(temp.id);
            if(unlikely(pogo_keyboard_client->touch_down ^ pogo_keyboard_client->touch_temp)){
                for(i = 0; i < TOUCH_FINGER_MAX; i++){
                    if (BIT(i) & (pogo_keyboard_client->touch_down ^ pogo_keyboard_client->touch_temp)) {  //finger change
                        input_mt_slot(input_dev, i);
                        input_mt_report_slot_state(input_dev, MT_TOOL_FINGER, false);

                        kb_debug("%s %d finger change id:%d\n",__func__,__LINE__,i);
                    }
                }
            }

            if(!pogo_keyboard_client->touch_down){    //finger all up
                input_report_key(input_dev, BTN_TOUCH, 0);
                pogo_keyboard_client->touch_temp = 0;
                pogo_keyboard_client->touch_down = 0;
                kb_debug("%s %d finger all up\n",__func__,__LINE__);
            }
            kb_debug("%s %d finger up\n",__func__,__LINE__);
        }
        if(j == fingers - 1){
            if(temp.is_left){
                event->is_left = temp.is_left;
                input_report_key(input_dev, BTN_MOUSE, temp.is_left);
            }
            if(temp.is_right){
                event->is_right = temp.is_right;
                input_report_key(input_dev, BTN_RIGHT, temp.is_right);
            }
            if(event->is_left && temp.is_left == 0){
                event->is_left = temp.is_left;
                input_report_key(input_dev, BTN_MOUSE, temp.is_left);
            }
            if(event->is_right && temp.is_right == 0){
                temp.is_right = temp.is_right;
                input_report_key(input_dev, BTN_RIGHT, temp.is_right);
            }
        }
        input_sync(input_dev);
        kb_debug("%s %d input end\n",__func__,__LINE__);
    }

    return 0;
}

int touchpad_input_init(void)
{
    int ret = 0;
    struct input_dev *input_dev = input_allocate_device();
    if(!input_dev){
    	input_free_device(input_dev);
        kb_err("%s %d input_allocate_device err\n",__func__,__LINE__);
        return -ENOMEM;
    }
    input_dev->name = TOUCHPAD_NAME;
    input_dev->id.bustype = BUS_HOST;
    input_dev->id.product = 0x8001;
    input_dev->id.vendor = 0x8286;
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

    input_set_abs_params(input_dev, ABS_MT_POSITION_X, 0, TOUCH_X_MAX, 0, 0);
    input_set_abs_params(input_dev, ABS_MT_POSITION_Y, 0, TOUCH_Y_MAX, 0, 0);
    input_set_abs_params(input_dev, ABS_X, 0, TOUCH_X_MAX, 0, 0);
    input_set_abs_params(input_dev, ABS_Y, 0, TOUCH_Y_MAX, 0, 0);
    input_set_abs_params(input_dev, ABS_MT_TOUCH_MAJOR, 0, 100, 0, 0);
    input_set_abs_params(input_dev, ABS_MT_TOUCH_MINOR, 0, 100, 0, 0);
    input_set_abs_params(input_dev, ABS_X, 0, TOUCH_X_MAX, 0, 0);
    input_set_abs_params(input_dev, ABS_Y, 0, TOUCH_Y_MAX, 0, 0);
    input_abs_set_res(input_dev, ABS_X, TOUCH_X_MAX);
    input_abs_set_res(input_dev, ABS_Y, TOUCH_Y_MAX);
    input_set_abs_params(input_dev, ABS_PRESSURE, 0, 255, 0, 0);
    input_set_abs_params(input_dev, ABS_MT_TRACKING_ID, 65535, 0, 0, 0);

#ifdef CONFIG_TOUCH_SCREEN
    set_bit(INPUT_PROP_DIRECT, input_dev->propbit);
    set_bit(INPUT_PROP_POINTER, input_dev->propbit);
#endif
    set_bit(INPUT_PROP_BUTTONPAD, input_dev->propbit);
    input_mt_init_slots(input_dev, 0x03,INPUT_MT_POINTER);

    ret = input_register_device(input_dev);
    if(ret){
        input_free_device(input_dev);
        kb_err("%s %d input_register_device err\n",__func__,__LINE__);
        return ret;
    }
    pogo_keyboard_client->input_touchpad = input_dev;
    kb_debug("%s %d ok\n",__func__,__LINE__);
    return 0;
}
