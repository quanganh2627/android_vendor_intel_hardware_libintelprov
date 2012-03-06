/*
 * Copyright (C) 2009 The Android Open Source Project
 * Copyright (C) 2011 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <linux/input.h>
#include <cutils/klog.h>
#include <cutils/android_reboot.h>
#include <charger/charger.h>

#include "recovery_ui.h"
#include "common.h"

#define MSEC_PER_SEC            (1000LL)
#define MIN_BATTERY_LEVEL       8
#define BATTERY_UNKNOWN_TIME    (2 * MSEC_PER_SEC)
#define POWER_ON_KEY_TIME       (2 * MSEC_PER_SEC)
#define UNPLUGGED_SHUTDOWN_TIME (30 * MSEC_PER_SEC)
#define CAPACITY_POLL_INTERVAL  (30 * MSEC_PER_SEC)

char* MENU_HEADERS[] = { "Android system recovery utility",
                         "Use volume down to navigate, volume up to select",
                         "",
                         NULL };

char* MENU_ITEMS[] = { "reboot system now",
                       "apply update from external storage",
                       "wipe data/factory reset",
                       "wipe cache partition",
                       NULL };

/* MFLD key binds
 * Vol+     KEY_VOLUMEUP
 * Vol-     KEY_VOLUMEDOWN
 * Power    KEY_POWER
 */

void device_ui_init(UIParameters* ui_parameters) {
    LOGI("Verifying battery level >= %d%% before continuing\n",
            MIN_BATTERY_LEVEL);
    klog_init();
    gr_init();
    klog_set_level(8);

    switch (charger_run(MIN_BATTERY_LEVEL, POWER_ON_KEY_TIME,
                            BATTERY_UNKNOWN_TIME,
                            UNPLUGGED_SHUTDOWN_TIME,
                            CAPACITY_POLL_INTERVAL)) {
    case CHARGER_SHUTDOWN:
        android_reboot(ANDROID_RB_POWEROFF, 0, 0);
        break;
    case CHARGER_PROCEED:
        LOGI("Battery level is acceptable\n");
        break;
    default:
        LOGE("mysterious return value from charger_run()\n");
    }
    gr_exit();
}

int device_recovery_start() {
    return 0;
}

int device_toggle_display(volatile char* key_pressed, int key_code) {
    return key_code == KEY_POWER;
}

int device_reboot_now(volatile char* key_pressed, int key_code) {
    return 0;
}

int device_handle_key(int key_code, int visible) {
    if (visible) {
        switch (key_code) {
            case KEY_VOLUMEDOWN:
                return HIGHLIGHT_DOWN;

            case KEY_VOLUMEUP:
                return SELECT_ITEM;
        }
    }
    return NO_ACTION;
}

int device_perform_action(int which) {
    return which;
}

int device_wipe_data() {
    return 0;
}
