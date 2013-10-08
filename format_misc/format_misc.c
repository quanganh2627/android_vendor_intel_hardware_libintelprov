/*
 * Copyright 2013 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <linux/hdreg.h>
#include <roots.h>
#include <mtdutils.h>
#include <cutils/properties.h>
#include <cutils/android_reboot.h>
#include "libc_logging.h"

#define USE_MISC_SIZE	1000

#define LOG_TAG "format_misc"

#define LOGI(format, ...) \
    __libc_format_log(ANDROID_LOG_INFO, LOG_TAG, (format), ##__VA_ARGS__ )
#define LOGE(format, ...) \
    __libc_format_log(ANDROID_LOG_ERROR, LOG_TAG, (format), ##__VA_ARGS__ )

/* Bootloader Message
 *
 * This structure describes the content of a block in flash
 * that is used for recovery and the bootloader to talk to
 * each other.
 *
 * The command field is updated by linux when it wants to
 * reboot into recovery or to update radio or bootloader firmware.
 * It is also updated by the bootloader when firmware update
 * is complete (to boot into recovery for any final cleanup)
 *
 * The status field is written by the bootloader after the
 * completion of an "update-radio" or "update-hboot" command.
 *
 * The recovery field is only written by linux and used
 * for the system to send a message to recovery or the
 * other way around.
 */
struct bootloader_message {
    char command[32];
    char status[32];
    char recovery[1024];
};

static int get_bootloader_message_mtd(struct bootloader_message *out, const Volume* v);
static int get_bootloader_message_block(struct bootloader_message *out, const Volume* v);
int get_bootloader_message(struct bootloader_message *out);

int get_bootloader_message(struct bootloader_message *out) {
    Volume* v = volume_for_path("/misc");
    if (v == NULL) {
      LOGE("Cannot load volume /misc!\n");
      return -1;
    }
    if (strcmp(v->fs_type, "mtd") == 0) {
        return get_bootloader_message_mtd(out, v);
    } else if (strcmp(v->fs_type, "emmc") == 0) {
        return get_bootloader_message_block(out, v);
    }
    LOGE("unknown misc partition fs_type \"%s\"\n", v->fs_type);
    return -1;
}


// ------------------------------
// for misc partitions on MTD
// ------------------------------

static const int MISC_PAGES = 3;         // number of pages to save
static const int MISC_COMMAND_PAGE = 1;  // bootloader command is this page

static int get_bootloader_message_mtd(struct bootloader_message *out,
                                      const Volume* v) {
    size_t write_size;
    mtd_scan_partitions();
    const MtdPartition *part = mtd_find_partition_by_name(v->device);
    if (part == NULL || mtd_partition_info(part, NULL, NULL, &write_size)) {
        LOGE("Can't find %s\n", v->device);
        return -1;
    }

    MtdReadContext *read = mtd_read_partition(part);
    if (read == NULL) {
        LOGE("Can't open %s\n(%s)\n", v->device, strerror(errno));
        return -1;
    }

    const ssize_t size = write_size * MISC_PAGES;
    char data[size];
    ssize_t r = mtd_read_data(read, data, size);
    if (r != size) LOGE("Can't read %s\n(%s)\n", v->device, strerror(errno));
    mtd_read_close(read);
    if (r != size) return -1;

    memcpy(out, &data[write_size * MISC_COMMAND_PAGE], sizeof(*out));
    return 0;
}

// ------------------------------------
// for misc partitions on block devices
// ------------------------------------

static void wait_for_device(const char* fn) {
    int tries = 0;
    int ret;
    struct stat buf;
    do {
        ++tries;
        ret = stat(fn, &buf);
        if (ret) {
            printf("stat %s try %d: %s\n", fn, tries, strerror(errno));
            sleep(1);
        }
    } while (ret && tries < 10);
    if (ret) {
        printf("failed to stat %s\n", fn);
    }
}

static int get_bootloader_message_block(struct bootloader_message *out,
                                        const Volume* v) {
    wait_for_device(v->device);
    FILE* f = fopen(v->device, "rb");
    if (f == NULL) {
        LOGE("Can't open %s\n(%s)\n", v->device, strerror(errno));
        return -1;
    }
    struct bootloader_message temp;
    int count = fread(&temp, sizeof(temp), 1, f);
    if (count != 1) {
        LOGE("Failed reading %s\n(%s)\n", v->device, strerror(errno));
        return -1;
    }
    if (fclose(f) != 0) {
        LOGE("Failed closing %s\n(%s)\n", v->device, strerror(errno));
        return -1;
    }
    memcpy(out, &temp, sizeof(temp));
    return 0;
}


int main(int argc, const char *argv[])
{
    struct bootloader_message boot;

    memset(&boot, 0, sizeof(boot));
    load_volume_table();
    get_bootloader_message(&boot);  // this may fail, leaving a zeroed structure

    if (strcmp(boot.command,"boot-recovery") == 0) {
		LOGI("Detect a recovery action was on going reboot in recovery to finish it\n");
		android_reboot(ANDROID_RB_RESTART2, 0, "recovery");
	} else {
		Volume* v;
		char bufToWrite[USE_MISC_SIZE] = { 0 };
		int i, f, ret;

		load_volume_table();
		v = volume_for_path("/misc");
		if (v == NULL) {
			LOGE("cannot get volume\n");
			return -1;
		}
		f = open(v->device, O_WRONLY);
		if (f < 0) {
			LOGE("cannot open device\n");
			return -1;
		}
		ret = write(f, bufToWrite, USE_MISC_SIZE);
		if (ret != USE_MISC_SIZE) {
			LOGE("cannot write full buffer\n");
			close(f);
			return -1;
		}
		if (close(f) != 0) {
			LOGE("cannot close file\n");
			return -1;
		}
	}
    return 0;
}




