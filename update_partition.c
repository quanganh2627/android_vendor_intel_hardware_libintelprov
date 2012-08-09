/*
 * Copyright (C) 2007 The Android Open Source Project
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

#define _LARGEFILE64_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include "util.h"

#include "droidboot.h"
#include "droidboot_ui.h"
#include "update_partition.h"

int nuke_volume(const char* volume, long int bufferSize)
{
    Volume* v = volume_for_path(volume);
    int fd, count, count_w, offset;
    char *pbuf = NULL, *pbufRead = NULL;
    long int ret, retval;
    long long size;

    if (v == NULL) {
        pr_error("unknown volume \"%s\"\n", volume);
        return -1;
    }
    if (strcmp(v->fs_type, "ramdisk") == 0) {
        // you can't format the ramdisk.
        pr_error("can't nuke_volume ramdisk volume: \"%s\"\n", volume);
        return -1;
    }
    if (strcmp(v->mount_point, volume) != 0) {
        pr_error("can't give path \"%s\" to nuke_volume\n", volume);
        return -1;
    }

    if (ensure_path_unmounted(volume) != 0) {
        pr_error("nuke_volume failed to unmount \"%s\"\n", v->mount_point);
        return -1;
    }

    fd = open(v->device, O_RDWR);
    if (fd == -1) {
        pr_error("nuke_volume failed to open for writing \"%s\"\n", v->device);
        return -1;
    }

    pbuf = (char *)malloc(bufferSize);
    if (pbuf == NULL){
        pr_error("nuke_volume: malloc pbuf failed\n");
        ret = -1;
        goto end3;
    }

    pbufRead = (char *)malloc(bufferSize);
    if (pbufRead == NULL){
        pr_error("nuke_volume: malloc pbufRead failed\n");
        ret = -1;
        goto end2;
    }

    memset(pbuf, 0xFF, bufferSize*sizeof(char));

    size = lseek64(fd, 0, SEEK_END);

    if(size == -1) {
        pr_error("nuke_volume: lseek64 fd failed\n");
        ret = -1;
        goto end1;
    }

    offset = lseek(fd, 0, SEEK_SET);

    if (offset == -1) {
            pr_error("nuke_volume: lseek fd failed");
            ret = -1;
            goto end1;
    }

    ui_print("erasing volume \"%s\", size=%lld...\n", volume, size);

    //now blast the device with F's until we hit the end.
    count = 0;
    do {
        ret = write(fd, pbuf, bufferSize);

        if (ret == -1) {
            pr_error("nuke_volume: failed to write file");
            goto end1;
        }

        count++;
    } while (ret == bufferSize);

    pr_info("wrote ret %ld, count %d,  \"%s\"\n",ret, count, v->device);

    //now do readback check that data is as expected
    offset = lseek(fd, 0, SEEK_SET);

    if (offset == -1) {
            pr_error("nuke_volume: lseek check data failed");
            goto end1;
    }

    count_w = count;
    count = 0;
    do {
        ret = read(fd, pbufRead, bufferSize);

        if (ret <= 0) {
            pr_error("nuke_volume: failed to read data");
            goto end1;
        }

        retval = memcmp(pbuf, pbufRead,  bufferSize);
        count++;
        if (retval != 0) {
            pr_error("nuke_volume failed read back check!! \"%s\"\n",
                                    v->device);
            ret = -1;
            goto end1;
        }
    } while (ret == bufferSize);

    if (count != count_w){
      pr_error("nuke_volume: failed read back check, bad count %d\n", count);
      ret = -1;
      goto end1;
    }

    pr_info("read back ret %ld, count %d \"%s\"\n",ret, count, v->device);
    ret = 0;

end1:
    free(pbufRead);
end2:
    free(pbuf);
end3:
    sync();
    close(fd);
    pbuf = NULL;
    pbufRead = NULL;
    return ret;
}

