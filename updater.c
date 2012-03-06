/*
 * Copyright 2011 Intel Corporation
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


#include <stdio.h>

#include <edify/expr.h>

#include "update_osip.h"
#include "util.h"
#include "modem_fw.h"
#include "fw_version_check.h"
#include "flash_ifwi.h"

Value *ExtractOsipFn(const char *name, State *state, int argc, Expr *argv[]) {
    Value *ret = NULL;
    char *filename = NULL;
    char *source = NULL;
    int osii_index;
    void *data = NULL;
    size_t size;

    if (ReadArgs(state, argv, 2, &filename, &source) < 0) {
        return NULL;
    }

    if (strlen(filename) == 0) {
        ErrorAbort(state, "filename argument to %s can't be empty", name);
        goto done;
    }

    if (strlen(source) == 0) {
        ErrorAbort(state, "source argument to %s can't be empty", name);
        goto done;
    }

    osii_index = get_named_osii_index(source);
    if (osii_index < 0) {
        ErrorAbort(state, "Can't get OSII index for %s", source);
        goto done;
    }

    if (read_osimage_data(&data, &size, osii_index) < 0) {
        ErrorAbort(state, "Couldn't read osip[%d]", osii_index);
        goto done;
    }

    if (file_write(filename, data, size) < 0) {
        ErrorAbort(state, "Couldn't write osii[%d] data to %s", osii_index,
                filename);
        goto done;
    }

    ret = StringValue(strdup(""));
done:
    if (source)
        free(source);
    if (filename)
        free(filename);
    if (data)
        free(data);

    return ret;
}

Value *FlashOsipFn(const char *name, State *state, int argc, Expr *argv[]) {
    Value *ret = NULL;
    char *filename = NULL;
    char *destination = NULL;
    int osii_index;
    void *image_data = NULL;
    size_t image_size;

    if (ReadArgs(state, argv, 2, &filename, &destination) < 0) {
        return NULL;
    }

    if (strlen(filename) == 0) {
        ErrorAbort(state, "filename argument to %s can't be empty", name);
        goto done;
    }

    if (strlen(destination) == 0) {
        ErrorAbort(state, "destination argument to %s can't be empty", name);
        goto done;
    }

    if (file_read(filename, &image_data, &image_size)) {
        ErrorAbort(state, "Cannot open os image %s", filename);
        goto done;
    }

    osii_index = get_named_osii_index(destination);

    if (osii_index < 0) {
        ErrorAbort(state, "Can't get OSII index for %s", destination);
        goto done;
    }

    if (write_stitch_image(image_data, image_size, osii_index)) {
        ErrorAbort(state, "Error writing %s image %s to OSIP%d",
                destination, filename, osii_index);
        goto done;
    }

    ret = StringValue(strdup(""));
done:
    if (image_data)
        free(image_data);
    if (destination)
        free(destination);
    if (filename)
        free(filename);

    return ret;
}

Value *FlashIfwiFn(const char *name, State *state, int argc, Expr *argv[]) {
    Value *ret = NULL;
    char *filename = NULL;
    struct firmware_versions cur_fw_rev;
    struct firmware_versions img_fw_rev;
    void *data = NULL;
    size_t size;

    if (ReadArgs(state, argv, 1, &filename) < 0) {
        return NULL;
    }

    if (strlen(filename) == 0) {
        ErrorAbort(state, "filename argument to %s can't be empty", name);
        goto done;
    }

    if (get_current_fw_rev(&cur_fw_rev)) {
        ErrorAbort(state,"Can't query kernel for current FW version");
        goto done;
    }

    if (file_read(filename, &data, &size)) {
        ErrorAbort(state, "Couldn't read firmware image!");
        goto done;
    }

    if (get_image_fw_rev(data, size, &img_fw_rev)) {
        ErrorAbort(state, "Coudn't extract FW version data from image");
        goto done;
    }

    printf("Current FW versions:\n");
    dump_fw_versions(&cur_fw_rev);

    if (fw_vercmp(&cur_fw_rev, &img_fw_rev)) {
        /* Apply the update, versions are different */
        printf("Image FW versions:\n");
        dump_fw_versions(&img_fw_rev);
        if (update_ifwi_image(data, size, 0)) {
            ErrorAbort(state, "IFWI update failed!");
            goto done;
        }
    } else
        printf("Firmware versions are identical, skipping\n");

    ret = StringValue(strdup(""));
done:
    if (filename)
        free(filename);
    if (data)
        free(data);

    return ret;
}

#if 0
static void progress_callback(enum cmfwdl_status_type type, int value,
        const char *msg, void *data)
{
    static int last_update_progress = -1;

    switch (type) {
    case cmfwdl_status_booting:
        printf("modem: Booting...\n");
        last_update_progress = -1;
        break;
    case cmfwdl_status_synced:
        printf("modem: Device Synchronized\n");
        last_update_progress = -1;
        break;
    case cmfwdl_status_downloading:
        printf("modem: Loading Component %s\n", msg);
        last_update_progress = -1;
        break;
    case cmfwdl_status_msg_detail:
        printf("modem: %s\n", msg);
        last_update_progress = -1;
        break;
    case cmfwdl_status_error_detail:
        printf("modem: ERROR: %s\n", msg);
        last_update_progress = -1;
        break;
    case cmfwdl_status_progress:
        if (value / 10 == last_update_progress)
            break;
        last_update_progress = value / 10;
        printf("modem: update progress %d%%\n", last_update_progress);
        break;
    case cmfwdl_status_version:
        printf("modem: Version: %s\n", msg);
        break;
    default:
        printf("modem: Ignoring: %s\n", msg);
        break;
    }
}
#endif

Value *FlashModemFn(const char *name, State *state, int argc, Expr *argv[]) {
    Value *ret = NULL;
    char *filename = NULL;

    if (ReadArgs(state, argv, 1, &filename) < 0) {
        return NULL;
    }

    if (strlen(filename) == 0) {
        ErrorAbort(state, "filename argument to %s can't be empty", name);
        goto done;
    }

#if 0
    if (flash_modem_fw(filename, progress_callback)) {
        ErrorAbort(state, "Failed to flash 3G firmware!");
        goto done;
    }
#else
    printf("3G Modem flashing STUB!\n");
#endif

    ret = StringValue(strdup(""));
done:
    if (filename)
        free(filename);

    return ret;
}

void Register_libmedfield_recovery(void)
{
    RegisterFunction("flash_osip", FlashOsipFn);
    RegisterFunction("flash_ifwi", FlashIfwiFn);
    RegisterFunction("flash_modem", FlashModemFn);
    RegisterFunction("extract_osip", ExtractOsipFn);
}
