/* Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>

#include "cgpt.h"
#include "cmd_show.h"
#include "cgpt_params.h"



#define BASE_BLOCK "/dev/block/"
#define BASE_EMMC BASE_BLOCK "mmcblk0"
#define BASE_PLATFORM BASE_BLOCK "platform"
#define BASE_PLATFORM_INTEL BASE_PLATFORM "/intel"
#define BASE_PLATFORM_INTEL_UUID BASE_PLATFORM_INTEL "/by-uuid"
#define BASE_PLATFORM_INTEL_LABEL BASE_PLATFORM_INTEL "/by-label"

int main(int argc, char *argv[]) {

    CgptShowParams params;
    GptEntry *entry;

    struct drive drive;
    int gpt_retval;
    int retval;
    uint32_t i;
    uint8_t label[GPT_PARTNAME_LEN];
    char  uuid[GUID_STRLEN];

    char from[sizeof(BASE_EMMC) + 3];
    char to[sizeof(BASE_PLATFORM_INTEL_LABEL) + GUID_STRLEN + 3];

    memset(&params, 0, sizeof(params));
    params.drive_name = BASE_EMMC;

    mkdir(BASE_PLATFORM, 0600);
    mkdir(BASE_PLATFORM_INTEL,0600);
    mkdir(BASE_PLATFORM_INTEL_UUID, 0600);
    mkdir(BASE_PLATFORM_INTEL_LABEL, 0600);

    if (CGPT_OK != DriveOpen(params.drive_name, &drive, O_RDONLY))
        return CGPT_FAILED;

    if (GPT_SUCCESS != (gpt_retval = GptSanityCheck(&drive.gpt))) {
        goto error;
    }

    for (i = 0; i < GetNumberOfEntries(&drive.gpt); ++i) {
        entry = GetEntry(&drive.gpt, ANY_VALID, i);

        if (IsZero(&entry->type))
            continue;

        UTF16ToUTF8(entry->name, sizeof(entry->name) / sizeof(entry->name[0]),
                label, sizeof(label));

        GuidToStr(&entry->unique, uuid, GUID_STRLEN);

        snprintf(from, sizeof(from) - 1, "%sp%d", BASE_EMMC, i + 1);

        snprintf(to,sizeof(to) - 1 , BASE_PLATFORM_INTEL_LABEL "/%s" , label);
        link(from, to);

        snprintf(to,sizeof(to) - 1 , BASE_PLATFORM_INTEL_UUID "/%s" , uuid);
        link(from, to);

    }

error:
    DriveClose(&drive, 0);

    return 0;
}
