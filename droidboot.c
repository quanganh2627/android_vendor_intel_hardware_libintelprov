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
#include <cmfwdl.h>
#include <droidboot.h>
#include <droidboot_plugin.h>
#include <droidboot_fstab.h>
#include <droidboot_util.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "update_osip.h"
#include "util.h"
#include "modem_fw.h"
#include "fw_version_check.h"
#include "flash_ifwi.h"

#define MODEM_TEMP_FILE		"/modemfw.bin"

static void progress_callback(enum cmfwdl_status_type type, int value,
		const char *msg, void *data)
{
	static int last_update_progress = -1;

	switch (type) {
	case cmfwdl_status_booting:
		pr_debug("modem: Booting...");
		last_update_progress = -1;
		break;
	case cmfwdl_status_synced:
		pr_info("modem: Device Synchronized");
		last_update_progress = -1;
		break;
	case cmfwdl_status_downloading:
		pr_info("modem: Loading Component %s", msg);
		last_update_progress = -1;
		break;
	case cmfwdl_status_msg_detail:
		pr_info("modem: %s", msg);
		last_update_progress = -1;
		break;
	case cmfwdl_status_error_detail:
		pr_error("modem: ERROR: %s", msg);
		last_update_progress = -1;
		break;
	case cmfwdl_status_progress:
		if (value / 10 == last_update_progress)
			break;
		last_update_progress = value / 10;
		pr_info("modem: update progress %d%%", last_update_progress);
		break;
	case cmfwdl_status_version:
		pr_info("modem: Version: %s", msg);
		break;
	default:
		pr_info("modem: Ignoring: %s", msg);
		break;
	}
}

static int flash_image(void *data, unsigned sz, int index)
{
	if (index < 0) {
		pr_error("Can't find OSII index!!");
		return -1;
	}
	return write_stitch_image(data, sz, index);
}

static int flash_android_kernel(void *data, unsigned sz)
{
	return flash_image(data, sz, get_named_osii_index(ANDROID_OS_NAME));
}

static int flash_recovery_kernel(void *data, unsigned sz)
{
	return flash_image(data, sz, get_named_osii_index(RECOVERY_OS_NAME));
}

static int flash_fastboot_kernel(void *data, unsigned sz)
{
	return flash_image(data, sz, get_named_osii_index(FASTBOOT_OS_NAME));
}

static int flash_uefi_firmware(void *data, unsigned sz)
{
	return flash_image(data, sz, get_named_osii_index(UEFI_FW_NAME));
}

static int flash_modem(void *data, unsigned sz)
{
	int ret;

	if (file_write(MODEM_TEMP_FILE, data, sz)) {
		pr_error("Couldn't write modem fw to %s", MODEM_TEMP_FILE);
		return -1;
	}
	ret = flash_modem_fw(MODEM_TEMP_FILE, progress_callback);
	unlink(MODEM_TEMP_FILE);
	return ret;
}

#define BIN_DNX  "/tmp/__dnx.bin"
#define BIN_IFWI "/tmp/__ifwi.bin"

static int flash_dnx(void *data, unsigned sz)
{
	if (file_write(BIN_DNX, data, sz)) {
		pr_error("Couldn't write dnx file to %s\n", BIN_DNX);
		return -1;
	}

	return 0;
}

static int flash_ifwi(void *data, unsigned sz)
{
	struct firmware_versions img_fw_rev;


	if (access(BIN_DNX, F_OK)) {
		pr_error("dnx binary must be flashed to board first\n");
		return -1;
	}

	if (get_image_fw_rev(data, sz, &img_fw_rev)) {
		pr_error("Coudn't extract FW version data from image");
		return -1;
	}

	printf("Image FW versions:\n");
	dump_fw_versions(&img_fw_rev);

	if (file_write(BIN_IFWI, data, sz)) {
		pr_error("Couldn't write ifwi file to %s\n", BIN_IFWI);
		return -1;
	}

	if (update_ifwi_file(BIN_DNX, BIN_IFWI)) {
		pr_error("IFWI flashing failed!");
		return -1;
	}
	return 0;
}

void libintel_droidboot_init(void)
{
	int ret = 0;
	struct OSIP_header osip;
	struct firmware_versions cur_fw_rev;

	ret |= aboot_register_flash_cmd(ANDROID_OS_NAME, flash_android_kernel);
	ret |= aboot_register_flash_cmd(RECOVERY_OS_NAME, flash_recovery_kernel);
	ret |= aboot_register_flash_cmd(FASTBOOT_OS_NAME, flash_fastboot_kernel);
	ret |= aboot_register_flash_cmd(UEFI_FW_NAME, flash_uefi_firmware);
	ret |= aboot_register_flash_cmd("radio", flash_modem);
	ret |= aboot_register_flash_cmd("dnx", flash_dnx);
	ret |= aboot_register_flash_cmd("ifwi", flash_ifwi);

	if (ret)
		die();

	/* Dump the OSIP to serial to assist debugging */
	if (read_OSIP(&osip)) {
		printf("OSIP read failure!\n");
	} else {
		dump_osip_header(&osip);
	}

	if (get_current_fw_rev(&cur_fw_rev)) {
		pr_error("Can't query kernel for current FW version");
	} else {
		printf("Current FW versions: (CHAABI versions unreadable at runtime)\n");
		dump_fw_versions(&cur_fw_rev);
	}
}

