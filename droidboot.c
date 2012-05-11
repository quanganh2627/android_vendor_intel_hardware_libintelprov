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
#include <droidboot_util.h>
#include <fcntl.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <cutils/properties.h>
#include <cutils/android_reboot.h>
#include <unistd.h>

#include "update_osip.h"
#include "util.h"
#include "modem_fw.h"
#include "fw_version_check.h"
#include "flash_ifwi.h"
#include "fastboot.h"
#include "droidboot_ui.h"

#define IMG_RADIO "/radio.img"
#define IMG_RADIO_RND "/radio_rnd.img"

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
		pr_info("modem: <msg> %s", msg);
		last_update_progress = -1;
		break;
	case cmfwdl_status_error_detail:
		pr_error("modem: ERROR: %s", msg);
		last_update_progress = -1;
		break;
	case cmfwdl_status_progress:
		pr_info("    <Progress> %d%%", value);
		last_update_progress = value;
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
	int argc = 1;
	char *argv[1];

	if (file_write(IMG_RADIO, data, sz)) {
		pr_error("Couldn't write radio image to %s", IMG_RADIO);
		return -1;
	}
	argv[0] = "f";
	/* Update modem SW. */
	ret = flash_modem_fw(IMG_RADIO, IMG_RADIO, argc, argv, progress_callback);
	unlink(IMG_RADIO);
	return ret;
}

static int flash_modem_store_fw(void *data, unsigned sz)
{
	/* Save locally modem SW (to be called first before flashing RND Cert) */
	if (file_write(IMG_RADIO, data, sz)) {
		pr_error("Couldn't write radio image to %s", IMG_RADIO);
		return -1;
	}
	printf("Radio Image Saved\n");
	return 0;
}

static int flash_modem_read_rnd(void *data, unsigned sz)
{
	int ret;
	int argc = 1;
	char *argv[1];

	if (file_write(IMG_RADIO, data, sz)) {
		pr_error("Couldn't write modem fw to %s", IMG_RADIO);
		return -1;
	}
	argv[0] = "g";
	/* Get RND Cert (print out in stdout) */
	ret = flash_modem_fw(IMG_RADIO, NULL, argc, argv, progress_callback);
	unlink(IMG_RADIO);
	return ret;
}

static int flash_modem_write_rnd(void *data, unsigned sz)
{
	int ret;
	int argc = 1;
	char *argv[1];

	if (access(IMG_RADIO, F_OK)) {
		pr_error("Radio Image %s Not Found!!\nCall flash radio_img first", IMG_RADIO);
		return -1;
	}
	if (file_write(IMG_RADIO_RND, data, sz)) {
		pr_error("Couldn't write radio_rnd image to %s", IMG_RADIO_RND);
		return -1;
	}
	argv[0] = "r";
	/* Flash RND Cert */
	ret = flash_modem_fw(IMG_RADIO, IMG_RADIO_RND, argc, argv, progress_callback);
	unlink(IMG_RADIO);
	unlink(IMG_RADIO_RND);
	return ret;
}

static int flash_modem_erase_rnd(void *data, unsigned sz)
{
	int ret;
	int argc = 1;
	char *argv[1];

	if (file_write(IMG_RADIO, data, sz)) {
		pr_error("Couldn't write radio image to %s", IMG_RADIO);
		return -1;
	}
	argv[0] = "y";
	/* Erase RND Cert */
	ret = flash_modem_fw(IMG_RADIO, NULL, argc, argv, progress_callback);
	unlink(IMG_RADIO);
	return ret;
}

static int flash_modem_get_hw_id(void *data, unsigned sz)
{
	int ret;
	int argc = 1;
	char *argv[1];

	if (file_write(IMG_RADIO, data, sz)) {
		pr_error("Couldn't write radio image to %s", IMG_RADIO);
		return -1;
	}
	printf("Getting radio HWID...\n");
	argv[0] = "h";
	/* Get modem HWID (print out in stdout) */
	ret = flash_modem_fw(IMG_RADIO, NULL, argc, argv, progress_callback);
	unlink(IMG_RADIO);
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

#define PROXY_SERVICE_NAME		"proxy"
#define PROXY_PROP		"service.proxy.enable"
#define PROXY_START		"1"
#define PROXY_STOP		"0"
#define HSI_PORT	"/sys/bus/hsi/devices/port0"

static int oem_manage_service_proxy(int argc, char **argv)
{
	int retval = 0;

	if ((argc < 2) || (strcmp(argv[0], PROXY_SERVICE_NAME))) {
		/* Should not pass here ! */
		pr_error("oem_manage_service called with wrong parameter!\n");
		retval = -1;
		return retval;
	}

	if (!strcmp(argv[1], "start")) {
		/* Check if HSI node was created, */
		/* indicating that the HSI bus is enabled.*/
		if (-1 != access(HSI_PORT, F_OK))
		{
			/* WORKAROUND */
			/* Check number of cpus => identify CTP (Clovertrail) */
			/* No modem reset for CTP, not supported */
			int fd;
			fd = open("/sys/class/cpuid/cpu3/dev", O_RDONLY);

			if (fd == -1)
			{
				/* Reset the modem */
				pr_info("Reset modem\n");
				reset_modem();
			}
			close(fd);

			/* Start proxy service (at-proxy). */
			property_set(PROXY_PROP, PROXY_START);

		} else {
			pr_error("Fails to find HSI node: %s\n", HSI_PORT);
			retval = -1;
		}

	} else if (!strcmp(argv[1], "stop")) {
		/* Stop proxy service (at-proxy). */
		property_set(PROXY_PROP, PROXY_STOP);

	} else {
		pr_error("Unknown command. Use %s [start/stop].\n", PROXY_SERVICE_NAME);
		retval = -1;
	}

	return retval;
}
#ifdef USE_GUI
#define PROP_FILE					"/default.prop"
#define SERIAL_NUM_FILE			"/sys/class/android_usb/android0/iSerial"
#define PRODUCT_NAME_ATTR		"ro.product.name"
#define MAX_NAME_SIZE			128
#define BUF_SIZE					256

static char* strupr(char *str)
{
	char *p = str;
	while (*p != '\0') {
		*p = toupper(*p);
		p++;
	}
	return str;
}

static int read_from_file(char* file, char *attr, char *value)
{
	char *p;
	char buf[BUF_SIZE];
	FILE *f;

	if ((f = fopen(file, "r")) == NULL) {
		LOGE("open %s error!\n", file);
		return -1;
	}
	while(fgets(buf, BUF_SIZE, f)) {
		if ((p = strstr(buf, attr)) != NULL) {
			p += strlen(attr)+1;
			strncpy(value, p, MAX_NAME_SIZE);
			value[MAX_NAME_SIZE-1] = '\0';
			strupr(value);
			break;
		}
	}

	fclose(f);
	return 0;
}

static int get_system_info(int type, char *info, unsigned sz)
{
	int ret = -1;
	char pro_name[MAX_NAME_SIZE];
	FILE *f;
	struct firmware_versions v;

	switch (type) {
		case IFWI_VERSION:
			if ((ret = get_current_fw_rev(&v)) < 0)
				break;
			snprintf(info, sz, "%2x.%2x", v.ifwi.major, v.ifwi.minor);
			ret = 0;
			break;
		case PRODUCT_NAME:
			if ((ret = read_from_file(PROP_FILE, PRODUCT_NAME_ATTR, pro_name)) < 0)
				break;
			snprintf(info, sz, "%s", pro_name);
			ret = 0;
			break;
		case SERIAL_NUM:
			if ((f = fopen(SERIAL_NUM_FILE, "r")) == NULL)
				break;
			if (fgets(info, sz, f) == NULL) {
				fclose(f);
				break;
			}
			fclose(f);
			ret = 0;
			break;
		default:
			break;
	}

	return ret;
}
#endif

static void cmd_intel_reboot(const char *arg, void *data, unsigned sz)
{
	fastboot_okay("");
	// This will cause a property trigger in init.rc to cold boot
	property_set("sys.forcecoldboot", "yes");
	sync();
	ui_print("REBOOT...\n");
	pr_info("Rebooting!\n");
	android_reboot(ANDROID_RB_RESTART2, 0, "android");
	pr_error("Reboot failed");
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

	ret |= aboot_register_flash_cmd("radio_img", flash_modem_store_fw);
	ret |= aboot_register_flash_cmd("rnd_read", flash_modem_read_rnd);
	ret |= aboot_register_flash_cmd("rnd_write", flash_modem_write_rnd);
	ret |= aboot_register_flash_cmd("rnd_erase", flash_modem_erase_rnd);
	ret |= aboot_register_flash_cmd("radio_hwid", flash_modem_get_hw_id);

	ret |= aboot_register_oem_cmd(PROXY_SERVICE_NAME, oem_manage_service_proxy);

	fastboot_register("continue", cmd_intel_reboot);
	fastboot_register("reboot", cmd_intel_reboot);

#ifdef USE_GUI
	ret |= aboot_register_ui_cmd(UI_GET_SYSTEM_INFO, get_system_info);
#endif

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
