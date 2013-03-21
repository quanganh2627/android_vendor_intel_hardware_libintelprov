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
#include <charger/charger.h>
#include <linux/ioctl.h>
#include <linux/mdm_ctrl.h>

#include "volumeutils/ufdisk.h"
#include "update_osip.h"
#include "util.h"
#include "modem_fw.h"
#include "modem_nvm.h"
#include "fw_version_check.h"
#include "flash_ifwi.h"
#include "fastboot.h"
#include "droidboot_ui.h"
#include "update_partition.h"
#include <cgpt.h>

#define IMG_RADIO "/radio.img"
#define IMG_RADIO_RND "/radio_rnd.img"

static int oem_partition_stop_handler(int argc, char **argv);

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

static void nvm_output_callback(const char *msg, int output)
{
	if (msg == NULL) {
		return;
	}
	if (output & OUTPUT_DEBUG) {
		pr_debug(msg);
	}
	if (output & OUTPUT_FASTBOOT_INFO) {
		fastboot_info(msg);
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

static int flash_splashscreen_image(void *data, unsigned sz)
{
	return flash_image(data, sz, get_attribute_osii_index(ATTR_SIGNED_SPLASHSCREEN));
}

static int flash_uefi_firmware(void *data, unsigned sz)
{
	return flash_image(data, sz, get_named_osii_index(UEFI_FW_NAME));
}

int flash_logs = 0;
static int flash_modem(void *data, unsigned sz)
{
	int ret;
	int argc;
	char *argv[2];

	if(flash_logs == 0) {
		argc = 1;
		argv[0] = "f";
	}
	else {
		argc = 2;
		argv[0] = "f";
		argv[1] = "l";
	}

	if (file_write(IMG_RADIO, data, sz)) {
		pr_error("Couldn't write radio image to %s", IMG_RADIO);
		return -1;
	}
	/* Update modem SW. */
	ret = flash_modem_fw(IMG_RADIO, IMG_RADIO, argc, argv, progress_callback);
	unlink(IMG_RADIO);
	return ret;
}

static int flash_modem_no_end_reboot(void *data, unsigned sz)
{
	int ret;
	int argc = 1;
	char *argv[1];

	if (file_write(IMG_RADIO, data, sz)) {
		pr_error("Couldn't write radio image to %s", IMG_RADIO);
		return -1;
	}
	argv[0] = "d";
	/* Update modem SW. */
	ret = flash_modem_fw(IMG_RADIO, IMG_RADIO, argc, argv, progress_callback);
	unlink(IMG_RADIO);
	return ret;
}

static int flash_modem_get_fuse(void *data, unsigned sz)
{
	int ret;
	int argc = 1;
	char *argv[1];

	if(oem_partition_stop_handler(argc, argv) != 0)
		return -1;

	if (file_write(IMG_RADIO, data, sz)) {
		pr_error("Couldn't write radio image to %s", IMG_RADIO);
		return -1;
	}
	argv[0] = "u"; /* Update modem SW and get chip fusing parameters */
	ret = flash_modem_fw(IMG_RADIO, IMG_RADIO, argc, argv, progress_callback);
	unlink(IMG_RADIO);
	return ret;
}

static int flash_modem_get_fuse_only(void *data, unsigned sz)
{
	int ret;
	int argc = 1;
	char *argv[1];

	if(oem_partition_stop_handler(argc, argv) != 0)
		return -1;

	if (file_write(IMG_RADIO, data, sz)) {
		pr_error("Couldn't write radio image to %s", IMG_RADIO);
		return -1;
	}

	argv[0] = "v"; /* Only get chip fusing parameters */
	ret = flash_modem_fw(IMG_RADIO, IMG_RADIO, argc, argv, progress_callback);
	unlink(IMG_RADIO);
	return ret;
}

static int flash_modem_erase_all(void *data, unsigned sz)
{
	int ret;
	int argc = 2;
	char *argv[2];

	if (file_write(IMG_RADIO, data, sz)) {
		pr_error("Couldn't write radio image to %s", IMG_RADIO);
		return -1;
	}
	argv[0] = "e";
	argv[1] = "f";
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

	if(oem_partition_stop_handler(argc, argv) != 0)
		return -1;

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

	if(oem_partition_stop_handler(argc, argv) != 0)
		return -1;

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

#ifdef MRFLD

static int flash_dnx(void *data, unsigned sz)
{
    return 0;
}

#define BOOT0 "/dev/block/mmcblk0boot0"
#define BOOT1 "/dev/block/mmcblk0boot1"
#define BOOT_PARTITION_SIZE 0x400000

#define IFWI_TYPE_LSH 12

void dump_fw_versions_long(struct firmware_versions_long *v)
{
	pr_info("	   ifwi: %04X.%04X\n", v->ifwi.major, v->ifwi.minor);
	pr_info("---- components ----\n");
	pr_info("	    scu: %04X.%04X\n", v->scu.major, v->scu.minor);
	pr_info("    hooks/oem: %04X.%04X\n", v->valhooks.major, v->valhooks.minor);
	pr_info("	   ia32: %04X.%04X\n", v->ia32.major, v->ia32.minor);
	pr_info("	 chaabi: %04X.%04X\n", v->chaabi.major, v->chaabi.minor);
	pr_info("	    mIA: %04X.%04X\n", v->mia.major, v->mia.minor);
}

int write_image(int fd, char *image, unsigned size)
{
    int ret = 0;
    char *ptr = NULL;

    ptr = image;
    if (!ptr) {
        pr_error("write_image(): Image is invalid\n");
        return -1;
    }

    while(size) {
    /*If this condition is not present, the write*/
    /*function errors out while writing the last chunk*/
        ret = write(fd, ptr, size);
        if (ret <= 0 && errno != EINTR) {
            pr_error("write_image(): image write failed with errno %d\n", errno);
            return -1;
        }
        ptr += ret;
        size -= ret;
    }

    fsync(fd);
    return 0;
}

static int flash_ifwi(void *data, unsigned size)
{
    int boot0_fd, boot1_fd, ret = 0;
    struct firmware_versions_long dev_fw_rev, img_fw_rev;

    if (get_image_fw_rev_long(data, size, &img_fw_rev)) {
        pr_error("Coudn't extract FW version data from image\n");
        return -1;
    }
    pr_info("Image FW versions:\n");
    dump_fw_versions_long(&img_fw_rev);

    if (get_current_fw_rev_long(&dev_fw_rev)) {
        pr_error("Couldn't query existing IFWI version\n");
        return -1;
    }
    pr_info("Attempting to flash ifwi image version %04X.%04X over ifwi current version %04X.%04X\n",
        img_fw_rev.ifwi.major,img_fw_rev.ifwi.minor,dev_fw_rev.ifwi.major,dev_fw_rev.ifwi.minor);

    if (img_fw_rev.ifwi.major != dev_fw_rev.ifwi.major) {
        pr_error("IFWI FW Major version numbers (file=%04X current=%04X) don't match, Update abort.\n",
            img_fw_rev.ifwi.major, dev_fw_rev.ifwi.major);

        /* Not an error case. Let update continue to next IFWI versions. */
        return 0;
    }

    if ( (img_fw_rev.ifwi.minor >> IFWI_TYPE_LSH) != (dev_fw_rev.ifwi.minor >> IFWI_TYPE_LSH) ) {
        pr_error("IFWI FW Type (file=%1X current=%1X) don't match, Update abort.\n",
            img_fw_rev.ifwi.minor >> IFWI_TYPE_LSH, dev_fw_rev.ifwi.minor >> IFWI_TYPE_LSH);

        /* Not an error case. Let update continue to next IFWI versions. */
        return 0;
    }

    if (size > BOOT_PARTITION_SIZE) {
        pr_error("flash_ifwi(): Truncating last %d bytes from the IFWI\n",
        (size - BOOT_PARTITION_SIZE));
        /* Since the last 144 bytes are the FUP header which are not required,*/
        /* we truncate it to fit into the boot partition. */
        size = BOOT_PARTITION_SIZE;
    }

    boot0_fd = open(BOOT0, O_RDWR);
    if (boot0_fd < 0) {
        pr_error("flash_ifwi(): failed to open %s\n", BOOT0);
        return -1;
    }
    boot1_fd = open(BOOT1, O_RDWR);
    if (boot1_fd < 0) {
        pr_error("flash_ifwi(): failed to open %s\n", BOOT1);
        close(boot0_fd);
        return -1;
    }

    if (lseek(boot0_fd, 0, SEEK_SET) < 0) { /* Seek to start of file */
        pr_error("flash_ifwi(): lseek failed on boot0");
        close(boot0_fd);
        close(boot1_fd);
        return -1;
    }

    if (lseek(boot1_fd, 0, SEEK_SET) < 0) {
        pr_error("flash_ifwi(): lseek failed on boot1");
        close(boot0_fd);
        close(boot1_fd);
        return -1;
    }

    ret = write_image(boot0_fd, (char*)data, size);
    if (ret)
        pr_error("flash_ifwi(): write to %s failed\n", BOOT0);
    else {
        ret = write_image(boot1_fd, (char*)data, size);
        if (ret)
            pr_error("flash_ifwi(): write to %s failed\n", BOOT1);
    }

    close(boot0_fd);
    close(boot1_fd);

    return ret;
}

#else

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

#endif

#define CAPSULE_PARTITION_NAME "/FWUP"
#define CAPSULE_UPDATE_FLAG_PATH "/sys/firmware/osnib/fw_update"

static int flash_capsule(void *data, unsigned sz)
{
	Volume *v;
	char capsule_trigger = '1';

	if ((v = volume_for_path(CAPSULE_PARTITION_NAME)) == NULL) {
		pr_error("Cannot find FWUP volume!\n");
		return -1;
	}

	if (file_write(v->device, data, sz)) {
		pr_error("Capsule flashing failed!\n");
		return -1;
	}

	if (file_write(CAPSULE_UPDATE_FLAG_PATH,
				&capsule_trigger, sizeof(capsule_trigger))) {
		pr_error("Capsule flashing failed!\n");
		return -1;
	}

	return 0;
}

#define PROXY_SERVICE_NAME	"proxy"
#define PROXY_PROP		"service.proxy.enable"
#define PROXY_START		"1"
#define PROXY_STOP		"0"
#define HSI_PORT		"/sys/bus/hsi/devices/port0"
#define MCD_CTRL		"/dev/mdm_ctrl"

static int oem_manage_service_proxy(int argc, char **argv)
{
	int retval = 0;
	int mcd_fd = -1;
	int evt_type = 0;

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
			} else
				close(fd);

			/* Start proxy service (at-proxy). */
			property_set(PROXY_PROP, PROXY_START);

		} else {
			/* MCD build. Modem needs to be powered */
			/* Boot up the modem */
			if ((mcd_fd = open(MCD_CTRL, O_RDWR)) == -1) {
				pr_error("Unable to open MCD node or find HSI. ABORT.\n");
				return -1;
			}
			if (ioctl(mcd_fd, MDM_CTRL_POWER_ON) == -1) {
				pr_info("Unable to power on modem. ABORT.\n");
				close(mcd_fd);
				return -1;
			} else {
				/* Let modem time to boot */
				pr_info("Modem will be powered up... ");
				evt_type = MDM_CTRL_STATE_IPC_READY;
				if (ioctl(mcd_fd, MDM_CTRL_WAIT_FOR_STATE, &evt_type) == -1) {
					pr_error("Power up failure. ABORT.\n");
					close(mcd_fd);
					return -1;
				}
				pr_info("Modem powered up.\n");
				close(mcd_fd);
				/* Start proxy service (at-proxy). */
				property_set(PROXY_PROP, PROXY_START);
			}
		}

	} else if (!strcmp(argv[1], "stop")) {
		/* For MCD build, modem will be powered down */
		if ((mcd_fd = open(MCD_CTRL, O_RDWR)) == -1) {
			/* Stop proxy service (at-proxy). */
			property_set(PROXY_PROP, PROXY_STOP);
			return 0;
		}
		/* Stop proxy service (at-proxy) anyway. */
		property_set(PROXY_PROP, PROXY_STOP);
		if (ioctl(mcd_fd, MDM_CTRL_POWER_OFF) == -1) {
			pr_info("Unable to power off modem. ABORT.\n");
			close(mcd_fd);
			return -1;
		} else {
			/* Let modem time to stop. */
			pr_info("Modem will be powered down... ");
			evt_type = MDM_CTRL_STATE_OFF;
			if (ioctl(mcd_fd, MDM_CTRL_WAIT_FOR_STATE, &evt_type) == -1) {
				pr_error("Power down failure. ABORT.\n");
				close(mcd_fd);
				return -1;
			}
			pr_info("Modem powered down.\n");
			close(mcd_fd);
			return 0;
		}

	} else {
		pr_error("Unknown command. Use %s [start/stop].\n", PROXY_SERVICE_NAME);
		retval = -1;
	}

	return retval;
}

#define DNX_TIMEOUT_CHANGE  "dnx_timeout"
#define DNX_TIMEOUT_GET	    "--get"
#define DNX_TIMEOUT_SET	    "--set"
#define SYS_CURRENT_TIMEOUT "/sys/devices/platform/intel_mid_umip/current_timeout"
#define TIMEOUT_SIZE	    20
#define OPTION_SIZE	    6

static int oem_dnx_timeout(int argc, char **argv)
{
	int retval = -1;
	int count, offset, bytes, size;
	int fd;
	char option[OPTION_SIZE] = "";
	char timeout[TIMEOUT_SIZE] = "";
	char check[TIMEOUT_SIZE] = "";

	if (argc < 1 || argc > 3) {
		/* Should not pass here ! */
		fastboot_fail("oem dnx_timeout requires one or two arguments");
		goto end2;
	}

	size = snprintf(option, OPTION_SIZE, "%s", argv[1]);

	if (size == -1 || size > OPTION_SIZE-1) {
	    fastboot_fail("Parameter size exceeds limit");
	    goto end2;
	}

	fd = open(SYS_CURRENT_TIMEOUT, O_RDWR);

	if (fd == -1) {
		pr_error("Can't open %s\n", SYS_CURRENT_TIMEOUT);
		goto end2;
	}

	if (!strcmp(option, DNX_TIMEOUT_GET)) {
		/* Get current timeout */
		count = read(fd, check, TIMEOUT_SIZE);

		if (count <= 0) {
			fastboot_fail("Failed to read");
			goto end1;
		}

		fastboot_info(check);

	} else { if (!strcmp(option, DNX_TIMEOUT_SET)) {
		    /* Set new timeout */

		    if (argc != 3) {
			/* Should not pass here ! */
			fastboot_fail("oem dnx_timeout --set not enough arguments");
			goto end1;
		    }

		    // Get timeout value to set
		    size = snprintf(timeout, TIMEOUT_SIZE, "%s", argv[2]);

		    if (size == -1 || size > TIMEOUT_SIZE-1) {
			fastboot_fail("Timeout value size exceeds limit");
			goto end1;
		    }

		    bytes = write(fd, timeout, size);
		    if (bytes != size) {
			fastboot_fail("oem dnx_timeout failed to write file");
			goto end1;
		    }

		    offset = lseek(fd, 0, SEEK_SET);
		    if (offset == -1) {
			fastboot_fail("oem dnx_timeout failed to set offset");
			goto end1;
		    }

		    memset(check, 0, TIMEOUT_SIZE);

		    count = read(fd, check, TIMEOUT_SIZE);
		    if (count <= 0) {
			fastboot_fail("Failed to check");
		    	goto end1;
		    }

		    // terminate string unconditionally to avoid buffer overflow
		    check[TIMEOUT_SIZE-1] = '\0';
		    if (check[strlen(check)-1] == '\n')
			check[strlen(check)-1]= '\0';
		    if (strcmp(check, timeout)) {
			fastboot_fail("oem dnx_timeout called with wrong parameter");
			goto end1;
		    }
		} else {
		    fastboot_fail("Unknown command. Use fastboot oem dnx_timeout [--get/--set] command\n");
		    goto end1;
		}
	}

	retval = 0;
	fastboot_okay("");

end1:
	close(fd);
end2:
	return retval;
}

#define K_MAX_LINE_LEN 8192
#define K_MAX_ARGS 256
#define K_MAX_ARG_LEN 256

static int oem_nvm_cmd_handler(int argc, char **argv)
{
	int retval = 0;
	char *nvm_path = NULL;

	if (!strcmp(argv[1], "apply")) {
		pr_info("in apply");
		if (argc < 3) {
			pr_error("oem_nvm_cmd_handler called with wrong parameter!\n");
			retval = -1;
			return retval;
		}
		nvm_path = argv[2];

		retval = flash_modem_nvm(nvm_path, nvm_output_callback);
	}
	else if (!strcmp(argv[1], "applyzip")) {
		pr_info("in applyzip");
		if (argc < 3) {
			pr_error("oem_nvm_cmd_handler called with wrong parameter!\n");
			retval = -1;
			return retval;
		}
		nvm_path = argv[2];

		retval = flash_modem_nvm_spid(nvm_path, nvm_output_callback);
	}
        else if (!strcmp(argv[1], "identify")) {
		pr_info("in identify");
		retval = read_modem_nvm_id(NULL, 0, nvm_output_callback);
	}
	else {
		pr_error("Unknown command. Use %s [apply].\n", "nvm");
		retval = -1;
	}

	return retval;
}

static char **str_to_array(char *str, int *argc)
{
	char *str1, *token;
	char *saveptr1;
	int j;
	int num_tokens;
	char **tokens;

	tokens=malloc(sizeof(char *) * K_MAX_ARGS);

	if(tokens==NULL)
	    return NULL;

	num_tokens = 0;

	for (j = 1, str1 = str; ; j++, str1 = NULL) {
		token = strtok_r(str1, " ", &saveptr1);

	if (token == NULL)
		break;

	tokens[num_tokens] = (char *) malloc(sizeof(char) * K_MAX_ARG_LEN+1);

	if(tokens[num_tokens]==NULL)
		break;

	strncpy(tokens[num_tokens], token, K_MAX_ARG_LEN);
	num_tokens++;

	if (num_tokens == K_MAX_ARGS)
		break;
	}

	*argc = num_tokens;
	return tokens;
}

static int oem_write_osip_header(int argc, char **argv)
{
	static struct OSIP_header default_osip = {
		.sig = OSIP_SIG,
		.intel_reserved = 0,
		.header_rev_minor = 0,
		.header_rev_major = 1,
		.header_checksum = 0,
		.num_pointers = 1,
		.num_images = 1,
		.header_size = 0
	};

	ui_print("Write OSIP header\n");
	default_osip.header_checksum = get_osip_crc(&default_osip);
	write_OSIP(&default_osip);
	restore_osii("boot");
	restore_osii("recovery");
	restore_osii("fastboot");
	return 0;
}
static int oem_partition_start_handler(int argc, char **argv)
{
	property_set("sys.partitioning", "1");
	ui_print("Start partitioning\n");
	ufdisk_umount_all();
	return 0;
}

static int oem_partition_stop_handler(int argc, char **argv)
{
	property_set("sys.partitioning", "0");
	ui_print("Stop partitioning\n");
	return 0;
}

static int oem_enable_flash_logs(int argc, char **argv)
{
	if(oem_partition_stop_handler(argc, argv) != 0)
		return -1;
	flash_logs = 1;
	ui_print("Enable flash logs\n");
	return 0;
}

static int oem_disable_flash_logs(int argc, char **argv)
{
	flash_logs = 0;
	ui_print("Disable flash logs\n");
	return 0;
}

static int oem_get_batt_info_handler(int argc, char **argv)
{
	char msg_buf[] = " level: 000";
	int batt_level = 0;

	batt_level = get_battery_level();
	if (batt_level == -1) {
		fastboot_fail("Could not get battery level");
		return -1;
	}
	// Prepare the message sent to the host
	snprintf(msg_buf, sizeof(msg_buf), "\nlevel: %d", batt_level);
	// Push the value to the host
	fastboot_info(msg_buf);
	// Display the result on the UI
	ui_print("Battery level at %d%%\n", batt_level);

	return 0;
}

static int _oem_partition_gpt_sub_command(int argc, char **argv)
{
	unsigned int i;
	char *command = argv[0];
	static struct {
		const char *name;
		int (*fp)(int argc, char *argv[]);
	} cmds[] = {
		{"create", cmd_create },
		{"add", cmd_add},
		{"dump", cmd_show},
		{"repair", cmd_repair},
		{"boot", cmd_bootable},
		{"find", cmd_find},
		{"prioritize", cmd_prioritize},
		{"legacy", cmd_legacy},
		{"reload", cmd_reload},
	};

	optind = 0;
	for (i = 0; command && i < sizeof(cmds)/sizeof(cmds[0]); ++i)
		if (0 == strncmp(cmds[i].name, command, strlen(command)))
			return cmds[i].fp(argc, argv);

	return -1;
}

static int oem_partition_gpt_handler(FILE *fp)
{
	int argc = 0;
	int ret = 0;
	int i;
	char buffer[K_MAX_ARG_LEN];
	char **argv = NULL;
	char value[PROPERTY_VALUE_MAX] = {'\0'};

	ui_print("Using GPT\n");

	property_get("sys.partitioning", value, NULL);
	if (strcmp(value, "1")) {
		fastboot_fail("Partitioning is not started\n");
		return -1;
	}

	uuid_generator = uuid_generate;
	while (fgets(buffer, sizeof(buffer), fp)) {
		if (buffer[strlen(buffer)-1] == '\n')
			buffer[strlen(buffer)-1]='\0';
		argv = str_to_array(buffer, &argc);

		if(argv != NULL) {
			ret = _oem_partition_gpt_sub_command(argc, argv);

			for(i = 0; i < argc ; i++) {
				if (argv[i]) {
					free(argv[i]);
					argv[i]=NULL;
				}
			}
			free(argv);
			argv=NULL;

			if (ret) {
				pr_error("gpt command failed: %s", buffer);
				fastboot_fail("GPT command failed\n");
				return -1;
			}
		}
		else {
			pr_error("GPT str_to_array error: %s", buffer);
			fastboot_fail("GPT str_to_array error. Malformed string ?\n");
			return -1;
		}
	}

	return 0;
}

static int oem_partition_mbr_handler(FILE *fp)
{
	ui_print("Using MBR\n");

	return ufdisk_create_partition();
}

int oem_partition_cmd_handler(int argc, char **argv)
{
	char buffer[K_MAX_ARG_LEN];
	char partition_type[K_MAX_ARG_LEN];
	FILE *fp;
	int retval = -1;

	memset(buffer, 0, sizeof(buffer));

	if (argc == 2) {
		fp = fopen(argv[1], "r");
		if (!fp) {
		      fastboot_fail("Can't open partition file");
		      return -1;
		}

		if (!fgets(buffer, sizeof(buffer), fp)) {
		      fastboot_fail("partition file is empty");
		      return -1;
		}

		buffer[strlen(buffer)-1]='\0';

		if (sscanf(buffer, "%*[^=]=%255s", partition_type) != 1) {
		      fastboot_fail("partition file is invalid");
		      return -1;
		}

		if (!strncmp("gpt", partition_type, strlen(partition_type)))
		      retval = oem_partition_gpt_handler(fp);

		if (!strncmp("mbr", partition_type, strlen(partition_type)))
		      retval = oem_partition_mbr_handler(fp);

		fclose(fp);
	}

	return retval;
}

#define ERASE_PARTITION     "erase"
#define MOUNT_POINT_SIZE    50      /* /dev/<whatever> */
#define BUFFER_SIZE         4000000 /* 4Mb */

static int oem_erase_partition(int argc, char **argv)
{
	int retval = -1;
	int size;
	char mnt_point[MOUNT_POINT_SIZE] = "";

	if ((argc != 2) || (strcmp(argv[0], ERASE_PARTITION))) {
		/* Should not pass here ! */
                fastboot_fail("oem erase called with wrong parameter!\n");
		goto end;
	}

	if (argv[1][0] == '/') {
		size = snprintf(mnt_point, MOUNT_POINT_SIZE, "%s", argv[1]);

		if (size == -1 || size > MOUNT_POINT_SIZE-1) {
		    fastboot_fail("Mount point parameter size exceeds limit");
		    goto end;
		}
	} else {
		if (!strcmp(argv[1], "userdata")) {
		    strcpy(mnt_point, "/data");
		} else {
		    size = snprintf(mnt_point, MOUNT_POINT_SIZE, "/%s", argv[1]);

		    if (size == -1 || size > MOUNT_POINT_SIZE-1) {
			fastboot_fail("Mount point size exceeds limit");
			goto end;
		    }
		}
	}

	pr_info("CMD '%s %s'...\n", ERASE_PARTITION, mnt_point);

	ui_print("ERASE step 1/2...\n");
	retval = nuke_volume(mnt_point, BUFFER_SIZE);
	if (retval != 0) {
		pr_error("format_volume failed: %s\n", mnt_point);
		goto end;
	} else {
		pr_info("format_volume succeeds: %s\n", mnt_point);
	}

	ui_print("ERASE step 2/2...\n");
	retval = format_volume(mnt_point);
	if (retval != 0) {
		pr_error("format_volume failed: %s\n", mnt_point);
	} else {
		pr_info("format_volume succeeds: %s\n", mnt_point);
	}

end:
    return retval;
}

#define REPART_PARTITION	"repart"

static int oem_repart_partition(int argc, char **argv)
{
	int retval = -1;

	if (argc != 1) {
		/* Should not pass here ! */
		fastboot_fail("oem repart does not require argument");
		goto end;
	}

	retval = ufdisk_create_partition();
	if (retval != 0)
		fastboot_fail("cannot write partition");
	else
		fastboot_okay("");

end:
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

static void cmd_intel_reboot_bootloader(const char *arg, void *data, unsigned sz)
{
	fastboot_okay("");
	// No cold boot as it would not allow to reboot in bootloader
	sync();
	ui_print("REBOOT in BOOTLOADER...\n");
	pr_info("Rebooting in BOOTLOADER !\n");
	android_reboot(ANDROID_RB_RESTART2, 0, "bootloader");
	pr_error("Reboot failed");
}

void libintel_droidboot_init(void)
{
	int ret = 0;
	struct OSIP_header osip;

	ret |= aboot_register_flash_cmd(ANDROID_OS_NAME, flash_android_kernel);
	ret |= aboot_register_flash_cmd(RECOVERY_OS_NAME, flash_recovery_kernel);
	ret |= aboot_register_flash_cmd(FASTBOOT_OS_NAME, flash_fastboot_kernel);
	ret |= aboot_register_flash_cmd(UEFI_FW_NAME, flash_uefi_firmware);
	ret |= aboot_register_flash_cmd("splashscreen", flash_splashscreen_image);
	ret |= aboot_register_flash_cmd("radio", flash_modem);
	ret |= aboot_register_flash_cmd("radio_no_end_reboot", flash_modem_no_end_reboot);
	ret |= aboot_register_flash_cmd("radio_fuse", flash_modem_get_fuse);
	ret |= aboot_register_flash_cmd("radio_erase_all", flash_modem_erase_all);
	ret |= aboot_register_flash_cmd("radio_fuse_only", flash_modem_get_fuse_only);
	ret |= aboot_register_flash_cmd("dnx", flash_dnx);
	ret |= aboot_register_flash_cmd("ifwi", flash_ifwi);
	ret |= aboot_register_flash_cmd("capsule", flash_capsule);

	ret |= aboot_register_flash_cmd("radio_img", flash_modem_store_fw);
	ret |= aboot_register_flash_cmd("rnd_read", flash_modem_read_rnd);
	ret |= aboot_register_flash_cmd("rnd_write", flash_modem_write_rnd);
	ret |= aboot_register_flash_cmd("rnd_erase", flash_modem_erase_rnd);
	ret |= aboot_register_flash_cmd("radio_hwid", flash_modem_get_hw_id);

	ret |= aboot_register_oem_cmd(PROXY_SERVICE_NAME, oem_manage_service_proxy);
	ret |= aboot_register_oem_cmd(DNX_TIMEOUT_CHANGE, oem_dnx_timeout);
	ret |= aboot_register_oem_cmd(ERASE_PARTITION, oem_erase_partition);
	ret |= aboot_register_oem_cmd(REPART_PARTITION, oem_repart_partition);

	ret |= aboot_register_oem_cmd("nvm", oem_nvm_cmd_handler);
	ret |= aboot_register_oem_cmd("write_osip_header", oem_write_osip_header);
	ret |= aboot_register_oem_cmd("start_partitioning", oem_partition_start_handler);
	ret |= aboot_register_oem_cmd("partition", oem_partition_cmd_handler);
	ret |= aboot_register_oem_cmd("stop_partitioning", oem_partition_stop_handler);
	ret |= aboot_register_oem_cmd("get_batt_info", oem_get_batt_info_handler);
	ret |= aboot_register_oem_cmd("enable_flash_logs", oem_enable_flash_logs);
	ret |= aboot_register_oem_cmd("disable_flash_logs", oem_disable_flash_logs);

	fastboot_register("continue", cmd_intel_reboot);
	fastboot_register("reboot", cmd_intel_reboot);
	fastboot_register("reboot-bootloader", cmd_intel_reboot_bootloader);

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

#ifdef MRFLD
	struct firmware_versions_long cur_fw_rev;
	if (get_current_fw_rev_long(&cur_fw_rev)) {
		pr_error("Can't query kernel for current FW version");
	} else {
		printf("Current FW versions:\n");
		dump_fw_versions_long(&cur_fw_rev);
	}
#else
	struct firmware_versions cur_fw_rev;
	if (get_current_fw_rev(&cur_fw_rev)) {
		pr_error("Can't query kernel for current FW version");
	} else {
		printf("Current FW versions: (CHAABI versions unreadable at runtime)\n");
		dump_fw_versions(&cur_fw_rev);
	}
#endif
}
