/*
 * Copyright 2011-2014 Intel Corporation
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
#include <stdbool.h>
#include <unistd.h>
#include <droidboot_plugin.h>
#include "fastboot.h"
#include "util.h"
#include "miu.h"

#define IMG_RADIO "/radio.img"
#define IMG_RADIO_RND "/radio_rnd.img"
#define INFO_MSG_LEN (size_t)128

static bool is_log_enabled = false;

static int enable_logs(int argc, char **argv)
{
	is_log_enabled = true;
	ui_print("Enable radio flash logs\n");
	return 0;
}

static int disable_logs(int argc, char **argv)
{
	is_log_enabled = false;
	ui_print("Disable radio flash logs\n");
	return 0;
}

static void miu_progress_cb(int progress, int total)
{
	char buff[INFO_MSG_LEN] = { '\0' };

	snprintf(buff, INFO_MSG_LEN, "Progress: %d / %d\n", progress, total);

	pr_info("%s\n", buff);

	if (is_log_enabled)
		fastboot_info(buff);
}

static void miu_log_cb(const char *msg, ...)
{
	char buff[INFO_MSG_LEN] = { '\0' };
	va_list ap;

	if (msg != NULL) {
		va_start(ap, msg);

		vsnprintf(buff, sizeof(buff), msg, ap);

		pr_info("%s\n", buff);
		if (is_log_enabled)
			fastboot_info(buff);

		va_end(ap);
	}
}

static int flash_modem(e_miu_flash_options_t flash_options)
{
	int ret = -1;

	if (miu_initialize(miu_progress_cb, miu_log_cb, IMG_RADIO) != E_MIU_ERR_SUCCESS) {
		pr_error("%s initialization has failed\n", __func__);
	} else {
		if (is_log_enabled)
			flash_options |= E_MIU_FLASH_ENABLE_LOGS;

		/* Update modem SW. */
		if (miu_flash_modem_fw(IMG_RADIO, flash_options) == E_MIU_ERR_SUCCESS) {
			ret = 0;
			pr_info("%s successful\n", __func__);
		} else {
			pr_error("%s: operation has failed\n", __func__);
			ret = -1;
		}
	}
	miu_dispose();
	unlink(IMG_RADIO);

	return ret;
}

static int flash_radio(void *data, unsigned sz)
{
	e_miu_flash_options_t flash_options = 0;

	if (file_write(IMG_RADIO, data, sz)) {
		pr_error("Couldn't write radio image to %s", IMG_RADIO);
		return -1;
	}

	return flash_modem(flash_options);
}

static int flash_modem_get_fuse(void *data, unsigned sz)
{
	e_miu_flash_options_t flash_options = E_MIU_FLASH_GET_FUSE_INFO;

	if (file_write(IMG_RADIO, data, sz)) {
		pr_error("Couldn't write radio image to %s", IMG_RADIO);
		return -1;
	}

	return flash_modem(flash_options);
}

static int flash_modem_get_fuse_only(void *data, unsigned sz)
{
	int ret = -1;

	if (miu_initialize(miu_progress_cb, miu_log_cb, NULL) != E_MIU_ERR_SUCCESS) {
		pr_error("%s failed at %s\n", __func__,
			 "miu_initialize failed");
	} else {
		/* Update modem SW. */
		if (miu_get_modem_fuse() == E_MIU_ERR_SUCCESS) {
			ret = 0;
			pr_info("%s successful\n", __func__);
		} else {
			pr_error("%s failed at %s\n", __func__,
					"miu_get_modem_fuse");
			ret = -1;
		}
		miu_dispose();
	}
	return ret;
}

static int flash_modem_erase_all(void *data, unsigned sz)
{
	e_miu_flash_options_t flash_options = E_MIU_FLASH_ERASE_ALL_FIRST;

	return flash_modem(flash_options);
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
	int ret = -1;

	if (miu_initialize(miu_progress_cb, miu_log_cb, NULL) != E_MIU_ERR_SUCCESS) {
		pr_error("%s failed at %s\n", __func__,
			 "miu_initialize failed");
	} else {
		/* Get RND Cert (print out in stdout) */
		if (miu_read_modem_rnd_cert(IMG_RADIO) == E_MIU_ERR_SUCCESS) {
			ret = 0;
			pr_info("%s successful\n", __func__);
		} else {
			pr_error("%s flash has failed\n", __func__);
		}
	}
	miu_dispose();
	unlink(IMG_RADIO);
	return ret;
}

static int flash_modem_write_rnd(void *data, unsigned sz)
{
	int ret = -1;

	if (file_write(IMG_RADIO_RND, data, sz)) {
		pr_error("Couldn't write radio_rnd image to %s", IMG_RADIO_RND);
		return ret;
	}
	if (miu_initialize(miu_progress_cb, miu_log_cb, NULL) != E_MIU_ERR_SUCCESS) {
		pr_error("%s failed at %s\n", __func__,
			 "miu_initialize failed");
	} else {
		/* Flash RND Cert */
		if (miu_write_modem_rnd_cert(IMG_RADIO, IMG_RADIO_RND) ==
				E_MIU_ERR_SUCCESS) {
			ret = 0;
			pr_info("%s successful\n", __func__);
		} else {
			pr_error("%s failed at %s\n", __func__,
				 "miu_read_modem_rnd_cert");
		}
	}
	miu_dispose();
	unlink(IMG_RADIO);
	unlink(IMG_RADIO_RND);
	return ret;
}

static int flash_modem_erase_rnd(void *data, unsigned sz)
{
	int ret = -1;

	if (miu_initialize(miu_progress_cb, miu_log_cb, NULL) != E_MIU_ERR_SUCCESS) {
		pr_error("%s failed at %s\n", __func__,
			 "miu_initialize failed");
	} else {
		/* Erase RND Cert */
		if (miu_erase_modem_rnd_cert(IMG_RADIO) == E_MIU_ERR_SUCCESS) {
			ret = 0;
			pr_info("%s successful\n", __func__);
		} else {
			pr_error("%s failed at %s\n", __func__,
				 "miu_read_modem_rnd_cert");
		}
	}
	miu_dispose();
	unlink(IMG_RADIO);
	return ret;
}

static int oem_nvm_cmd_handler(int argc, char **argv)
{
	int retval = -1;
	char *nvm_path = NULL;

	if (miu_initialize(miu_progress_cb, miu_log_cb, NULL) != E_MIU_ERR_SUCCESS) {
		pr_error("%s failed at %s\n", __func__, "miu_initialize failed");
	} else {
		if (!strcmp(argv[1], "apply")) {
			pr_info("Applying nvm...");

			if (argc < 3) {
				pr_error("oem_nvm_cmd_handler called with wrong parameter!\n");
				retval = -1;
				return retval;
			}
			nvm_path = argv[2];

			if (miu_flash_modem_nvm(nvm_path, NULL) == E_MIU_ERR_SUCCESS) {
				retval = 0;
				pr_info("%s successful\n", __func__);
			} else {
				pr_error("%s failed with error: %i\n", __func__,
					retval);
				retval = -1;
			}
		} else if (!strcmp(argv[1], "identify")) {
			pr_info("Identifying nvm...");

			if (miu_read_modem_nvm_id(NULL, 0) == E_MIU_ERR_SUCCESS) {
				retval = 0;
				pr_info("%s successful\n", __func__);
			} else {
				pr_error("%s failed with error: %i\n", __func__,
					retval);
				retval = -1;
			}
		} else {
			pr_error("Unknown command. Use %s [apply].\n", "nvm");
			retval = -1;
		}
	}
	miu_dispose();
	return retval;
}

int aboot_register_telephony_functions(void)
{
	int ret = 0;

	ret |= aboot_register_flash_cmd("radio", flash_radio);
	ret |= aboot_register_flash_cmd("radio_fuse", flash_modem_get_fuse);
	ret |= aboot_register_flash_cmd("radio_erase_all", flash_modem_erase_all);
	ret |= aboot_register_flash_cmd("radio_fuse_only", flash_modem_get_fuse_only);
	ret |= aboot_register_flash_cmd("radio_img", flash_modem_store_fw);
	ret |= aboot_register_flash_cmd("rnd_read", flash_modem_read_rnd);
	ret |= aboot_register_flash_cmd("rnd_write", flash_modem_write_rnd);
	ret |= aboot_register_flash_cmd("rnd_erase", flash_modem_erase_rnd);
	ret |= aboot_register_oem_cmd("nvm", oem_nvm_cmd_handler);
	ret |= aboot_register_oem_cmd("enable_flash_logs", enable_logs);
	ret |= aboot_register_oem_cmd("disable_flash_logs", disable_logs);

	return ret;
}
