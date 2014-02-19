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

#include <libgen.h>
#include <unistd.h>
#include <stdio.h>

#include "common.h"
#include "util.h"
#include "fastboot.h"

/* needed for ensure_path_mounted */
#include <roots.h>
/* roots header brings LOG definition. We need to remove them
 * as droidboot_plugin will define them */
#ifdef LOGE
#undef LOGE
#endif
#ifdef LOGW
#undef LOGW
#endif
#ifdef LOGI
#undef LOGI
#endif
#ifdef LOGV
#undef LOGV
#endif
#ifdef LOGD
#undef LOGD
#endif

#include <droidboot_plugin.h>

#define RND_FILE "/config/telephony/rnd_cert.bin"
#define TLV_FILE "/config/telephony/provisioning/tlv_update.tlv"

static int push_file(void *data, const char *filename, unsigned sz)
{
	int ret = -1;

	if (ensure_path_mounted(CONFIG_FOLDER) != 0) {
		pr_error("partition %s not mounted", CONFIG_FOLDER);
	} else {
		pr_info("Pushing file %s", filename);
		if (!file_write(filename, data, sz))
			ret = set_file_permission(filename);
	}

	return ret;
}

static int push_mdm_package(void *data, unsigned sz)
{
	/* This command can be used for a fls or a zip file. So we cannot
	 * define the extension */
	pr_info("Pushing fls or zip update");

	/* @TODO: remove this file deletion */
	unlink("/config/telephony/modembinary.fls");

	return push_file(data, TELEPHONY_PROVISIONING"/package", sz);
}

static int push_tlv(void *data, unsigned sz)
{
	pr_info("Pushing tlv update");
	return push_file(data, TLV_FILE, sz);
}

static int rnd_write(void *data, unsigned sz)
{
	pr_info("Pushing RND file");
	return push_file(data, RND_FILE, sz);
}

static int rnd_erase(void *data, unsigned sz)
{
	int ret = -1;

	if (ensure_path_mounted(CONFIG_FOLDER) != 0) {
		pr_error("partition %s not mounted", CONFIG_FOLDER);
	} else {
		pr_info("Deleting RND file: %s", RND_FILE);
		ret = unlink(RND_FILE);
	}
	return ret;
}

static int rnd_read(void *data, unsigned sz)
{
	int ret = -1;

	(void) data; /* unused */
	(void) sz; /* unused */

	if ((ensure_path_mounted("/logs") != 0) ||
			(ensure_path_mounted(CONFIG_FOLDER) != 0)) {
		pr_error("partition %s or /logs not mounted", CONFIG_FOLDER);
	} else {
		static const char* const dest = "/logs/modem_rnd_certif.bin";
		pr_info("Copy RND to %s", dest);
		if (!file_copy(RND_FILE, dest))
			ret = set_file_permission(dest);
	}

	return ret;
}

static int oem_nvm_cmd_handler(int argc, char **argv)
{
	int ret = -1;

	if (argc < 3) {
		pr_error("%s called with wrong parameter", __FUNCTION__);
		goto out;
	}

	if (!strcmp(argv[1], "apply")) {
		char *input = argv[2];
		char output[PATH_MAX];

		pr_info("Applying nvm...");
		snprintf(output, sizeof(output), "%s/%s", TELEPHONY_PROVISIONING,
				basename(input));
		if (ensure_path_mounted(CONFIG_FOLDER) != 0) {
			pr_error("partition %s not mounted", CONFIG_FOLDER);
		} else {
			pr_info("Pushing TLV update %s", output);
			if (!file_copy(input, output))
				ret = set_file_permission(output);
		}
	} else if (!strcmp(argv[1], "identify")) {
		pr_error("Identify is no more supported");
	} else {
		pr_error("Unknown command. Use nvm [apply]");
	}

out:
	return ret;
}

int aboot_register_telephony_functions(void)
{
	int ret = 0;

	ret |= aboot_register_flash_cmd("radio", push_mdm_package);
	ret |= aboot_register_flash_cmd("tlv", push_tlv);
	ret |= aboot_register_flash_cmd("rnd_write", rnd_write);
	ret |= aboot_register_flash_cmd("rnd_erase", rnd_erase);
	ret |= aboot_register_flash_cmd("rnd_read", rnd_read);

	/* Deprecated command: */
	ret |= aboot_register_oem_cmd("nvm", oem_nvm_cmd_handler);
	return ret;
}
