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

#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <cmfwdl.h>

#include "util.h"
#include "modem_fw.h"

#define TTY_NODE	"/dev/ttyMFD1"
#define IFX_NODE	"/dev/ttyIFX0"
#define HSU_PM_SYSFS	"/sys/devices/pci0000:00/0000:00:05.1/power/control"
#define S0_PM_SYSFS	"/sys/module/mid_pmu/parameters/s0ix"
#define TRACE_FILE	"/modemtrace.log"

static int disable_pm(void)
{
	int ret = 0;
	ret |= file_string_write(HSU_PM_SYSFS, "on");
	ret |= file_string_write(S0_PM_SYSFS, "none");
	return ret;
}

static int enable_pm(void)
{
	int ret = 0;
	ret |= file_string_write(HSU_PM_SYSFS, "auto");
	ret |= file_string_write(S0_PM_SYSFS, "s0i3");
	return ret;
}

#define check(val) if (0 != (val)) { \
		printf("flash_modem_fw: '%s' failed\n", #val); \
		goto out; \
	}

int flash_modem_fw(char *firmware_filename, modem_progress_callback cb)
{
	struct cmfwdl *h;
	int ret = -1;
	struct cmfwdl_buffer fw_buffer, boot_buffer;
	return 0; /* disable for now */

	h = cmfwdl_create_instance();
	if (!h)
		return -1;

	fw_buffer.name = firmware_filename;
	fw_buffer.size = 0;
	fw_buffer.data = NULL;

	check(cmfwdl_queue_file_download(h, &fw_buffer, 1));

	boot_buffer.name = firmware_filename;
	boot_buffer.size = 0;
	boot_buffer.data = NULL;

	/* Set up various properties */
	cmfwdl_set_modemname(h, ifx6260);
	check(cmfwdl_set_ports(h, TTY_NODE, IFX_NODE));
	check(cmfwdl_set_trace_file(h, 1, TRACE_FILE));
	check(cmfwdl_set_property(h, cmfwdl_property_allow_hw_channel_switch,
			1));
	check(cmfwdl_set_property(h, cmfwdl_property_boot_process_timeout,
			30000));
	check(cmfwdl_set_property(h, cmfwdl_property_comm_timeout, 30000));
	check(cmfwdl_set_property(h, cmfwdl_property_faster_crc_method, 1));
	check(cmfwdl_set_property(h, cmfwdl_property_skip_empty_blocks, 0));
	check(cmfwdl_set_property(h, cmfwdl_property_use_pre_erase, 1));
	check(cmfwdl_set_property(h, cmfwdl_property_check_sign_hw_cfg_value,
			1));
	check(cmfwdl_set_property(h, cmfwdl_property_use_alt_boot_speed, 0));

	/* Apply the new firmware image */
	if (disable_pm())
		printf("WARNING: Unable to disable all power management."
				" Proceeding anyway.\n");
	check(cmfwdl_boot_modem(h, &boot_buffer, cb, NULL));
	check(cmfwdl_execute(h, cb, NULL));
	ret = 0;
out:
	enable_pm();
	cmfwdl_destroy_instance(h);
	printf("trace file contents --------------\n");
	dump_trace_file(TRACE_FILE);
	printf("----------------------------------\n");
	return ret;
}
