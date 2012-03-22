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
#include <sys/ioctl.h>
#include <fcntl.h>
#include <cmfwdl.h>

#include "util.h"
#include "modem_fw.h"

#define TTY_NODE	"/dev/ttyMFD1"
#define IFX_NODE	"/dev/ttyIFX0"
#define HSU_PM_SYSFS	"/sys/devices/pci0000:00/0000:00:05.1/power/control"
#define S0_PM_SYSFS	"/sys/module/mfld_pmu/parameters/s0ix"
#define TRACE_FILE	"/modemtrace.log"

#define FFL_TTY_MAGIC	0x77
#define FFL_TTY_MODEM_RESET	_IO(FFL_TTY_MAGIC, 4)

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

int flash_modem_fw(char *bootloader_name, char *firmware_filename, int argc, char **argv, modem_progress_callback cb)
{
	struct cmfwdl *h;
	int ret = -1;
	struct cmfwdl_buffer fw_buffer, boot_buffer, rd_certif_buffer;

	struct cmfwdl_buffer *p_buffer_read_rd_certif;
	struct cmfwdl_buffer *p_buffer_hw_id;
	int b_read_rd_certif = 0;
	int b_rd_certif = 0;
	int read_hw_id = 0;
	int b_erase_rd_certif = 0;
	int arg;

	h = cmfwdl_create_instance();
	if (!h)
		return -1;

	for (arg = 0; arg < argc; arg++) {
		if (!strcmp(argv[arg], "f")) {
			if (cmfwdl_file_exist(firmware_filename))  {
				fw_buffer.name = firmware_filename;
				fw_buffer.size = 0;
				fw_buffer.data = NULL;
				if (cmfwdl_queue_file_download(h, &fw_buffer, 1) != 0) {
					printf("Unkown error when parse param.\n");
					goto out;
				}
			} else if ( !(cmfwdl_file_exist(firmware_filename) )) {
				printf("Image file doesn't exists. (%s)\n", firmware_filename);
				goto out;
			}
		} else if (!strcmp(argv[arg], "r")) {
			if (cmfwdl_file_exist(firmware_filename))  {
				rd_certif_buffer.name = firmware_filename;
				rd_certif_buffer.size = 0;
				rd_certif_buffer.data = NULL;
				b_rd_certif = 1;
			}
		} else if (!strcmp(argv[arg], "g")) {
			b_read_rd_certif = 1;
		} else if (!strcmp(argv[arg], "y")) {
			b_erase_rd_certif = 1;
		} else if (!strcmp(argv[arg], "h")) {
			read_hw_id = 1;
		}
	}

	boot_buffer.name = bootloader_name;
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

	/* Get modem HWID (print out in stdout) */
	if (read_hw_id == 1) {
		check(cmfwdl_queue_fetch_hardware_id(h));
	}

	/* Flash RND Cert */
	if (b_rd_certif == 1) {
		check(cmfwdl_queue_certificate_action(h, cmfwdl_certificate_RDC, cmfwdl_certificate_write, &rd_certif_buffer))
		check(cmfwdl_queue_certificate_action(h, cmfwdl_certificate_RDC, cmfwdl_certificate_read, NULL))
	}

	/* Erase RND Cert */
	if (b_erase_rd_certif == 1) {
		check(cmfwdl_queue_certificate_action(h, cmfwdl_certificate_RDC, cmfwdl_certificate_erase, NULL))
	}

	/* Get RND Cert (print out in stdout) */
	if (b_read_rd_certif == 1){
		check(cmfwdl_queue_certificate_action(h, cmfwdl_certificate_RDC, cmfwdl_certificate_read, NULL))
	}

	check(cmfwdl_execute(h, cb, NULL));

	if (read_hw_id == 1) {
		p_buffer_hw_id = cmfwdl_get_hardware_id(h);

		if (p_buffer_hw_id != NULL) {
			unsigned int cnt_bytes = 0;
			for (cnt_bytes = 0; cnt_bytes < p_buffer_hw_id->size; cnt_bytes++)
			{
				if (cnt_bytes%16 == 0)
					printf("\n");
				printf ("%02x", p_buffer_hw_id->data[cnt_bytes]);
			}
			printf("\n");
			cmfwdl_free_buffer(h, p_buffer_hw_id);
		}
	}

	if (b_read_rd_certif == 1) {
		p_buffer_read_rd_certif = cmfwdl_get_certificate(h, cmfwdl_certificate_RDC);

		if (p_buffer_read_rd_certif != NULL) {
			unsigned int cnt_bytes = 0;
			for (cnt_bytes = 0; cnt_bytes < p_buffer_read_rd_certif->size; cnt_bytes++)
			{
				if (cnt_bytes%16 == 0)
					printf("\n");
				printf ("%02x ", p_buffer_read_rd_certif->data[cnt_bytes]);
			}
			printf("\n");
			cmfwdl_free_buffer(h, p_buffer_read_rd_certif);
		}
		else
		printf("R&D CERTIFICATE NOT PRESENT !!\n");
	}

	ret = 0;
out:
	enable_pm();
	cmfwdl_destroy_instance(h);
	return ret;
}

int reset_modem()
{
	int fd;
	int retval = 1;

	fd = open(IFX_NODE, O_RDWR);
	if ( ioctl(fd, FFL_TTY_MODEM_RESET) < 0 )
	{
		printf("Could not reset modem\n");
		retval = -1;
	}
	close(fd);
	return retval;
}