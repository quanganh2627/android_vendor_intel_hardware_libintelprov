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
#include <limits.h>
#include <cmfwdl.h>

#include "util.h"
#include "modem_fw.h"

#define TTY_NODE	"/dev/ttyMFD1"
#define IFX_NODE0	"/dev/ttyIFX0"
#define IFX_NODE1	"/dev/ttyIFX1"
#define HSU_PM_SYSFS	"/sys/devices/pci0000:00/0000:00:05.1/power/control"
#define S0_PM_SYSFS	"/sys/module/intel_soc_pmu/parameters/s0ix"
#define TRACE_FILE	"/modemtrace.log"
#define RND_CERTIFICATE_FILE	"/logs/modem_rnd_certif.bin"
#define HW_ID_FILE	"/logs/modem_hw_id.hwd"
#define FUSE_FILE	"/logs/modem_fuse.fus"
#define CHIP_FUSE_SIZE 9  /* Number of chip fusing parameters */

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

/*
 * store_data_to_file.
 *
 * Helper to store data got to modem into file.
 * Use for instance to store HWID or RnD cert read from modem.
 * @param buffer struct buffer holding data to be stored and
 * filename, including path.
 * @return store status (0 = ok, otherwise ko)
 */
static int store_data_to_file(struct cmfwdl_buffer *buffer)
{

	FILE *file;
	size_t count = 0;

	if(buffer == NULL || buffer->name == NULL) {
		fprintf(stderr,"Unexpected NULL buffer pointer\n");
		return -1;
	}

	size_t len = strlen(buffer->name);

	if(len >= PATH_MAX) {
		fprintf(stderr,"File name too long !!\n");
		return -1;
	}

	file = fopen(buffer->name, "wb+");

	if (file == NULL) {
		fprintf(stderr,"Create file fail !\n");
		return -1;
	}

	count = fwrite( buffer->data, 1, buffer->size, file );

	if (count != buffer->size) {
		fprintf(stderr,"store data to file fail !\n");
		fclose(file);
		return -1;
	}

	fclose(file);
	return 0;
}

#define check(val) if (0 != (val)) { \
	printf("flash_modem_fw: '%s' failed\n", #val); \
	goto out; \
}

int flash_modem_fw(char *bootloader_name, char *firmware_filename, int argc, char **argv, modem_progress_callback cb)
{
	struct cmfwdl *h;
	int ret = -1;
	struct cmfwdl_buffer fw_buffer, boot_buffer, rd_certif_buffer, fuse_buffer;

	struct cmfwdl_buffer *p_buffer_read_rd_certif = NULL;
	struct cmfwdl_buffer *p_buffer_hw_id = NULL;
	int b_erase_all = 0;
	int b_asked_reboot = CMFWDL_REBOOT;
	int b_end_reboot = CMFWDL_REBOOT;
	int b_read_rd_certif = 0;
	int b_rd_certif = 0;
	int read_hw_id = 0;
	int b_erase_rd_certif = 0;
	int arg;
	int b_bootloader = 1;
	int b_fw_download = 0;
	int b_fuse = 0;
	unsigned char fuse_data[CHIP_FUSE_SIZE];
	char fuse_ascii[3*CHIP_FUSE_SIZE+1];
	int i;

	h = cmfwdl_create_instance();
	if (!h)
		return -1;

	for (arg = 0; arg < argc; arg++) {
		if (!strcmp(argv[arg], "e")) {
			b_erase_all = 1;
		} else if (!strcmp(argv[arg], "f")) {
			b_asked_reboot = CMFWDL_REBOOT;
			b_fw_download = 1;
		} else if (!strcmp(argv[arg], "d")) {
			b_asked_reboot = CMFWDL_NOREBOOT;
			b_fw_download = 1;
		} else if (!strcmp(argv[arg], "u")) {
			b_fuse = 1;
			b_bootloader = 1;
			b_fw_download = 1;
		} else if (!strcmp(argv[arg], "v")) {
			b_fuse = 1;
			b_bootloader = 0;
			b_fw_download = 0;
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
		if (b_fw_download != 0)
		{
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
			b_fw_download = 0;
		}
	}

	boot_buffer.name = bootloader_name;
	boot_buffer.size = 0;
	boot_buffer.data = NULL;

	/* Set up various properties */
	if (cmfwdl_file_exist(firmware_filename)) {
	    cmfwdl_set_modemname(h, cmfwdl_get_modemname_from_file(firmware_filename));
	}
	if (cmfwdl_modemname(h) == no_modem) {
	    cmfwdl_set_modemname(h, xmm6260);
	}

#ifdef CLVT
	check(cmfwdl_set_ports(h, NULL, IFX_NODE1));
#else
	check(cmfwdl_set_ports(h, TTY_NODE, IFX_NODE0));
#endif
	check(cmfwdl_set_trace_file(h, 1, TRACE_FILE));

	/* If asked, set erase mode to erase all (code and calibration table) */
	if (b_erase_all == 1) {
		check(cmfwdl_set_property(h, cmfwdl_property_erase_mode, 1));
	}

	check(cmfwdl_set_property(h, cmfwdl_property_allow_hw_channel_switch,
			1));
	check(cmfwdl_set_property(h, cmfwdl_property_boot_process_timeout,
			10000));
	check(cmfwdl_set_property(h, cmfwdl_property_comm_timeout, 10000));
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

	check(cmfwdl_enable_flashing(h, IFX_NODE0)); /* Switch to Flashing mode */

	/* First part of modem boot: initialization and open comm ports */
	check(cmfwdl_pre_boot_modem(h, cb, NULL));

	/* Get chip fusing parameters (print out in stdout and in a file) */
	if (b_fuse == 1) {
		if (cmfwdl_get_chip_response(h, fuse_data, CHIP_FUSE_SIZE) == 0) {
			for (i = 0; i < CHIP_FUSE_SIZE; ++i) {
				snprintf(&fuse_ascii[3*i], 3+1, "%02x ", fuse_data[i]);
			}
			snprintf(&fuse_ascii[3*CHIP_FUSE_SIZE-1], 1+1, "\n");
			fuse_buffer.size = 3*CHIP_FUSE_SIZE;
			printf("Chip fusing parameters: %s", fuse_ascii);
		} else {
			snprintf(&fuse_ascii[0], 1+1, "\n");
			fuse_buffer.size = 1;
			printf("Getting chip fusing parameters failed\n");
		}

		fuse_buffer.name = FUSE_FILE;
		fuse_buffer.data = (unsigned char *) fuse_ascii;
		check(store_data_to_file(&fuse_buffer));
		printf("Storing chip fusing parameters to file %s succeeded\n", fuse_buffer.name);
	}

	/* Second part of modem boot: not called if only fusing parameters are wanted */
	if ((b_bootloader == 1) || (b_fuse == 0)) {
		check(cmfwdl_boot_modem(h, &boot_buffer));
	}

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
	if (b_read_rd_certif == 1) {
		check(cmfwdl_queue_certificate_action(h, cmfwdl_certificate_RDC, cmfwdl_certificate_read, NULL))
	}

	if (b_bootloader == 1) {
		check(cmfwdl_execute(h, cb, NULL));
		cmfwdl_reset_ttyifx_parameters_for_nonflashing(h);
	}

	if (read_hw_id == 1) {
		p_buffer_hw_id = cmfwdl_get_hardware_id(h);

		if (p_buffer_hw_id != NULL) {
			p_buffer_hw_id->name = HW_ID_FILE;
			check(store_data_to_file(p_buffer_hw_id));
			printf("\nStoring HWID success: %s\n", p_buffer_hw_id->name);
			cmfwdl_free_buffer(h, p_buffer_hw_id);
		} else {
			printf("\nCAN GET HARDWARE ID !!\n");
			goto out;
		}
	}

	if (b_read_rd_certif == 1) {
		p_buffer_read_rd_certif = cmfwdl_get_certificate(h, cmfwdl_certificate_RDC);

		if (p_buffer_read_rd_certif != NULL) {
			p_buffer_read_rd_certif->name = RND_CERTIFICATE_FILE;
			check(store_data_to_file(p_buffer_read_rd_certif));
			printf("\nStoring RnD cert success: %s\n", p_buffer_read_rd_certif->name);
			cmfwdl_free_buffer(h, p_buffer_read_rd_certif);
		} else {
			printf("\nR&D CERTIFICATE NOT PRESENT !!\n");
			goto out;
		}
	}

	b_end_reboot = b_asked_reboot;
	ret = 0;
out:
	cmfwdl_destroy_instance(h, b_end_reboot);
	cmfwdl_disable_flashing(h, IFX_NODE0); /* Switch back to IPC mode */
	// wait for modem to reboot
	sleep(5);
	enable_pm();
	return ret;
}

int reset_modem()
{
	int fd;
	int retval = 1;

	fd = open(IFX_NODE0, O_RDWR);
	if ( ioctl(fd, FFL_TTY_MODEM_RESET) < 0 )
	{
		printf("Could not reset modem\n");
		retval = -1;
	}
	close(fd);
	return retval;
}
