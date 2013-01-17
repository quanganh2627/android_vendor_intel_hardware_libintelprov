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

#include "minzip/Zip.h"
#include "util.h"
#include "modem_fw.h"
#include "modem_nvm.h"

#define check(val) if (0 != (val)) { \
		printf("flash_modem_fw: '%s' failed\n", #val); \
		goto out; \
	}

#define TTY_NODE            "/dev/ttyMFD1"
#define IFX_NODE            "/dev/ttyIFX0"

#define LOG_BUFF_SIZE       256

int flash_modem_nvm(const char *nvm_filename, modem_nvm_status_callback cb)
{
	struct cmfwdl *h;
	int ret = -1;
	struct cmfwdl_buffer *pbuffer_nvm_command;
	struct cmfwdl_buffer *pbuffer_nvm_response;
	char strBuff[LOG_BUFF_SIZE] = {'\0'};

	h = cmfwdl_create_instance();
	if (h == NULL)
	{
		return -1;
	}

	/* Set up various properties */
	cmfwdl_set_modemname(h, xmm6260);
	check(cmfwdl_set_ports(h, TTY_NODE, IFX_NODE));

	pbuffer_nvm_command = (struct cmfwdl_buffer*)malloc(sizeof(struct cmfwdl_buffer));
	pbuffer_nvm_response = (struct cmfwdl_buffer*)malloc(sizeof(struct cmfwdl_buffer));

	pbuffer_nvm_response->data = NULL;
	pbuffer_nvm_command->data = NULL;

	// read_file allocates the right buffer size according to the loaded file size
	if ((ret = cmfwdl_read_file(nvm_filename, pbuffer_nvm_command)) == 0)
	{
		if (cb != NULL)
		{
			cb("Sending NVM config to the modem...\r\n", OUTPUT_DEBUG | OUTPUT_FASTBOOT_INFO);
		}
		if ((ret = cmfwdl_nvm_config_send(h, pbuffer_nvm_command, pbuffer_nvm_response)) == CMFWDL_NVM_ERR_SUCESS)
		{
			if (cb != NULL)
			{
				cb("NVM Config OK\r\n", OUTPUT_DEBUG);
			}
		}
		else
		{
			if (cb != NULL)
			{
				snprintf(strBuff, LOG_BUFF_SIZE, "Send NVM config failed. Error %d\r\n", ret);
				cb(strBuff, OUTPUT_DEBUG | OUTPUT_FASTBOOT_INFO);
				if (pbuffer_nvm_response->data != NULL)
				{
					cb((char*)pbuffer_nvm_response->data, OUTPUT_DEBUG | OUTPUT_FASTBOOT_INFO);
				}
			}
		}
	}

	cmfwdl_free_buffer(h, pbuffer_nvm_command);
	cmfwdl_free_buffer(h, pbuffer_nvm_response);

out:

	// we reboot in any case to make sure we leave the modem
	// in correct state
	cmfwdl_destroy_instance(h, CMFWDL_REBOOT);

	return ret;
}

#define MAX_FILENAME_LEN 256
#define HARDWARE_ID_LEN  4
#define HW_ID_FILE_NAME  "/sys/spid/hardware_id"
#define DEFAULT_NVM_FILE "empty_config.tlv"
#define FILEMODE  S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH


char *read_spid(char *buffer, int len)
{
	int fd;
	int ret;
	if (buffer == NULL) {
		return NULL;
	}
	fd = open(HW_ID_FILE_NAME, O_RDONLY);
	if (fd < 0) {
		return NULL;
	}
	len = len < HARDWARE_ID_LEN ? len : HARDWARE_ID_LEN;
	ret = read(fd, buffer, len);
	if (ret < len) {
		buffer = NULL; /* will return NULL */
	}
	close(fd);
	return buffer;
}

int flash_modem_nvm_spid(const char *nvm_filename, modem_nvm_status_callback cb) {
	char spid_buf[HARDWARE_ID_LEN];
	char filenamebuffer[MAX_FILENAME_LEN];
	ZipArchive nvm_za;
	const ZipEntry *nvm_entry, *default_nvm_entry = NULL;
	int nvm_fd, err, num, i;
	int found = 0;
	int retval = 0;

	if (NULL == read_spid(spid_buf, HARDWARE_ID_LEN)) {
		if (cb != NULL)
		{
			cb("Error reading hardware_id\r\n", OUTPUT_DEBUG | OUTPUT_FASTBOOT_INFO);
		}
		return -1;
	}
	err = mzOpenZipArchive(nvm_filename, &nvm_za);
	if (err) {
		if (cb != NULL)
		{
			cb("Error opening archive\r\n", OUTPUT_DEBUG | OUTPUT_FASTBOOT_INFO);
		}
		return -1;
	}
	num = mzZipEntryCount(&nvm_za);
	for (i = 0; i < num; i++) {
		nvm_entry = mzGetZipEntryAt(&nvm_za, i);
		if (nvm_entry && strncmp(spid_buf, nvm_entry->fileName, HARDWARE_ID_LEN) == 0) {
			snprintf(filenamebuffer, MAX_FILENAME_LEN, "/tmp/modem_%s_nvm.tlv", spid_buf);
			nvm_fd = open(filenamebuffer, O_RDWR | O_TRUNC | O_CREAT, FILEMODE);
			if (nvm_fd < 0) {
				if (cb != NULL)
				{
					cb("Error creating tmp file\r\n", OUTPUT_DEBUG | OUTPUT_FASTBOOT_INFO);
				}
				retval = -2;
				goto closezip;
			}
			err = mzExtractZipEntryToFile(&nvm_za, nvm_entry, nvm_fd);
			close(nvm_fd);
			if (!err) {
				if (cb != NULL)
				{
					cb("Error extracting file\r\n", OUTPUT_DEBUG | OUTPUT_FASTBOOT_INFO);
				}
				retval = -1;
				goto closezip;
			}
			if (flash_modem_nvm(filenamebuffer, cb)) {
				if (cb != NULL)
				{
					cb("Error flashing file\r\n", OUTPUT_DEBUG | OUTPUT_FASTBOOT_INFO);
				}
				retval = -1;
				goto closezip;
			}
			found = 1;
			break;
		} else if (nvm_entry && strncmp(nvm_entry->fileName, DEFAULT_NVM_FILE, strlen(DEFAULT_NVM_FILE))) {
			default_nvm_entry = nvm_entry;
		} else {
			goto closezip;
		}
	}
	if (!found && default_nvm_entry != NULL) {
		if (cb != NULL)
		{
			cb("No config file found for this HW, using default one\r\n", OUTPUT_DEBUG | OUTPUT_FASTBOOT_INFO);
		}
		snprintf(filenamebuffer, MAX_FILENAME_LEN, "/tmp/%s", DEFAULT_NVM_FILE);
		nvm_fd = open(filenamebuffer, O_RDWR | O_TRUNC | O_CREAT, FILEMODE);
		if (nvm_fd < 0) {
			if (cb != NULL)
			{
				cb("Error while opening default config file\r\n", OUTPUT_DEBUG | OUTPUT_FASTBOOT_INFO);
			}
			retval = -2;
			goto closezip;
		}
		err = mzExtractZipEntryToFile(&nvm_za, default_nvm_entry, nvm_fd);
		close(nvm_fd);
		if (!err) {
			if (cb != NULL)
			{
				cb("Error extracting default config file\r\n", OUTPUT_DEBUG | OUTPUT_FASTBOOT_INFO);
			}
			retval = -1;
			goto closezip;
		}
		if (flash_modem_nvm(filenamebuffer, cb)) {
			if (cb != NULL)
			{
				cb("NVM flash failed\r\n", OUTPUT_DEBUG | OUTPUT_FASTBOOT_INFO);
			}
			retval = -1;
			goto closezip;
		}
	}
closezip:
	mzCloseZipArchive(&nvm_za);
	return retval;
}



int read_modem_nvm_id(char* out_buffer, size_t max_out_size, modem_nvm_status_callback cb)
{
	struct cmfwdl *h;
	int ret = -1;
	struct cmfwdl_buffer *pbuffer_nvm_response;

	h = cmfwdl_create_instance();
	if (h == NULL)
	{
		return -1;
	}

	/* Set up various properties */
	cmfwdl_set_modemname(h, xmm6260);
	check(cmfwdl_set_ports(h, TTY_NODE, IFX_NODE));

	pbuffer_nvm_response = (struct cmfwdl_buffer*)malloc(sizeof(struct cmfwdl_buffer));

	pbuffer_nvm_response->data = NULL;

	if ((ret = cmfwdl_nvm_config_read(h, pbuffer_nvm_response)) == 0)
	{
		cb("Reading NVM config ID from the modem...\r\n", OUTPUT_DEBUG);
		if (cb != NULL)
		{
			if (pbuffer_nvm_response->data != NULL)
			{
				cb((char*)pbuffer_nvm_response->data, OUTPUT_DEBUG | OUTPUT_FASTBOOT_INFO);
			}
		}
	}
	else
	{
		if (cb != NULL)
		{
			cb("Read NVM config failed.\r\n", OUTPUT_DEBUG | OUTPUT_FASTBOOT_INFO);
		}
	}

	if (out_buffer != NULL)
	{
		if (pbuffer_nvm_response->data != NULL)
		{
			strncpy(out_buffer, (const char*)pbuffer_nvm_response->data, MIN(pbuffer_nvm_response->size, max_out_size));
		}
	}

	cmfwdl_free_buffer(h, pbuffer_nvm_response);

out:

	cmfwdl_destroy_instance(h, CMFWDL_REBOOT);

	return ret;
}
