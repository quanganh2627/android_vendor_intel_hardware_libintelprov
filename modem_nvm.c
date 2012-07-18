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
	cmfwdl_set_modemname(h, ifx6260);
	check(cmfwdl_set_ports(h, TTY_NODE, IFX_NODE));

	pbuffer_nvm_command = (struct cmfwdl_buffer*)malloc(sizeof(struct cmfwdl_buffer));
	pbuffer_nvm_response = (struct cmfwdl_buffer*)malloc(sizeof(struct cmfwdl_buffer));

	pbuffer_nvm_response->data = NULL;
	pbuffer_nvm_command->data = NULL;

	// read_file allocates the right buffer size according to the loaded file size
	if ((ret = cmfwdl_read_file(nvm_filename, pbuffer_nvm_command)) == 0)
	{
		cb("Sending NVM config to the modem...\r\n", OUTPUT_DEBUG | OUTPUT_FASTBOOT_INFO);
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
				cb((char*)pbuffer_nvm_response->data, OUTPUT_DEBUG | OUTPUT_FASTBOOT_INFO);
			}
		}
	}

	cmfwdl_free_buffer(h, pbuffer_nvm_command);
	cmfwdl_free_buffer(h, pbuffer_nvm_response);

out:

	cmfwdl_destroy_instance(h, CMFWDL_REBOOT);

	return ret;
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
	cmfwdl_set_modemname(h, ifx6260);
	check(cmfwdl_set_ports(h, TTY_NODE, IFX_NODE));

	pbuffer_nvm_response = (struct cmfwdl_buffer*)malloc(sizeof(struct cmfwdl_buffer));

	pbuffer_nvm_response->data = NULL;

	if ((ret = cmfwdl_nvm_config_read(h, pbuffer_nvm_response)) == 0)
	{
		cb("Reading NVM config ID from the modem...\r\n", OUTPUT_DEBUG);
		if (cb != NULL)
		{
			cb((char*)pbuffer_nvm_response->data, OUTPUT_DEBUG | OUTPUT_FASTBOOT_INFO);
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
		strncpy(out_buffer, (const char*)pbuffer_nvm_response->data, MIN(pbuffer_nvm_response->size, max_out_size));
	}

	cmfwdl_free_buffer(h, pbuffer_nvm_response);

out:

	cmfwdl_destroy_instance(h, CMFWDL_REBOOT);

	return ret;
}
