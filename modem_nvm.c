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

#define TTY_NODE	"/dev/ttyMFD1"
#define IFX_NODE	"/dev/ttyIFX0"

int flash_modem_nvm(const char *nvm_filename, modem_progress_callback cb)
{
	struct cmfwdl *h;
	int ret = -1;
	struct cmfwdl_buffer *pbuffer_nvm_command;
	struct cmfwdl_buffer *pbuffer_nvm_response;

	h = cmfwdl_create_instance();
	if (h == NULL)
	{
		return -1;
	}

	if (cb != NULL)
	{
		cb(cmfwdl_status_progress, 0, "", NULL);
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
		if ((ret = cmfwdl_nvm_config_send(h, pbuffer_nvm_command, pbuffer_nvm_response)) == CMFWDL_NVM_ERR_SUCESS)
		{
			if (cb != NULL)
			{
				cb(cmfwdl_status_msg_detail, 0, (char*)pbuffer_nvm_response->data, NULL);
			}
		}
		else
		{
			if (cb != NULL)
			{
				cb(cmfwdl_status_error_detail, 0, "Send NVM config failed.\r\n", NULL);
			}
		}
	}

	cmfwdl_free_buffer(h, pbuffer_nvm_command);
	cmfwdl_free_buffer(h, pbuffer_nvm_response);

out:

	cmfwdl_destroy_instance(h);

	if (cb != NULL)
	{
		cb(cmfwdl_status_progress, 100, "", NULL);
	}

	return ret;
}
