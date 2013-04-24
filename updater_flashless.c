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

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <edify/expr.h>
#include <updater/updater.h>

#include "update_osip.h"
#include "util.h"
#include "fw_version_check.h"
#include "flash_ifwi.h"
#include "miu.h"

static void miu_progress_cb(int progress, int total)
{
	printf("Progress: %d / %d\n", progress, total);
}

static void miu_log_cb(const char *msg, ...)
{
	va_list ap;

	if (msg != NULL) {
		va_start(ap, msg);
		vprintf(msg, ap);
		va_end(ap);
	}
}

Value *ExtractOsipFn(const char *name, State * state, int argc, Expr * argv[])
{
	Value *ret = NULL;
	char *filename = NULL;
	char *source = NULL;
	int osii_index;
	void *data = NULL;
	size_t size;

	if (ReadArgs(state, argv, 2, &filename, &source) < 0) {
		return NULL;
	}

	if (filename == NULL || strlen(filename) == 0) {
		ErrorAbort(state, "filename argument to %s can't be empty",
			   name);
		goto done;
	}

	if (source == NULL || strlen(source) == 0) {
		ErrorAbort(state, "source argument to %s can't be empty", name);
		goto done;
	}

	osii_index = get_named_osii_index(source);
	if (osii_index < 0) {
		ErrorAbort(state, "Can't get OSII index for %s", source);
		goto done;
	}

	if (read_osimage_data(&data, &size, osii_index) < 0) {
		ErrorAbort(state, "Couldn't read osip[%d]", osii_index);
		goto done;
	}

	if (file_write(filename, data, size) < 0) {
		ErrorAbort(state, "Couldn't write osii[%d] data to %s",
			   osii_index, filename);
		goto done;
	}

	ret = StringValue(strdup(""));
done:
	if (source)
		free(source);
	if (filename)
		free(filename);
	if (data)
		free(data);

	return ret;
}

Value *FlashOsipFn(const char *name, State * state, int argc, Expr * argv[])
{
	Value *ret = NULL;
	char *filename = NULL;
	char *destination = NULL;
	int osii_index;
	void *image_data = NULL;
	size_t image_size;

	if (ReadArgs(state, argv, 2, &filename, &destination) < 0) {
		return NULL;
	}

	if (filename == NULL || strlen(filename) == 0) {
		ErrorAbort(state, "filename argument to %s can't be empty",
			   name);
		goto done;
	}

	if (destination == NULL || strlen(destination) == 0) {
		ErrorAbort(state, "destination argument to %s can't be empty",
			   name);
		goto done;
	}

	if (file_read(filename, &image_data, &image_size)) {
		ErrorAbort(state, "Cannot open os image %s", filename);
		goto done;
	}

	osii_index = get_named_osii_index(destination);

	if (osii_index < 0) {
		ErrorAbort(state, "Can't get OSII index for %s", destination);
		goto done;
	}

	if (write_stitch_image(image_data, image_size, osii_index)) {
		ErrorAbort(state, "Error writing %s image %s to OSIP%d",
			   destination, filename, osii_index);
		goto done;
	}

	ret = StringValue(strdup(""));
done:
	if (image_data)
		free(image_data);
	if (destination)
		free(destination);
	if (filename)
		free(filename);

	return ret;
}

Value *ExecuteOsipFunction(const char *name, State * state, int argc,
			   Expr * argv[], int (*action) (char *))
{
	Value *ret = NULL;
	char *destination = NULL;

	if (ReadArgs(state, argv, 1, &destination) < 0) {
		return NULL;
	}

	if (destination == NULL || strlen(destination) == 0) {
		ErrorAbort(state, "destination argument to %s can't be empty",
			   name);
		goto done;
	}

	if (action(destination) == -1) {
		ErrorAbort(state, "Error writing %s to OSIP", destination);
		goto done;
	}

	ret = StringValue(strdup(""));

done:
	if (destination)
		free(destination);

	return ret;
}

Value *InvalidateOsFn(const char *name, State * state, int argc, Expr * argv[])
{
	return ExecuteOsipFunction(name, state, argc, argv, invalidate_osii);
}

Value *RestoreOsFn(const char *name, State * state, int argc, Expr * argv[])
{
	return ExecuteOsipFunction(name, state, argc, argv, restore_osii);
}

#define DNX_BIN_PATH	"/tmp/dnx.bin"
#define IFWI_BIN_PATH	"/tmp/ifwi.bin"
#define IFWI_NAME	"ifwi"
#define DNX_NAME	"dnx"
#define FILEMODE  S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH

Value *FlashIfwiFn(const char *name, State * state, int argc, Expr * argv[])
{
	Value *ret = NULL;
	char *filename = NULL;
	int err, ifwi_bin_fd, dnx_bin_fd, i, num;
	char ifwi_name[128], dnx_name[128];
	ZipArchive ifwi_za;
	const ZipEntry *dnx_entry, *ifwi_entry;

	if (ReadArgs(state, argv, 1, &filename) < 0) {
		return NULL;
	}

	if (filename == NULL || strlen(filename) == 0) {
		ErrorAbort(state, "filename argument to %s can't be empty",
			   name);
		goto done;
	}

	err = mzOpenZipArchive(filename, &ifwi_za);
	if (err) {
		ErrorAbort(state, "Failed to open zip archive %s\n", filename);
		goto done;
	}

	num = mzZipEntryCount(&ifwi_za);
	for (i = 0; i < num; i++) {
		ifwi_entry = mzGetZipEntryAt(&ifwi_za, i);
		if ((ifwi_entry->fileNameLen + 1) < sizeof(ifwi_name)) {
			strncpy(ifwi_name, ifwi_entry->fileName,
				ifwi_entry->fileNameLen);
			ifwi_name[ifwi_entry->fileNameLen] = '\0';
		} else {
			ErrorAbort(state,
				   "ifwi file name is too big. Size max is:%d.\n",
				   sizeof(ifwi_name));
			goto error;
		}
		if (strncmp(ifwi_name, IFWI_NAME, strlen(IFWI_NAME)))
			continue;

		if ((ifwi_bin_fd =
		     open(IFWI_BIN_PATH, O_RDWR | O_TRUNC | O_CREAT,
			  FILEMODE)) < 0) {
			ErrorAbort(state,
				   "unable to create Extracted file:%s.\n",
				   IFWI_BIN_PATH);
			goto error;
		}
		if ((dnx_bin_fd =
		     open(DNX_BIN_PATH, O_RDWR | O_TRUNC | O_CREAT,
			  FILEMODE)) < 0) {
			ErrorAbort(state,
				   "unable to create Extracted file:%s.\n",
				   IFWI_BIN_PATH);
			close(ifwi_bin_fd);
			goto error;
		}
		strcpy(dnx_name, "dnx");
		strncat(dnx_name, &(ifwi_name[strlen(IFWI_NAME)]),/* if(miu_flash_modem_nvm_for_spid(nvm_path, hwid, HARDWARE_ID_LEN) == E_MIU_ERR_SUCCESS) { retval = 0;
		* pr_info("%s successful\n", __func__); } else { pr_error("%s failed with error: %i\n", __func__,
		* retval); retval = -1; } */
			sizeof(dnx_name) - strlen("dnx") - 1);
		dnx_entry = mzFindZipEntry(&ifwi_za, dnx_name);

		if (dnx_entry == NULL) {
			ErrorAbort(state, "Could not find DNX entry");
			close(ifwi_bin_fd);
			close(dnx_bin_fd);
			goto error;
		}

		err = mzExtractZipEntryToFile(&ifwi_za, dnx_entry, dnx_bin_fd);
		if (!err) {
			ErrorAbort(state, "Failed to unzip %s\n", DNX_BIN_PATH);
			close(ifwi_bin_fd);
			close(dnx_bin_fd);
			goto error;
		}
		close(dnx_bin_fd);
		err =
		    mzExtractZipEntryToFile(&ifwi_za, ifwi_entry, ifwi_bin_fd);
		if (!err) {
			ErrorAbort(state, "Failed to unzip %s\n", DNX_BIN_PATH);
			close(ifwi_bin_fd);
			goto error;
		}
		close(ifwi_bin_fd);
		update_ifwi_file(DNX_BIN_PATH, IFWI_BIN_PATH);
	}

	ret = StringValue(strdup(""));

error:
	mzCloseZipArchive(&ifwi_za);

done:
	if (filename)
		free(filename);

	return ret;
}

#define MODEM_PATH   "/tmp/radio_firmware.bin"
#define MODEM_NAME   "radio_firmware"

Value *FlashModemFn(const char *name, State * state, int argc, Expr * argv[])
{
	Value *ret = NULL;
	char *filename = NULL;
	e_miu_flash_options_t flash_options = 0;

	if (ReadArgs(state, argv, 1, &filename) < 0) {
		return NULL;
	}

	if (filename == NULL || strlen(filename) == 0) {
		ErrorAbort(state, "filename argument to %s can't be empty",
			   name);
		goto done;
	}
	if (miu_initialize(miu_progress_cb, miu_log_cb) != E_MIU_ERR_SUCCESS) {
		printf("%s failed at %s\n", __func__, "miu_initialize failed");
	} else {
		if (miu_flash_modem_fw(filename, flash_options) !=
		    E_MIU_ERR_SUCCESS) {
			printf("error during 3G Modem flashing!\n");
		}
		miu_dispose();
	}

	ret = StringValue(strdup(""));
done:
	if (filename)
		free(filename);

	return ret;
}

Value *FlashNvmFn(const char *name, State * state, int argc, Expr * argv[])
{
	Value *ret = NULL;
	char *filename = NULL;

	if (ReadArgs(state, argv, 1, &filename) < 0) {
		return NULL;
	}

	if (filename == NULL || strlen(filename) == 0) {
		ErrorAbort(state, "filename argument to %s can't be empty",
			   name);
		goto done;
	}
	if (miu_initialize(miu_progress_cb, miu_log_cb) != E_MIU_ERR_SUCCESS) {
		printf("%s failed at %s\n", __func__, "miu_initialize failed");
	} else {
		if (miu_flash_modem_nvm(filename) != E_MIU_ERR_SUCCESS) {
			printf("error during 3G Modem NVM config!\n");
		}
		miu_dispose();
	}

	ret = StringValue(strdup(""));
done:
	if (filename)
		free(filename);

	return ret;
}

Value *FlashSpidNvmFn(const char *name, State * state, int argc, Expr * argv[])
{
	Value *ret = NULL;
	char *filename = NULL;

	if (ReadArgs(state, argv, 1, &filename) < 0) {
		return NULL;
	}

	if (filename == NULL || strlen(filename) == 0) {
		ErrorAbort(state, "filename argument to %s can't be empty",
			   name);
		goto done;
	}

	ret = StringValue(strdup(""));
done:
	if (filename)
		free(filename);

	return ret;
}

void Register_libintel_updater(void)
{
	RegisterFunction("flash_osip", FlashOsipFn);
	RegisterFunction("flash_ifwi", FlashIfwiFn);
	RegisterFunction("flash_modem", FlashModemFn);
	RegisterFunction("flash_nvm", FlashNvmFn);
	RegisterFunction("flash_nvm_spid", FlashSpidNvmFn);
	RegisterFunction("extract_osip", ExtractOsipFn);
	RegisterFunction("invalidate_os", InvalidateOsFn);
	RegisterFunction("restore_os", RestoreOsFn);
}
