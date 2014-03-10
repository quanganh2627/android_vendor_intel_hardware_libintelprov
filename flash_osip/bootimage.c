/*
 * Copyright 2014 Intel Corporation
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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "util.h"
#include "update_osip.h"
#include "flash.h"
#include "../gpt/partlink/partlink.h"

#define OSIP_SIG_SIZE		480

bool is_osip(void)
{
	struct stat buf;
	return !(stat(BASE_PLATFORM_INTEL_LABEL "/fastboot", &buf) == 0 && S_ISBLK(buf.st_mode));
}

int read_image_osip(const char *name, void **data)
{
	int index;
	size_t size;

	index = get_named_osii_index(name);
	if (index < 0) {
		error("Can't find image %s in the OSIP\n", name);
		return -1;
	}

	if (read_osimage_data(data, &size, index)) {
		error("Failed to read OSIP entry\n");
		return -1;
	}
	return size;
}

int flash_image_osip(void *data, unsigned sz, const char *name)
{
	int index;

	if (!strcmp(name, TEST_OS_NAME)) {
		oem_write_osip_header(0, 0);
		return write_stitch_image_ex(data, sz, ANDROID_OS_NUM, 1);

	}

	index = get_named_osii_index(name);

	if (index < 0) {
		error("Can't find OSII index!!\n");
		return -1;
	}

	return write_stitch_image(data, sz, index);
}

int read_image_signature_osip(void **buf, char *name)
{
	int fd = -1;
	int sig_size;
	int offset;
	int image_index;
	struct OSIP_header osip;

	image_index = get_named_osii_index(name);
	if (image_index < 0) {
		error("Can't find %s index in the OSIP", name);
		goto err;
	}

	fd = open(MMC_DEV_POS, O_RDONLY);
	if (fd < 0) {
		error("open: %s", strerror(errno));
		goto err;
	}

	offset = osip.desc[image_index].logical_start_block * LBA_SIZE;
	if (lseek(fd, offset, SEEK_SET) < 0) {
		error("lseek: %s", strerror(errno));
		goto close;
	}

	sig_size = OSIP_SIG_SIZE;
	*buf = malloc(sig_size);
	if (!*buf) {
		error("Failed to allocate signature buffer\n");
		goto close;
	}

	if (safe_read(fd, *buf, sig_size)) {
		error("read: %s", strerror(errno));
		goto free;
	}

	close(fd);
	return sig_size;

free:
	free(*buf);
close:
	close(fd);
err:
	return -1;
}

int is_image_signed_osip(const char *name)
{
	struct OSIP_header osip;
	int ret = -1;
	int recovery_index;

	if (read_OSIP(&osip)) {
		error("Can't read the OSIP");
		goto out;
	}

	recovery_index = get_named_osii_index(RECOVERY_OS_NAME);

	if (recovery_index < 0) {
		error("Can't find recovery console in the OSIP");
		goto out;
	}
	ret = osip.desc[recovery_index].attribute & ATTR_UNSIGNED_KERNEL ? 0 : 1;
out:
	return ret;
}
