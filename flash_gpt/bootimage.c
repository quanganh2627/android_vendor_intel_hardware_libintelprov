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

#include <bootimg.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include "../gpt/partlink/partlink.h"
#include "../gpt/diskd/diskd.h"
#include "util.h"
#include "flash.h"

static char *try_prefix(const char *prefix, const char *name)
{
	char *path;
	struct stat buf;

	int ret = asprintf(&path, "%s/%s", prefix, name);
	if (ret == -1) {
		error("%s: Failed to build %s/%s path\n", prefix, name);
		return NULL;
	}

	if (stat(path, &buf) == 0 && S_ISBLK(buf.st_mode))
		return path;

	free(path);
	return NULL;
}

static const char *PREFIXES[] = { DISK_BY_LABEL_DIR, BASE_PLATFORM_INTEL_LABEL };

int get_gpt_path(char **path, const char *name)
{
	if (!name) {
		error("%s: Passed name is empty.\n", __func__);
		return -1;
	}

	unsigned int i;
	char *tmp;
	for (i = 0 ; i < ARRAY_SIZE(PREFIXES) ; i++) {
		tmp = try_prefix(PREFIXES[i], name);
		if (tmp) {
			*path = tmp;
			return 0;
		}
	}

	return -1;
}

bool is_gpt(void)
{
	char *path = NULL;

	if (!get_gpt_path(&path, "fastboot"))
		free(path);

	return !!path;
}

int flash_image_gpt(void *data, unsigned sz, const char *name)
{
	char *block_dev;
	int ret;

	if (!strcmp(name, TEST_OS_NAME))
		name = ANDROID_OS_NAME;

	if (get_gpt_path(&block_dev, name))
		return -1;

	ret = file_write(block_dev, data, sz);
	free(block_dev);
	return ret;
}

static int pages(struct boot_img_hdr *hdr, int blob_size)
{
	return (blob_size + hdr->page_size - 1) / hdr->page_size;
}

int open_bootimage(const char *name)
{
	char *block_dev;
	int fd = -1;

	if (get_gpt_path(&block_dev, name))
		goto out;

	fd = open(block_dev, O_RDONLY);
	if (fd < 0)
		error("Failed to open %s: %s\n", block_dev, strerror(errno));

	free(block_dev);
out:
	return fd;
}

/* Fill hdr with bootimage's header and return image's size */
ssize_t bootimage_size(int fd, struct boot_img_hdr * hdr, bool include_sig)
{
	ssize_t size = -1;

	if (safe_read(fd, hdr, sizeof(*hdr))) {
		error("Failed to read image header: %s\n", strerror(errno));
		goto out;
	}

	if (memcmp(hdr->magic, BOOT_MAGIC, sizeof(hdr->magic))) {
		error("Image is corrupted (bad magic)\n");
		goto out;
	}

	size = (1 + pages(hdr, hdr->kernel_size) +
		pages(hdr, hdr->ramdisk_size) + pages(hdr, hdr->second_size)) * hdr->page_size;

	if (include_sig)
		size += pages(hdr, hdr->sig_size) * hdr->page_size;

out:
	return size;
}

int read_image_gpt(const char *name, void **data)
{
	ssize_t size;
	struct boot_img_hdr hdr;
	int ret = -1;
	int fd;

	fd = open_bootimage(name);
	if (fd < 0) {
		error("Failed to open %s image\n", name);
		goto out;
	}

	size = bootimage_size(fd, &hdr, true);
	if (size <= 0) {
		error("Invalid %s image\n", name);
		goto out;
	}

	if (lseek(fd, 0, SEEK_SET) < 0) {
		error("Seek to beginning of file failed: %s\n", strerror(errno));
		goto out;
	}

	*data = malloc(size);
	if (!*data) {
		error("Memory allocation failure\n");
		goto close;
	}

	ret = safe_read(fd, *data, size);
	if (ret)
		free(*data);
	else
		ret = size;
close:
	close(fd);
out:
	return ret;
}

int read_image_signature_gpt(void **buf, char *name)
{
	int fd = -1;
	int sig_size;
	struct boot_img_hdr hdr;
	ssize_t img_size;

	fd = open_bootimage(name);
	if (fd < 0) {
		error("open: %s", strerror(errno));
		goto err;
	}

	img_size = bootimage_size(fd, &hdr, false);
	if (img_size <= 0) {
		error("Invalid image\n");
		goto close;
	}

	if (lseek(fd, img_size, SEEK_SET) < 0) {
		error("lseek: %s", strerror(errno));
		goto close;
	}

	sig_size = hdr.sig_size;
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

int is_image_signed_gpt(const char *name)
{
	struct boot_img_hdr hdr;
	int ret = -1;
	int fd;
	char *path = NULL;

	if (get_gpt_path(&path, "/recovery")) {
		error("Unable to find the device path for the recovery boot image\n");
		goto out;
	}

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		error("open: %s", strerror(errno));
		goto out;
	}

	if (safe_read(fd, &hdr, sizeof(hdr))) {
		error("read: %s", strerror(errno));
		goto close;
	}

	ret = hdr.sig_size == 0 ? 0 : 1;
close:
	close(fd);
out:
	free(path);
	return ret;
}
