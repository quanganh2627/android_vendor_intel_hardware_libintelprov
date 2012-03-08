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
#include <sys/ioctl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "flash_ifwi.h"
#include "fw_version_check.h"

#define DNX_SYSFS_INT	 "/sys/devices/pci0000:00/0000:00:01.7/DnX"
#define IFWI_SYSFS_INT	 "/sys/devices/pci0000:00/0000:00:01.7/ifwi"
#define PREP_SYSFS_INT	 "/sys/devices/pci0000:00/0000:00:01.7/scu_ipc/medfw_prepare"

#define BUF_SIZ	4096

#define IPC_DEVICE_NAME		"/dev/mid_ipc"
#define DEVICE_FW_UPGRADE	0xA4

#define pr_perror(x)	fprintf(stderr, "update_ifwi_image: %s failed: %s\n", \
		x, strerror(errno))

struct update_info{
	uint32_t ifwi_size;
	uint32_t reset_after_update;
	uint32_t reserved;
};

int update_ifwi_file(const char *dnx, const char *ifwi)
{
	int fupd_hdr_len, fsize, dnx_size, ret = 0;
	size_t cont;
	char buff[BUF_SIZ];
	FILE *f_src, *f_dst;
	struct stat sb_ifwi, sb_dnx;
	struct fw_version img_ifwi_rev;
	struct firmware_versions dev_fw_rev;

	if (crack_update_fw(ifwi, &img_ifwi_rev)) {
		fprintf(stderr, "Coudn't crack ifwi file!\n");
		return -1;
	}
	if (get_current_fw_rev(&dev_fw_rev)) {
		fprintf(stderr, "Couldn't query existing IFWI version\n");
		return -1;
	}
	if (img_ifwi_rev.major != dev_fw_rev.ifwi.major) {
		fprintf(stderr, "IFWI FW Major version numbers (file=%02X current=%02X) don't match, Update abort.\n",
				img_ifwi_rev.major, 	dev_fw_rev.ifwi.major);
		goto end;
	}

	if (img_ifwi_rev.minor <= dev_fw_rev.ifwi.minor) {
		fprintf(stderr, "IFWI FW is not new than board's existing version (file=%02X current=%02X), Update abort.\n",
				img_ifwi_rev.minor, dev_fw_rev.ifwi.minor);
		goto end;
	}

	f_src = fopen(dnx, "rb");
	if (f_src == NULL) {
		fprintf(stderr, "open %s failed\n", dnx);
		ret = -1;
		goto end;
	}
	if (fstat(fileno(f_src), &sb_dnx) == -1) {
		fprintf(stderr, "get %s fstat failed\n", dnx);
		ret = -1;
		goto err;
	}

	f_dst = fopen(DNX_SYSFS_INT, "wb");
	if (f_dst == NULL) {
		fprintf(stderr, "open %s failed\n", DNX_SYSFS_INT);
		ret = -1;
		goto err;
	}
	while ((cont = fread(buff, 1, sizeof(buff), f_src)) && cont <= sizeof(buff))
		fwrite(buff, 1, cont, f_dst);
	fclose(f_src);
	fclose(f_dst);

	f_src = fopen(ifwi, "rb");
	if (f_src == NULL) {
		fprintf(stderr, "open %s failed\n", ifwi);
		ret = -1;
		goto end;
	}
	if (fstat(fileno(f_src), &sb_ifwi) == -1) {
		fprintf(stderr, "get %s fstat failed\n", ifwi);
		ret = -1;
		goto err;
	}
	f_dst = fopen(IFWI_SYSFS_INT, "wb");
	if (f_dst == NULL) {
		fprintf(stderr, "open %s failed\n", IFWI_SYSFS_INT);
		ret = -1;
		goto err;
	}
	while ((cont = fread(buff, 1, sizeof(buff), f_src)) && cont <= sizeof(buff))
		fwrite(buff, 1, cont, f_dst);
	fclose(f_src);
	fclose(f_dst);

	f_src = fopen(PREP_SYSFS_INT, "r");
	if (f_src == NULL) {
		fprintf(stderr, "open %s failed\n", PREP_SYSFS_INT);
		ret = -1;
		goto end;
	}
	cont = fread(buff, 1, sizeof(buff), f_src);
	buff[cont] = '\0';
	printf("%s\n", buff);
	sscanf(buff, "fupd_hdr_len=%d, fsize=%d, dnx_size=%d",
		&fupd_hdr_len, &fsize, &dnx_size);
	if ((sb_dnx.st_size == dnx_size) && (sb_ifwi.st_size == fsize))
		fprintf(stderr, "IFWI update prepare successed\n");
	else {
		fprintf(stderr, "IFWI update prepare failed\n");
		ret = -1;
	}

err:
	fclose(f_src);
end:
	return ret;
}

int update_ifwi_image(void *data, size_t size, unsigned reset_flag)
{
	struct update_info *packet;
	int ret = -1;
	int fd;
	struct firmware_versions img_fw_rev;
	struct firmware_versions dev_fw_rev;

	/* Sanity check: If the Major version numbers do not match
	 * refuse to install; the versioning scheme in use encodes
	 * the device type in the major version number. This is not
	 * terribly robust but there isn't any additional metadata
	 * encoded within the IFWI image that can help us */
	if (get_image_fw_rev(data, size, &img_fw_rev)) {
		fprintf(stderr, "update_ifwi_image: Coudn't extract FW "
				"version data from image\n");
		return -1;
	}
	if (get_current_fw_rev(&dev_fw_rev)) {
		fprintf(stderr, "update_ifwi_image: Couldn't query existing "
				"IFWI version\n");
		return -1;
	}
	if (img_fw_rev.ifwi.major != dev_fw_rev.ifwi.major) {
		fprintf(stderr, "update_ifwi_image: IFWI FW Major version "
				"numbers (file=%02X current=%02X don't match. "
				"Abort.\n", img_fw_rev.ifwi.major,
				dev_fw_rev.ifwi.major);
		return -1;
	}

	packet = malloc(size + sizeof(struct update_info));
	if (!packet) {
		pr_perror("malloc");
		return -1;
	}

	memcpy(packet + 1, data, size);
	packet->ifwi_size = size;
	packet->reset_after_update = reset_flag;
	packet->reserved = 0;

	printf("update_ifwi_image -- size: %d reset: %d\n",
			packet->ifwi_size, packet->reset_after_update);
	fd = open(IPC_DEVICE_NAME, O_RDWR);
	if (fd < 0) {
		pr_perror("open");
		goto out;
	}
	sync(); /* reduce the chance of EMMC contention */
	ret = ioctl(fd, DEVICE_FW_UPGRADE, packet);
	close(fd);
	if (ret < 0)
		pr_perror("DEVICE_FW_UPGRADE");
out:
	free(packet);
	return ret;
}
