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
#include "util.h"
#include "fw_version_check.h"

#define DNX_SYSFS_INT		"/sys/devices/ipc/intel_fw_update.0/dnx"
#define DNX_SYSFS_INT_ALT   "/sys/kernel/fw_update/dnx"

#define IFWI_SYSFS_INT		"/sys/devices/ipc/intel_fw_update.0/ifwi"
#define IFWI_SYSFS_INT_ALT  "/sys/kernel/fw_update/ifwi"

#define BUF_SIZ	4096

#define IPC_DEVICE_NAME		"/dev/mid_ipc"
#define DEVICE_FW_UPGRADE	0xA4

#define PTI_ENABLE_BIT		(1<<7)	/* For testing if PTI is enabled or disabled. */

#define pr_perror(x)	fprintf(stderr, "update_ifwi_image: %s failed: %s\n", \
		x, strerror(errno))

#define CLVT_MINOR_CHECK 0x80 /* Mask applied to check IFWI compliance */

#define CAPSULE_PARTITION_NAME "/dev/block/platform/intel/by-label/FWUP"
#define CAPSULE_UPDATE_FLAG_PATH "/sys/firmware/osnib/fw_update"
#define ULPMC_PATH "/dev/ulpmc-fwupdate"

struct update_info{
	uint32_t ifwi_size;
	uint32_t reset_after_update;
	uint32_t reserved;
};

int ifwi_downgrade_allowed(const char *ifwi)
{
	uint8_t pti_field;

	if (crack_update_fw_pti_field(ifwi, &pti_field)) {
		fprintf(stderr, "Coudn't crack ifwi file to get PTI field!\n");
		return -1;
	}

	/* The SMIP offset 0x30C bit 7 indicates if the PTI is enabled/disabled. */
	/* If PTI is enabled, DEV/DBG IFWI: IFWI downgrade allowed.              */
	/* If PTI is disabled, end user/PROD IFWI: IFWI downgrade not allowed.   */

	if (pti_field & PTI_ENABLE_BIT)
		return 1;

	return 0;
}

#ifdef MRFLD

#define BOOT0 "/dev/block/mmcblk0boot0"
#define BOOT1 "/dev/block/mmcblk0boot1"
#define BOOT_PARTITION_SIZE 0x400000

#define IFWI_TYPE_LSH 12

void dump_fw_versions_long(struct firmware_versions_long *v)
{
	fprintf(stderr, "	   ifwi: %04X.%04X\n", v->ifwi.major, v->ifwi.minor);
	fprintf(stderr, "---- components ----\n");
	fprintf(stderr, "	    scu: %04X.%04X\n", v->scu.major, v->scu.minor);
	fprintf(stderr, "    hooks/oem: %04X.%04X\n", v->valhooks.major, v->valhooks.minor);
	fprintf(stderr, "	   ia32: %04X.%04X\n", v->ia32.major, v->ia32.minor);
	fprintf(stderr, "	 chaabi: %04X.%04X\n", v->chaabi.major, v->chaabi.minor);
	fprintf(stderr, "	    mIA: %04X.%04X\n", v->mia.major, v->mia.minor);
}

int write_image(int fd, char *image, unsigned size)
{
	int ret = 0;
	char *ptr = NULL;

	ptr = image;
	if (!ptr) {
		fprintf(stderr, "write_image(): Image is invalid\n");
		return -1;
	}

	while(size) {
	/*If this condition is not present, the write*/
	/*function errors out while writing the last chunk*/
		ret = write(fd, ptr, size);
		if (ret <= 0 && errno != EINTR) {
			fprintf(stderr, "write_image(): image write failed with errno %d\n", errno);
			return -1;
		}
		ptr += ret;
		size -= ret;
	}

	fsync(fd);
	return 0;
}

int update_ifwi_file(void *data, unsigned size)
{
	int boot0_fd, boot1_fd, ret = 0;
	struct firmware_versions_long dev_fw_rev, img_fw_rev;

	if (get_image_fw_rev_long(data, size, &img_fw_rev)) {
		fprintf(stderr, "Coudn't extract FW version data from image\n");
		return -1;
	}
	fprintf(stderr, "Image FW versions:\n");
	dump_fw_versions_long(&img_fw_rev);

	if (get_current_fw_rev_long(&dev_fw_rev)) {
		fprintf(stderr, "Couldn't query existing IFWI version\n");
		return -1;
	}
	fprintf(stderr, "Attempting to flash ifwi image version %04X.%04X over ifwi current version %04X.%04X\n",
		img_fw_rev.ifwi.major,img_fw_rev.ifwi.minor,dev_fw_rev.ifwi.major,dev_fw_rev.ifwi.minor);

	if (img_fw_rev.ifwi.major != dev_fw_rev.ifwi.major) {
		fprintf(stderr, "IFWI FW Major version numbers (file=%04X current=%04X) don't match, Update abort.\n",
			img_fw_rev.ifwi.major, dev_fw_rev.ifwi.major);

		/* Not an error case. Let update continue to next IFWI versions. */
		return 0;
	}

	if ( (img_fw_rev.ifwi.minor >> IFWI_TYPE_LSH) != (dev_fw_rev.ifwi.minor >> IFWI_TYPE_LSH) ) {
		fprintf(stderr, "IFWI FW Type (file=%1X current=%1X) don't match, Update abort.\n",
			img_fw_rev.ifwi.minor >> IFWI_TYPE_LSH, dev_fw_rev.ifwi.minor >> IFWI_TYPE_LSH);

		/* Not an error case. Let update continue to next IFWI versions. */
		return 0;
	}

	if (size > BOOT_PARTITION_SIZE) {
		fprintf(stderr, "flash_ifwi(): Truncating last %d bytes from the IFWI\n",
		(size - BOOT_PARTITION_SIZE));
		/* Since the last 144 bytes are the FUP header which are not required,*/
		/* we truncate it to fit into the boot partition. */
		size = BOOT_PARTITION_SIZE;
	}

	boot0_fd = open(BOOT0, O_RDWR);
	if (boot0_fd < 0) {
		fprintf(stderr, "flash_ifwi(): failed to open %s\n", BOOT0);
		return -1;
	}
	boot1_fd = open(BOOT1, O_RDWR);
	if (boot1_fd < 0) {
		fprintf(stderr, "flash_ifwi(): failed to open %s\n", BOOT1);
		close(boot0_fd);
		return -1;
	}

	if (lseek(boot0_fd, 0, SEEK_SET) < 0) { /* Seek to start of file */
		fprintf(stderr, "flash_ifwi(): lseek failed on boot0");
		close(boot0_fd);
		close(boot1_fd);
		return -1;
	}

	if (lseek(boot1_fd, 0, SEEK_SET) < 0) {
		fprintf(stderr, "flash_ifwi(): lseek failed on boot1");
		close(boot0_fd);
		close(boot1_fd);
		return -1;
	}

	ret = write_image(boot0_fd, (char*)data, size);
	if (ret)
		fprintf(stderr, "flash_ifwi(): write to %s failed\n", BOOT0);
	else {
		ret = write_image(boot1_fd, (char*)data, size);
		if (ret)
			fprintf(stderr, "flash_ifwi(): write to %s failed\n", BOOT1);
	}

	close(boot0_fd);
	close(boot1_fd);

	return ret;
}

#else

static int retry_write(char *buf, int cont, FILE *f)
{
	int w_bytes = 0, retry = 0;

	while (w_bytes < cont && retry++ < 3) {
		w_bytes += fwrite(buf + w_bytes, 1, cont - w_bytes, f);
		if (w_bytes < cont)
			sleep(1);
	}

	if (w_bytes < cont) {
		fprintf(stderr, "retry_write error!\n");
		return -1;
	}
	return 0;
}

int update_ifwi_file(const char *dnx, const char *ifwi)
{
	int ret = 0;
	int ifwi_allowed;
	size_t cont;
	char buff[BUF_SIZ];
	FILE *f_src, *f_dst;
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

	/* Check if this IFWI file can be updated. */
	ifwi_allowed = ifwi_downgrade_allowed(ifwi);

	if (ifwi_allowed == -1) {
		fprintf(stderr, "Couldn't get PTI information from ifwi file\n");
		return -1;
	}

	if (img_ifwi_rev.major != dev_fw_rev.ifwi.major) {
		fprintf(stderr, "IFWI FW Major version numbers (file=%02X current=%02X) don't match, Update abort.\n",
				img_ifwi_rev.major, dev_fw_rev.ifwi.major);

		/* Not an error case. Let update continue to next IFWI versions. */
		goto end;
	}

#ifdef CLVT
	if ((img_ifwi_rev.minor & CLVT_MINOR_CHECK) != (dev_fw_rev.ifwi.minor & CLVT_MINOR_CHECK)) {
		fprintf(stderr, "IFWI FW Minor version numbers (file=%02X current=%02X mask=%02X) don't match, Update abort.\n",
				img_ifwi_rev.minor, dev_fw_rev.ifwi.minor,CLVT_MINOR_CHECK);

		/* Not an error case. Let update continue to next IFWI versions. */
		goto end;
	}
#endif

	if (img_ifwi_rev.minor < dev_fw_rev.ifwi.minor) {
		if (!ifwi_allowed) {
			fprintf(stderr, "IFWI FW Minor downgrade not allowed (file=%02X current=%02X). Update abort.\n",
				img_ifwi_rev.minor, dev_fw_rev.ifwi.minor);

			/* Not an error case. Let update continue to next IFWI versions. */
			goto end;
		} else {
			fprintf(stderr, "IFWI FW Minor downgrade allowed (file=%02X current=%02X).\n",
				img_ifwi_rev.minor, dev_fw_rev.ifwi.minor);
		}
	}

	if (img_ifwi_rev.minor == dev_fw_rev.ifwi.minor) {
		fprintf(stderr, "IFWI FW Minor is not new than board's existing version (file=%02X current=%02X), Update abort.\n",
			img_ifwi_rev.minor, dev_fw_rev.ifwi.minor);

		/* Not an error case. Let update continue to next IFWI versions. */
		goto end;
	}

	fprintf(stderr, "Found IFWI to be flashed (maj=%02X min=%02X)\n", img_ifwi_rev.major, img_ifwi_rev.minor);

	f_src = fopen(dnx, "rb");
	if (f_src == NULL) {
		fprintf(stderr, "open %s failed\n", dnx);
		ret = -1;
		goto end;
	}

	f_dst = fopen(DNX_SYSFS_INT, "wb");
	if (f_dst == NULL) {
		f_dst = fopen(DNX_SYSFS_INT_ALT, "wb");
		if (f_dst == NULL) {
			fprintf(stderr, "open %s failed\n", DNX_SYSFS_INT_ALT);
			ret = -1;
			goto err;
		}
	}

	while ((cont = fread(buff, 1, sizeof(buff), f_src)) > 0) {
		if(retry_write(buff, cont, f_dst) == -1) {
		fprintf(stderr,"DNX write failed\n");
		fclose(f_dst);
		ret = -1;
		goto err;
		}
	}

	fclose(f_src);
	fclose(f_dst);

	f_src = fopen(ifwi, "rb");
	if (f_src == NULL) {
		fprintf(stderr, "open %s failed\n", ifwi);
		ret = -1;
		goto end;
	}

	f_dst = fopen(IFWI_SYSFS_INT, "wb");
	if (f_dst == NULL) {
		f_dst = fopen(IFWI_SYSFS_INT_ALT, "wb");
		if (f_dst == NULL) {
			fprintf(stderr, "open %s failed\n", IFWI_SYSFS_INT_ALT);
			ret = -1;
			goto err;
		}
	}

	while ((cont = fread(buff, 1, sizeof(buff), f_src)) > 0) {
		if(retry_write(buff, cont, f_dst) == -1) {
		fprintf(stderr,"IFWI write failed\n");
		fclose(f_dst);
		ret = -1;
		goto err;
		}
	}


	fclose(f_dst);

err:
	fclose(f_src);
end:
	fprintf(stderr, "IFWI flashed\n");
	return ret;
}
#endif

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


int flash_capsule(void *data, unsigned sz)
{
	char capsule_trigger = '1';

	if (file_write(CAPSULE_PARTITION_NAME, data, sz)) {
		pr_perror("Capsule flashing failed!\n");
		return -1;
	}

	if (file_write(CAPSULE_UPDATE_FLAG_PATH,
				&capsule_trigger, sizeof(capsule_trigger))) {
		pr_perror("Capsule flashing failed!\n");
		return -1;
	}

	return 0;
}

int flash_ulpmc(void *data, unsigned sz)
{
	/*
	 * TODO: check version after flashing
	 */
	if (file_write(ULPMC_PATH, data, sz)) {
		pr_perror("ULPMC flashing failed\n");
		return -1;
	}

	return 0;
}

