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

#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <cutils/properties.h>
#include "fw_version_check.h"

#define FORCE_RW_OPT "0"
#define BOOT_PARTITION_SIZE 0x400000
#define TOKEN_UMIP_AREA_ADDRESS 16384
#define TOKEN_UMIP_AREA_SIZE 11264
#define BOOT0 "/dev/block/mmcblk0boot0"
#define BOOT1 "/dev/block/mmcblk0boot1"
#define BOOT0_FORCE_RO "/sys/block/mmcblk0boot0/force_ro"
#define BOOT1_FORCE_RO "/sys/block/mmcblk0boot1/force_ro"

#define IFWI_TYPE_LSH 12

static void dump_fw_versions_long(struct firmware_versions_long *v)
{
	fprintf(stderr, "	   ifwi: %04X.%04X\n", v->ifwi.major, v->ifwi.minor);
	fprintf(stderr, "---- components ----\n");
	fprintf(stderr, "	    scu: %04X.%04X\n", v->scu.major, v->scu.minor);
	fprintf(stderr, "    hooks/oem: %04X.%04X\n", v->valhooks.major, v->valhooks.minor);
	fprintf(stderr, "	   ia32: %04X.%04X\n", v->ia32.major, v->ia32.minor);
	fprintf(stderr, "	 chaabi: %04X.%04X\n", v->chaabi.major, v->chaabi.minor);
	fprintf(stderr, "	    mIA: %04X.%04X\n", v->mia.major, v->mia.minor);
}

static int write_image(int fd, char *image, unsigned size)
{
	int ret = 0;
	char *ptr = NULL;

	ptr = image;
	if (!ptr) {
		fprintf(stderr, "write_image(): Image is invalid\n");
		return -1;
	}

	while (size) {
		/*If this condition is not present, the write */
		/*function errors out while writing the last chunk */
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

static int force_rw(char *name)
{
	int ret, fd;

	fd = open(name, O_WRONLY);
	if (fd < 0) {
		fprintf(stderr, "force_ro(): failed to open %s\n", name);
		return fd;
	}

	ret = write(fd, FORCE_RW_OPT, sizeof(FORCE_RW_OPT));
	if (ret <= 0) {
		fprintf(stderr, "force_ro(): failed to write %s\n", name);
		close(fd);
		return ret;
	}

	close(fd);
	return 0;
}

int check_ifwi_file_scu_emmc(void *data, size_t size)
{
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
	fprintf(stderr,
		"Attempting to flash ifwi image version %04X.%04X over ifwi current version %04X.%04X\n",
		img_fw_rev.ifwi.major, img_fw_rev.ifwi.minor, dev_fw_rev.ifwi.major, dev_fw_rev.ifwi.minor);

	if (img_fw_rev.ifwi.major != dev_fw_rev.ifwi.major) {
		fprintf(stderr,
			"IFWI FW Major version numbers (file=%04X current=%04X) don't match, Update abort.\n",
			img_fw_rev.ifwi.major, dev_fw_rev.ifwi.major);

		/* Not an error case. Let update continue to next IFWI versions. */
		return 0;
	}

	if ((img_fw_rev.ifwi.minor >> IFWI_TYPE_LSH) != (dev_fw_rev.ifwi.minor >> IFWI_TYPE_LSH)) {
		fprintf(stderr, "IFWI FW Type (file=%1X current=%1X) don't match, Update abort.\n",
			img_fw_rev.ifwi.minor >> IFWI_TYPE_LSH, dev_fw_rev.ifwi.minor >> IFWI_TYPE_LSH);

		/* Not an error case. Let update continue to next IFWI versions. */
		return 0;
	}

	return 1;
}

int update_ifwi_file_scu_emmc(void *data, size_t size)
{
	int boot0_fd, boot1_fd, ret = 0;
	char *token_data;

	token_data = malloc(TOKEN_UMIP_AREA_SIZE);
	if (!token_data) {
		fprintf(stderr, "flash_ifwi(): Malloc error\n");
		return -1;
	}

	if (size > BOOT_PARTITION_SIZE) {
		fprintf(stderr, "flash_ifwi(): Truncating last %d bytes from the IFWI\n",
			(size - BOOT_PARTITION_SIZE));
		/* Since the last 144 bytes are the FUP header which are not required, */
		/* we truncate it to fit into the boot partition. */
		size = BOOT_PARTITION_SIZE;
	}

	ret = force_rw(BOOT0_FORCE_RO);
	if (ret) {
		fprintf(stderr, "flash_ifwi(): unable to force_ro %s\n", BOOT0);
		goto err;
	}
	boot0_fd = open(BOOT0, O_RDWR);
	if (boot0_fd < 0) {
		fprintf(stderr, "flash_ifwi(): failed to open %s\n", BOOT0);
		goto err;
	}
	if (lseek(boot0_fd, TOKEN_UMIP_AREA_ADDRESS, SEEK_SET) < 0) {
		fprintf(stderr, "flash_ifwi(): lseek failed on boot0\n");
		goto err_boot0;
	}
	ret = read(boot0_fd, token_data, TOKEN_UMIP_AREA_SIZE);
	if (ret <= 0 && errno != EINTR) {
		fprintf(stderr, "flash_ifwi(): UMIP token area read failed with errno %d\n", errno);
		goto err_boot0;
	}
	if (lseek(boot0_fd, 0, SEEK_SET) < 0) {	/* Seek to start of file */
		fprintf(stderr, "flash_ifwi(): lseek failed on boot0\n");
		goto err_boot0;
	}
	ret = write_image(boot0_fd, (char *)data, size);
	if (ret) {
		fprintf(stderr, "flash_ifwi(): write to %s failed\n", BOOT0);
		goto err_boot0;
	}
	if (lseek(boot0_fd, TOKEN_UMIP_AREA_ADDRESS, SEEK_SET) < 0) {
		fprintf(stderr, "flash_ifwi: lseek failed on boot0\n");
		goto err_boot0;
	}
	ret = write_image(boot0_fd, token_data, TOKEN_UMIP_AREA_SIZE);
	close(boot0_fd);
	if (ret)
		fprintf(stderr, "flash_ifwi(): Restore UMIP token area to %s failed\n", BOOT0);
	else {
		ret = force_rw(BOOT1_FORCE_RO);
		if (ret) {
			fprintf(stderr, "flash_ifwi(): unable to force_ro %s\n", BOOT1);
			goto err;
		}
		boot1_fd = open(BOOT1, O_RDWR);
		if (boot1_fd < 0) {
			fprintf(stderr, "flash_ifwi(): failed to open %s\n", BOOT1);
			goto err;
		}
		if (lseek(boot1_fd, TOKEN_UMIP_AREA_ADDRESS, SEEK_SET) < 0) {
			fprintf(stderr, "flash_ifwi(): lseek failed on boot1\n");;
			goto err_boot1;
		}
		ret = read(boot1_fd, token_data, TOKEN_UMIP_AREA_SIZE);
		if (ret <= 0 && errno != EINTR) {
			fprintf(stderr, "flash_ifwi(): UMIP token area read failed with errno %d\n", errno);
			goto err_boot1;
		}
		if (lseek(boot1_fd, 0, SEEK_SET) < 0) {
			fprintf(stderr, "flash_ifwi(): lseek failed on boot1\n");
			goto err_boot1;
		}
		ret = write_image(boot1_fd, (char *)data, size);
		if (ret) {
			fprintf(stderr, "flash_ifwi(): write to %s failed\n", BOOT1);
			goto err_boot1;
		}
		if (lseek(boot1_fd, TOKEN_UMIP_AREA_ADDRESS, SEEK_SET) < 0) {
			fprintf(stderr, "flash_ifwi: lseek failed on boot1\n");
			goto err_boot1;
		}
		ret = write_image(boot1_fd, token_data, TOKEN_UMIP_AREA_SIZE);
		close(boot1_fd);
		if (ret)
			fprintf(stderr, "flash_ifwi(): write to %s failed\n", BOOT1);
	}
	free(token_data);
	return ret;

err_boot0:
	close(boot0_fd);
	goto err;

err_boot1:
	close(boot1_fd);
	goto err;

err:
	free(token_data);
	return -1;
}

int flash_dnx_scu_emmc(void *data, unsigned sz)
{
	return 0;
}

int flash_ifwi_scu_emmc(void *data, unsigned size)
{
	int ret;

	ret = check_ifwi_file_scu_emmc(data, size);
	if (ret > 0)
		return update_ifwi_file_scu_emmc(data, size);

	return ret;
}

int flash_token_umip_scu_emmc(void *data, size_t size)
{
	uint32_t *ptr = (uint32_t *) data;
	int boot0_fd, boot1_fd, ret = 0;
	int token_size = size;
	uint32_t xor = 0;
	int token_size32 = token_size / sizeof(uint32_t);
	int i;
	int padding_size = TOKEN_UMIP_AREA_SIZE - token_size - sizeof(uint32_t);
	char *ptr_padding = calloc(1, padding_size);

	if (!ptr_padding) {
		fprintf(stderr, "write_token_umip: calloc failed\n");
		return -1;
	}
	/* 32-bit XOR compensation calculation
	 * The token just added shall avoid any effect on xor calculation (checksum)
	 * 32-bit XOR compensation is written in UMIP just after the token
	 */
	for (i = 0; i < token_size32; i++) {
		xor = xor ^ *ptr;
		ptr++;
	}

	ret = force_rw(BOOT0_FORCE_RO);
	if (ret) {
		fprintf(stderr, "write_token_umip: unable to force_ro %s\n", BOOT0);
		goto err;
	}
	boot0_fd = open(BOOT0, O_RDWR);
	if (boot0_fd < 0) {
		fprintf(stderr, "write_token_umip: failed to open %s\n", BOOT0);
		goto err;
	}
	if (lseek(boot0_fd, TOKEN_UMIP_AREA_ADDRESS, SEEK_SET) < 0) {
		fprintf(stderr, "write_token_umip: lseek failed on boot0\n");
		goto err_boot0;
	}
	/* Write the token */
	ret = write_image(boot0_fd, (char *)data, token_size);
	if (ret) {
		fprintf(stderr, "flash_token_umip(): write token to %s failed\n", BOOT0);
		goto err_boot0;
	}
	/* Write the XOR Compensation */
	ret = write_image(boot0_fd, (char *)&xor, sizeof(uint32_t));
	if (ret) {
		fprintf(stderr, "flash_token_umip(): write xor to %s failed\n", BOOT0);
		goto err_boot0;
	}
	/* Write the padding bytes */
	ret = write_image(boot0_fd, ptr_padding, padding_size);
	close(boot0_fd);
	if (ret)
		fprintf(stderr, "flash_token_umip(): padding -- write to %s failed\n", BOOT0);
	else {
		ret = force_rw(BOOT1_FORCE_RO);
		if (ret) {
			fprintf(stderr, "write_token_umip: unable to force_ro %s\n", BOOT1);
			goto err;
		}
		boot1_fd = open(BOOT1, O_RDWR);
		if (boot1_fd < 0) {
			fprintf(stderr, "write_token_umip: failed to open %s\n", BOOT1);
			goto err;
		}
		if (lseek(boot1_fd, TOKEN_UMIP_AREA_ADDRESS, SEEK_SET) < 0) {
			fprintf(stderr, "write_token_umip: lseek failed on boot1\n");
			goto err_boot1;
		}
		/* Write the token */
		ret = write_image(boot1_fd, (char *)data, token_size);
		if (ret) {
			fprintf(stderr, "flash_token_umip(): write token to %s failed\n", BOOT1);
			goto err_boot1;
		}
		/* Write the XOR compensation */
		ret = write_image(boot1_fd, (char *)&xor, sizeof(uint32_t));
		if (ret) {
			fprintf(stderr, "flash_token_umip(): write xor to %s failed\n", BOOT1);
			goto err_boot1;
		}
		/* Write the padding bytes */
		ret = write_image(boot1_fd, ptr_padding, padding_size);
		close(boot1_fd);
		if (ret)
			fprintf(stderr, "flash_token_umip(): padding -- write to %s failed\n", BOOT1);
	}
	free(ptr_padding);
	return ret;

err_boot0:
	close(boot0_fd);
	goto err;

err_boot1:
	close(boot1_fd);
	goto err;

err:
	free(ptr_padding);
	return -1;
}

bool is_scu_emmc(void)
{
	char value[PROPERTY_VALUE_MAX];
	return property_get("sys.scu.version", value, "") > 0;
}
