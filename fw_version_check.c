/*
 * Copyright (C) 2011 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdint.h>

#include "fw_version_check.h"

#define DEVICE_NAME	"/sys/devices/ipc/intel_fw_update.0/fw_info/fw_version"
#define DEVICE_NAME_ALT	"/sys/kernel/fw_update/fw_info/fw_version"
#define FIP_PATTERN	0x50494624
#define SCU_IPC_VERSION_LEN 16

struct fip_version_block {
	uint8_t reserved;
	uint8_t minor;
	uint8_t major;
	uint8_t checksum;
};

struct Chaabi_rev {
	struct fip_version_block icache;
	struct fip_version_block resident;
	struct fip_version_block ext;
};

struct IFWI_rev {
	uint8_t minor;
	uint8_t major;
	uint16_t reserved;
};

struct FIP_header {
	uint32_t FIP_SIG;
	uint32_t header_info;
	struct fip_version_block ia32_rev;
	struct fip_version_block punit_rev;
	struct fip_version_block oem_rev;
	struct fip_version_block suppia32_rev;
	struct fip_version_block scu_rev;
	struct Chaabi_rev chaabi_rev;
	struct IFWI_rev ifwi_rev;
};

#define print_perror(x)	fprintf(stderr, "%s: %s failed: %s\n", \
		__func__, x, strerror(errno))

/* Bytes in scu_ipc_version after the ioctl():
 * 00 SCU RT Firmware Minor Revision
 * 01 SCU RT Firmware Major Revision
 * 02 SCU ROM Firmware Minor Revision
 * 03 SCU ROM Firmware Major Revision 
 * 04 P-unit Microcode Minor Revision
 * 05 P-unit Microcode Major Revision
 * 06 IA-32 Firmware Minor Revision
 * 07 IA-32 Firmware Major Revision
 * 08 FTL Driver Minor Revision
 * 09 FTL Driver Major Revision
 * 10 Validation Hooks / OEM Minor Revision
 * 11 Validation Hooks / OEM Major Revision
 * 12 n/a
 * 13 n/a
 * 14 IFWI Minor Revision
 * 15 IFWI Major Revision
 */
int get_current_fw_rev(struct firmware_versions *v)
{
	int i;
	FILE *fw_info;
	unsigned int fw_revision[SCU_IPC_VERSION_LEN];

	fw_info = fopen(DEVICE_NAME, "r");
	if (fw_info == NULL) {
		fw_info = fopen(DEVICE_NAME_ALT, "r");
		if (fw_info == NULL) {
			print_perror("fopen");
			return -1;
		}
	}

	memset(fw_revision, 0, SCU_IPC_VERSION_LEN);
	for (i = 0; i < SCU_IPC_VERSION_LEN; i++)
		fscanf(fw_info, "%x", &fw_revision[i]);
	fclose(fw_info);

	v->ifwi.major = fw_revision[15];
	v->ifwi.minor = fw_revision[14];
	v->scu.major = fw_revision[1];
	v->scu.minor = fw_revision[0];
	v->oem.major = fw_revision[11];
	v->oem.minor = fw_revision[10];
	v->punit.major = fw_revision[5];
	v->punit.minor = fw_revision[4];
	v->ia32.major = fw_revision[7];
	v->ia32.minor = fw_revision[6];
	v->supp_ia32.major = fw_revision[9];
	v->supp_ia32.minor = fw_revision[8];
	/* Can't read these from the SCU >:( */
	v->chaabi_icache.major = 0;
	v->chaabi_icache.minor = 0;
	v->chaabi_res.major = 0;
	v->chaabi_res.minor = 0;
	v->chaabi_ext.major = 0;
	v->chaabi_ext.minor = 0;
	return 0;
}

int fw_vercmp(struct firmware_versions *v1, struct firmware_versions *v2)
{
	uint16_t ver1 = (v1->ifwi.major << 8) + v1->ifwi.minor;
	uint16_t ver2 = (v2->ifwi.major << 8) + v2->ifwi.minor;

	if (ver1 < ver2)
		return -1;
	else if (ver1 > ver2)
		return 1;
	else
		return 0;
}

void dump_fw_versions(struct firmware_versions *v)
{
	printf("         ifwi: %02X.%02X\n", v->ifwi.major, v->ifwi.minor);
	printf("---- components ----\n");
	printf("          scu: %02X.%02X\n", v->scu.major, v->scu.minor);
	printf("        punit: %02X.%02X\n", v->punit.major, v->punit.minor);
	printf("    hooks/oem: %02X.%02X\n", v->oem.major, v->oem.minor);
	printf("         ia32: %02X.%02X\n", v->ia32.major, v->ia32.minor);
	printf("     suppia32: %02X.%02X\n", v->supp_ia32.major, v->supp_ia32.minor);
	printf("chaabi icache: %02X.%02X\n", v->chaabi_icache.major, v->chaabi_icache.minor);
	printf("   chaabi res: %02X.%02X\n", v->chaabi_res.major, v->chaabi_res.minor);
	printf("   chaabi ext: %02X.%02X\n", v->chaabi_ext.major, v->chaabi_ext.minor);
}

int get_image_fw_rev(void *data, unsigned sz, struct firmware_versions *v)
{
	struct FIP_header fip;
	unsigned char *databytes = (unsigned char *)data;
	int magic;

	v->ifwi.major=0;
	v->ifwi.minor=0;

	while ((v->ifwi.major == 0) && (v->ifwi.minor == 0)){

		/* Scan for the FIP magic */
		while (sz >= sizeof(fip)) {
			memcpy(&magic, databytes, sizeof(magic));
			if (magic == FIP_PATTERN)
				break;
			databytes += sizeof(magic);
			sz -= sizeof(magic);
		}

		if (sz < sizeof(fip)) {
			fprintf(stderr, "Couldn't find FIP magic in image!");
			return -1;
		}

		memcpy(&fip, databytes, sizeof(fip));
		v->ifwi.major = fip.ifwi_rev.major;
		v->ifwi.minor = fip.ifwi_rev.minor;
		v->scu.major = fip.scu_rev.major;
		v->scu.minor = fip.scu_rev.minor;
		v->oem.major = fip.oem_rev.major;
		v->oem.minor = fip.oem_rev.minor;
		v->punit.major = fip.punit_rev.major;
		v->punit.minor = fip.punit_rev.minor;
		v->ia32.major = fip.ia32_rev.major;
		v->ia32.minor = fip.ia32_rev.minor;
		v->supp_ia32.major = fip.suppia32_rev.major;
		v->supp_ia32.minor = fip.suppia32_rev.minor;
		v->chaabi_icache.major = fip.chaabi_rev.icache.major;
		v->chaabi_icache.minor = fip.chaabi_rev.icache.minor;
		v->chaabi_res.major = fip.chaabi_rev.resident.major;
		v->chaabi_res.minor = fip.chaabi_rev.resident.minor;
		v->chaabi_ext.major = fip.chaabi_rev.ext.major;
		v->chaabi_ext.minor = fip.chaabi_rev.ext.minor;

		if ((v->ifwi.major == 0) && (v->ifwi.minor == 0)){
			databytes += sizeof(magic);
			sz -= sizeof(magic);
		}
	}

	return 0;
}

int crack_update_fw(const char *fw_file, struct fw_version *ifwi_version){
	struct FIP_header fip;
	FILE *fd;
	int tmp = 0;
	int location;

	memset((void *)&fip, 0, sizeof(fip));

	if ((fd = fopen(fw_file, "rb")) == NULL) {
		fprintf(stderr, "fopen error: Unable to open file\n");
		return -1;
	}
	ifwi_version->major = 0;
	ifwi_version->minor = 0;

	while ((ifwi_version->minor == 0) && (ifwi_version->major == 0)){

		while (tmp != FIP_PATTERN) {
			int cur;
			fread(&tmp, sizeof(int), 1, fd);
			if (ferror(fd) || feof(fd)) {
				fprintf(stderr, "find FIP_pattern failed\n");
				fclose(fd);
				return -1;
			}
			cur = ftell(fd) - sizeof(int);
			fseek(fd, cur + sizeof(char), SEEK_SET);
		}
		location = ftell(fd) - sizeof(char);

		fseek(fd, location, SEEK_SET);
		fread((void *)&fip, sizeof(fip), 1, fd);
		if (ferror(fd) || feof(fd)) {
			fprintf(stderr, "read of FIP_header failed\n");
			fclose(fd);
			return -1;
		}
		ifwi_version->major = fip.ifwi_rev.major;
		ifwi_version->minor = fip.ifwi_rev.minor;
		tmp=0;

	}
	fclose(fd);

	return 0;
}
