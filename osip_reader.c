/* Copyright (C) 2011 Intel Corporation
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
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <diskconfig/diskconfig.h>

#include "update_osip.h"
#include "util.h"


void usage(void) {
	printf("usage: osip_reader <options> <list of stitched files>\n");
	printf("options:\n");
	printf("-f   Fix up LBA offsets to device standard\n");
	printf("-c   Location of disk_layout.conf (needed by -f)\n");
	printf("-v   Verify image sizes\n");
	printf("If run with no options, simply display the OSIP table\n");
}

/* HACK: libdiskconfig won't compute the LBA offsets because it (correctly)
 * wants to query the device for the LBA size. We're going to go with the
 * hard-coded value in the update_osip.h header */
void get_lba_offsets(struct disk_info *dinfo)
{
	uint32_t lba = dinfo->skip_lba;
	int i;

	for (i = 0; i < dinfo->num_parts; i++) {
		struct part_info *ptn = &dinfo->part_lst[i];
		ptn->start_lba = lba;
		lba = lba + ((ptn->len_kb * 1024) / LBA_SIZE);
	}
}

int main(int argc, char *argv[])
{
	int fd;
	struct OSIP_header osip;
	int i, opt;
	int fixup = 0;
	int verify = 0;
	char *config = NULL;
	struct disk_info *dinfo = NULL;

	while ((opt = getopt(argc, argv, "vfc:h")) != -1) {
		switch (opt) {
		case 'h':
			usage();
			exit(0);
		case 'f':
			fixup = 1;
			break;
		case 'c':
			config = strdup(optarg);
			break;
		case 'v':
			verify = 1;
			break;
		default:
			usage();
			exit(EXIT_FAILURE);
		}
	}

	if (optind >= argc) {
		usage();
		exit(EXIT_FAILURE);
	}

	if (config) {
		dinfo = load_diskconfig(config, NULL);
		if (!dinfo) {
			fprintf(stderr, "Disk layout %s unreadable", config);
			exit(EXIT_FAILURE);
		}
		get_lba_offsets(dinfo);
	}

	for (i = optind; i < argc; i++) {
		fd = open(argv[i], O_RDWR);
		if (!fd) {
			fprintf(stderr, "Can't open %s: %s\n", argv[i],
					strerror(errno));
			continue;
		}
		if (safe_read(fd, &osip, sizeof(osip))) {
			fprintf(stderr, "Can't read OSIP header from %s\n",
					argv[i]);
			close(fd);
			continue;
		}
		if (verify) {
			if (verify_osip_sizes(&osip)) {
				fprintf(stderr, "Bad sizes in image %s\n", argv[1]);
				exit(EXIT_FAILURE);
			}
		}
		if (fixup) {
			int ret;
			int cache_lba = 0;
			struct part_info *cache_ptn;

			if (!dinfo) {
				fprintf(stderr, "fixup requires disk_layout.conf passed in");
				exit(EXIT_FAILURE);
			}
			cache_ptn = find_part(dinfo, "cache");
			if (!cache_ptn) {
				fprintf(stderr, "Cache partition not found in disk layout");
				exit(EXIT_FAILURE);
			}
			cache_lba = cache_ptn->start_lba;
			if (fixup_osip(&osip, cache_lba)) {
				fprintf(stderr, "Couldn't modify OSIP!");
				exit(EXIT_FAILURE);
			}
			if (lseek(fd, 0, SEEK_SET)) {
				perror("lseek");
				exit(EXIT_FAILURE);
			}
			ret = write(fd, &osip, sizeof(osip));
			if (ret != sizeof(osip)) {
				fprintf(stderr, "file_write: Failed to "
					"write to %s: %s\n",
					argv[i], strerror(errno));
				exit(EXIT_FAILURE);
			}
		}
		if (!verify && !fixup)
			dump_osip_header(&osip);
		close(fd);
	}
	return 0;
}
