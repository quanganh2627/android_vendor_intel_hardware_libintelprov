/*
 * Copyright 2013 Intel Corporation
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

#define LOG_TAG "teeprov"

#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <libgen.h>
#include <sys/mman.h>
#include <getopt.h>
#include <errno.h>
#include <cutils/log.h>
#include "tee_connector.h"

static void teeprov_output(const char *msg)
{
	fprintf(stdout, "%s", msg);
	LOGI("%s", msg);
}

static void teeprov_error(const char *msg)
{
	fprintf(stderr, "%s\n", msg);
	LOGE("%s", msg);
}

static void usage (int status, const char *program_name)
{
	printf("Usage: %s [-o FILE] OPTION...\n", basename(program_name));
	printf("\
Provide data to or retrieve data from Chaabi.\n\
Mandatory arguments to long options are mandatory for short options too.\n\
When used, -o option must the first.\n\
  -o, --output-file=FILE           write data into FILE instead of printing it\n\
  -s, --get-spid                   get SPID\n\
  -f, --get-fru                    get FRU\n\
  -p, --get-part-id                get Part Specific ID\n\
  -l, --get-lifetime               get lifetime\n\
  -u, --start-update               start the update\n\
  -c, --cancel-update              cancel the update\n\
  -z, --finalize-update            finalize the update\n\
  -w, --write-token=FILE           write token FILE\n\
  -r, --read-token=DATAGROUP_ID    read token\n\
  -m, --remove-token=DATAGROUP_ID  remove token\n\
  -h, --help                       display this help\n\
");
	exit(status);
}

/* Send a token read from FILE_PATH to Chaabi. Returns 0 on
   success.  */
static int write_token_file (const char *file_path)
{
	struct stat fd_stat;
	int fd, ret, result;
	void *data;

	fd = open(file_path, O_RDONLY);
	if (fd == -1)
	{
		raise_error("Failed to open token \"%s\" file, error: %s", file_path, strerror(errno));
		return EXIT_FAILURE;
	}

	ret = fstat(fd, &fd_stat);
	if (ret == -1)
	{
		raise_error("Failed to retrieve the token file stat, error: %s", strerror(errno));
		result = EXIT_FAILURE;
		goto close;
	}

	data = mmap(NULL, fd_stat.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (data == MAP_FAILED)
	{
		raise_error("Failed to map file into memory, error: %s", strerror(errno));
		result = EXIT_FAILURE;
		goto close;
	}

	result = write_token(data, fd_stat.st_size);

	ret = munmap(data, fd_stat.st_size);
	if (ret != 0)
	{
		raise_error("Failed to unmap file, error: %s", strerror(errno));
		if (result == 0)
			raise_error("Exit without complaining because write_token has been successfully executed");
		else
			result = ret;
		goto exit;
	}

close:
	ret = close(fd);
	if (ret != 0)
	{
		raise_error("Failed to close file, error: %s", strerror(errno));
		result = ret;
	}

exit:
	return result;
}

static struct option const long_options[] =
{
	{"get-spid", no_argument, NULL, 's'},
	{"get-fru", no_argument, NULL, 'f'},
	{"get-part-id", no_argument, NULL, 'p'},
	{"get-lifetime", no_argument, NULL, 'l'},
	{"start-update", no_argument, NULL, 'u'},
	{"cancel-update", no_argument, NULL, 'c'},
	{"finalize-update", no_argument, NULL, 'z'},
	{"write-token", required_argument, NULL, 'w'},
	{"read-token", required_argument, NULL, 'r'},
	{"remove-token", required_argument, NULL, 'm'},
	{"output-file", required_argument, NULL, 'o'},
	{"help", no_argument, NULL, 'h'},
	{NULL, 0, NULL, 0}
};

int main(int argc, char **argv)
{
	int ret, c;

	print_fun = teeprov_output;
	error_fun = teeprov_error;
	atexit(close_output_file_when_open);

	while ((c = getopt_long (argc, argv, "sfpluczw:r:o:hm:", long_options, NULL)) != -1)
	{
		switch (c)
		{
		case 's':
			return get_spid(0, NULL);

		case 'f':
			return get_fru(0, NULL);

		case 'p':
			return get_part_id(0, NULL);

		case 'l':
			return get_lifetime(0, NULL);

		case 'u':
			return start_update(0, NULL);

		case 'c':
			return cancel_update(0, NULL);

		case 'z':
			return finalize_update(0, NULL);

		case 'w':
			return write_token_file(optarg);

		case 'r':
			return read_token(2, &argv[optind - 2]);

		case 'm':
			return remove_token(2, &argv[optind - 2]);

		case 'o':
			if (optind != 3)
			{
				raise_error("-o, --output-file=FILE MUST be the first option");
				return EXIT_FAILURE;
			}
			ret = set_output_file(optarg);
			if (ret != 0)
				return ret;
			break;

		case 'h':
			usage(EXIT_SUCCESS, argv[0]);
			break;

		default:
			fprintf(stderr, "\n");
			return EXIT_FAILURE;
		}
	}

	if (argc == 1)
		usage(EXIT_FAILURE, argv[0]);

	return EXIT_SUCCESS;
}
