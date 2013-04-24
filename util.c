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
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#define pr_perror(x)	fprintf(stderr, "%s failed: %s\n", x, strerror(errno))

#define FILEMODE  S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH

int safe_read(int fd, void *data, size_t size)
{
	int ret;
	unsigned char *bytes = (unsigned char *)data;
	while (size) {
		ret = read(fd, bytes, size);
		if (ret <= 0 && errno != EINTR) {
			pr_perror("read");
			return -1;
		}
		size -= ret;
		bytes += ret;
	}
	return 0;
}

int file_read(const char *filename, void **datap, size_t *szp)
{
	struct stat sb;
	size_t sz;
	char *data;
	int fd;

	if (stat(filename, &sb)) {
		printf("file_read: can't stat %s: %s\n", filename, strerror(errno));
		return -1;
	}

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		printf("file_read: can't open file %s: %s\n",
				filename, strerror(errno));
		return -1;
	}

	sz = sb.st_size;
	data = malloc(sz);
	if (!datap) {
		printf("memory allocation failure: %s\n",
				strerror(errno));
		return -1;
	}

	if (safe_read(fd, data, sz)) {
		close(fd);
		free(data);
		return -1;
	}

	*datap = data;
	*szp = sz;
	close(fd);
	return 0;
}

int file_write(const char *filename, const void *data, size_t sz)
{
	int fd;
	int ret;
	const unsigned char *what = (const unsigned char *)data;

	fd = open(filename, O_RDWR | O_CREAT | O_TRUNC, FILEMODE);
	if (fd < 0) {
		printf("file_write: Can't open file %s: %s\n",
				filename, strerror(errno));
		return -1;
	}

	while (sz) {
		ret = write(fd, what, sz);
		if (ret <= 0 && errno != EINTR) {
			printf("file_write: Failed to write to %s: %s\n",
					filename, strerror(errno));
			close(fd);
			return -1;
		}
		what += ret;
		sz -= ret;
	}
	fsync(fd);
	close(fd);
	return 0;
}

int file_string_write(const char *filename, const char *what)
{
	return file_write(filename, what, strlen(what));
}

void dump_trace_file(const char *filename)
{
	char buf[1024];
	FILE *fp;

	fp = fopen(filename, "r");
	if (!fp) {
		printf("can't open trace file %s: %s\n",
				filename, strerror(errno));
		return;
	}

	while (fgets(buf, sizeof(buf), fp))
		printf("%s", buf);
	fclose(fp);
}

int snhexdump(char *str, size_t size, const unsigned char *data, unsigned int sz)
{
	int ret=0;
	while(sz > 0 && size >4) {
		int len = snprintf(str, 4, "%02x ",*data);
		str += len;
		size -= len;
		sz--;
		data++;
		ret += len;
	}
	return ret;
}

void hexdump_buffer(const unsigned char *buffer, unsigned int buffer_size,
		void (*printrow)(const char *text), unsigned int bytes_per_row)
{
	unsigned int left = buffer_size;
	static char buffer_txt[1024];

	while (left > 0) {
		unsigned int row = left < bytes_per_row ? left : bytes_per_row;
		unsigned int rowlen = snhexdump(buffer_txt, sizeof(buffer_txt)
				- 1, buffer, row);
		snprintf(buffer_txt + rowlen,
				sizeof(buffer_txt) - rowlen - 1, "\n");
		printrow(buffer_txt);
		buffer += row;
		left -= row;
	}
}

void twoscomplement(unsigned char *cs, unsigned char *buf, unsigned int size)
{
	*cs = 0;
	while (size > 0) {
		*cs += *buf;
		buf++;
		size--;
	}
	*cs = (~*cs) + 1;
}

int is_hex(char c) {
	return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
}
