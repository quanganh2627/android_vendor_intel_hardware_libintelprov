#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#define pr_perror(x)	fprintf(stderr, "%s failed: %s\n", x, strerror(errno))

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

	fd = open(filename, O_RDWR | O_CREAT | O_TRUNC);
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
