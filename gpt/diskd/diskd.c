/*
 * Copyright (C) 2014 Intel Corporation
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

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <unistd.h>
#include <poll.h>
#include <fcntl.h>
#include <libgen.h>
#include <dirent.h>

#include "cgpt.h"
#include "cgpt_params.h"

#include <cutils/uevent.h>
#include <cutils/list.h>
#include <cutils/klog.h>
#include <sys/capability.h>
#include <private/android_filesystem_config.h>
#include <linux/prctl.h>

#include "diskd.h"

#define DAEMON_NAME	"diskd"

#define ERROR(x...)	KLOG_ERROR(DAEMON_NAME, x)
#define WARNING(x...)	KLOG_WARNING(DAEMON_NAME, x)
#define DEBUG(x...)	KLOG_DEBUG(DAEMON_NAME, x)

#define NB_UEVENT_MSG	256
#define UEVENT_MSG_LEN	1024

static const char *DIR_TREE[] = {
	DISK_BASE_DIR, DISK_BY_LABEL_DIR, DISK_BY_UUID_DIR
};

#define TMP_NODE_FILE		DISK_BASE_DIR"/tmp"
#define BLOCK_DEV_PREFIX	"../../block"
#define BLOCK_DEV_DIR		"/sys/block"

static const mode_t DEFAULT_MODE = S_IRWXU;

static const char *BLOCK_SUBSYSTEM = "block";

static struct block_node_fmt {
	int major;
	char *fmt;
} BLOCK_NODE_FMTS[] = {
	{ 179, "%s/%sp%d" },	/* eMMC */
	{ 8, "%s/%s%d"}		/* sd device */
};

enum {
	ADD,
	REMOVE,
	CHANGE
};

static const char *ACTIONS[] = {
	[ADD]		     = "add",
	[REMOVE]	     = "remove",
	[CHANGE]	     = "change"
};

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

typedef struct uevent {
	const char *action;
	const char *path;
	const char *subsystem;
	int major;
	int minor;
} uevent_t;

struct link_node {
	const char *path;
	int major;
	int minor;
	struct listnode plist;
};

static list_declare(links);

static char *create_symlink(const char *dir, const char *name, const char *to)
{
	int ret;
	char *from;

	ret = asprintf(&from, "%s/%s", dir, name);
	if (ret == -1) {
		WARNING("From path creation failed : %s",
			strerror(errno));
		return NULL;
	}

	ret = symlink(to, from);
	if (ret == -1) {
		if (errno != EEXIST) {
			WARNING("Failed to create link from %s to %s : %s\n",
				from, to, strerror(errno));
			goto error;
		}

		ret = unlink(from);
		if (ret == -1) {
			WARNING("Failed to delete existing %s link : %s\n",
				from, strerror(errno));
			goto error;
		}

		ret = symlink(to, from);
		if (ret == -1) {
			WARNING("%s link creation failed : %s\n",
				from, strerror(errno));
			goto error;
		}
	}

	return from;

error:
	free(from);
	return NULL;
}

static void create_link(const char *dir, const char *name,
			int major, int minor, char *to)
{
	char *path = create_symlink(dir, name, to);
	if (!path)
		return;

	struct link_node *node = calloc(1, sizeof(*node));
	if (!node) {
		WARNING("Link node allocation failed : %s\n",
			strerror(errno));
		unlink(path);
		free(path);
		return;
	}

	node->major = major;
	node->minor = minor;
	node->path = path;

	list_add_tail(&links, &node->plist);
}

static void delete_links(int major, int minor, bool unconditionally)
{
	struct listnode *node, *next;

	list_for_each_safe(node, next, &links) {
		struct link_node *link = node_to_item(node,
						      struct link_node, plist);
		if (unconditionally
		    || (link->major == major && link->minor == minor)) {
			if (unlink(link->path) == -1)
				WARNING("Failed to delete link %s : %s\n",
					link->path, strerror(errno));
			list_remove(node);
			free((void *)link->path);
			free(link);
		}
	}
}

static void parse_event(const char *msg, uevent_t *uevent)
{
	while (*msg) {
		if (!strncmp(msg, "ACTION=", 7)) {
			msg += 7;
			uevent->action = msg;
		} else if (!strncmp(msg, "DEVPATH=", 8)) {
			msg += 8;
			uevent->path = msg;
		} else if (!strncmp(msg, "SUBSYSTEM=", 10)) {
			msg += 10;
			uevent->subsystem = msg;
		} else if (!strncmp(msg, "MAJOR=", 6)) {
			msg += 6;
			uevent->major = atoi(msg);
		} else if (!strncmp(msg, "MINOR=", 6)) {
			msg += 6;
			uevent->minor = atoi(msg);
		}

		while (*msg != '\0' && *msg != '\n')
			msg++;
		msg++;
	}

	DEBUG("event { action:'%s', path:'%s', subsystem:'%s', major:'%d', minor:'%d' }\n",
	      uevent->action, uevent->path, uevent->subsystem,
	      uevent->major, uevent->minor);
}

static void add_device(uevent_t *uevent)
{
	DEBUG("%s: %s (%d, %d)\n", __func__,
	      uevent->path, uevent->major, uevent->minor);

	char *format = NULL;
	unsigned int i;
	for (i = 0 ; i < ARRAY_SIZE(BLOCK_NODE_FMTS) ; i++)
		if (BLOCK_NODE_FMTS[i].major == uevent->major)
			format = BLOCK_NODE_FMTS[i].fmt;

	if (!format) {
		DEBUG("Unsupported major %d\n", uevent->major);
		return;
	}

	if (mknod(TMP_NODE_FILE, DEFAULT_MODE | S_IFBLK,
		  makedev(uevent->major, uevent->minor)) == -1) {
		WARNING("Temporary node creation failed : %s\n",
			strerror(errno));
		return;
	}

	struct drive drive;
	if (CGPT_OK != DriveOpen(TMP_NODE_FILE, &drive, O_RDONLY))
		goto exit;

	if (GPT_SUCCESS != GptSanityCheck(&drive.gpt))
		goto close;

	char *name = basename(uevent->path);
	for (i = 0; i < GetNumberOfEntries(&drive.gpt); i++) {
		GptEntry *entry = GetEntry(&drive.gpt, ANY_VALID, i);

		if (IsZero(&entry->type))
			continue;

		char label[GPT_PARTNAME_LEN];
		UTF16ToUTF8(entry->name, ARRAY_SIZE(entry->name),
			    (uint8_t *)label, sizeof(label));

		char uuid[GUID_STRLEN];
		GuidToStr(&entry->unique, uuid, GUID_STRLEN);

		char *from;
		int ret = asprintf(&from, format, BLOCK_DEV_PREFIX, name, i + 1);
		if (ret == -1) {
			WARNING("From path creation failed : %s",
				strerror(errno));
			continue;
		}

		create_link(DISK_BY_LABEL_DIR, label, uevent->major,
			    uevent->minor, from);
		create_link(DISK_BY_UUID_DIR, uuid, uevent->major,
			    uevent->minor, from);

		free(from);
	}

close:
	DriveClose(&drive, 0);
exit:
	unlink(TMP_NODE_FILE);
}

static void remove_device(uevent_t *uevent)
{
	delete_links(uevent->major, uevent->minor, false);
}

static void handle_event(const char *msg, uevent_t *uevent)
{
	parse_event(msg, uevent);

	if (!uevent->subsystem || !uevent->action || !uevent->path)
		return;

	if (strcmp(uevent->subsystem, BLOCK_SUBSYSTEM))
		return;

	if (!strcmp(uevent->action, ACTIONS[REMOVE])
	    || !strcmp(uevent->action, ACTIONS[CHANGE]))
		remove_device(uevent);

	if (!strcmp(uevent->action, ACTIONS[ADD])
	    || !strcmp(uevent->action, ACTIONS[CHANGE]))
		add_device(uevent);
}

static void handle_events(int fd)
{
	char msg[UEVENT_MSG_LEN + 2];
	uevent_t uevent;
	int n;

	while ((n = uevent_kernel_multicast_recv(fd, msg, UEVENT_MSG_LEN)) > 0) {
		if (n >= UEVENT_MSG_LEN)
			continue;

		/* We double '\0' end the message to ease the
		 * parsing.  */
		msg[n] = msg[n + 1] = '\0';

		memset(&uevent, 0, sizeof(uevent));
		handle_event(msg, &uevent);
	}
}

static char *read_uevent_file(int fd)
{
	struct stat statbuf;

	if (fstat(fd, &statbuf) == -1) {
		WARNING("Failed to stat file : %s\n",
			strerror(errno));
		return NULL;
	}

	char *buf = calloc(1, statbuf.st_size);
	if (!buf) {
		WARNING("Failed to allocate file buffer : %s\n",
			strerror(errno));
		return NULL;
	}

	ssize_t size = read(fd, buf, statbuf.st_size);
	if (size == -1 || size == 0) {
		WARNING("Failed to read uevent file : %s\n",
			strerror(errno));
		free(buf);
		return NULL;
	}

	DEBUG("%s: %s\n", __func__, buf);

	return buf;
}

static void populate_from_sysfs(void)
{
	DIR *dir;
	struct dirent *cur;
	uevent_t uevent;
	char *path;

	dir = opendir(BLOCK_DEV_DIR);
	if (!dir) {
		WARNING("Failed to open %s directory: %s\n",
			BLOCK_DEV_DIR, strerror(errno));
		return;
	}

	while ((cur = readdir(dir)) != NULL) {
		if (!strcmp(".", cur->d_name) || !strcmp("..", cur->d_name))
			continue;

		int ret = asprintf(&path, BLOCK_DEV_DIR"/%s/uevent",
				   cur->d_name);
		if (ret == -1) {
			WARNING("Failed to create uevent file path for %s : %s\n",
				cur->d_name, strerror(errno));
			continue;
		}

		int fd = open(path, O_RDONLY);
		if (fd == -1) {
			WARNING("Failed to open %s : %s\n", path,
				strerror(errno));
			goto next;
		}

		char *buf = read_uevent_file(fd);
		if (!buf)
			goto next;

		memset(&uevent, 0, sizeof(uevent));
		uevent.action = ACTIONS[ADD];
		uevent.subsystem = BLOCK_SUBSYSTEM;
		uevent.path = cur->d_name;
		handle_event(buf, &uevent);
		free(buf);

	next:
		free(path);
	}

	closedir(dir);
}

static void init_tree(void)
{
	unsigned int i;
	for (i = 1 ; i < ARRAY_SIZE(DIR_TREE) ; i++) {
		int ret = mkdir(DIR_TREE[i], DEFAULT_MODE);
		if (ret == -1 && errno != EEXIST) {
			ERROR("%s directory creation failed : %s\n",
			      DIR_TREE[i], strerror(errno));
			exit(EXIT_FAILURE);
		}
	}
}

static void destroy_tree(int sig)
{
	delete_links(-1, -1, true);

	int i;
	for (i = ARRAY_SIZE(DIR_TREE) - 1 ; i >= 0 ; i--)
		rmdir(DIR_TREE[i]);

	exit(EXIT_SUCCESS);
}

void diskd_populate_tree(void)
{
	struct stat sbuf;

	if (stat(DISK_BY_LABEL_DIR, &sbuf) == 0)
		return;

	init_tree();
	populate_from_sysfs();
}

void drop_root_privileges(void)
{
	struct __user_cap_header_struct header;
	struct __user_cap_data_struct cap;

	gid_t groups[] = { AID_SYSTEM };

	memset(&header, 0, sizeof(header));
	memset(&cap, 0, sizeof(cap));

	if (setgroups(sizeof(groups)/sizeof(groups[0]), groups) < 0)
		WARNING("setgroups failed: %s", strerror(errno));

	prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0);

	if (chdir("/") < 0)
		WARNING("chdir failed: %s", strerror(errno));
	if (setgid(AID_SYSTEM) < 0)
		WARNING("setgid failed: %s", strerror(errno));
	if (setuid(AID_SYSTEM) < 0)
		WARNING("setuid failed: %s", strerror(errno));

	header.version = _LINUX_CAPABILITY_VERSION;
	header.pid = 0;
	cap.effective = cap.permitted = (1 << CAP_MKNOD);

	if (capset(&header, &cap) < 0)
		WARNING("capset failed: %s", strerror(errno));
}

int diskd_run(int argc, char **argv)
{
	int fd;
	struct pollfd ufd;
	struct sigaction sighandler;

	/* create base dir as root, change owner, and then drop root
	 * privileges.  */
	mkdir(DIR_TREE[0], DEFAULT_MODE);
	chown(DIR_TREE[0], AID_SYSTEM, AID_SYSTEM);

	drop_root_privileges();

	/* First, open the NETLINK socket to ensure we won't miss any
	 * events.  */
	fd = uevent_open_socket(NB_UEVENT_MSG * UEVENT_MSG_LEN, true);
	if (fd == -1) {
		ERROR("Failed to open uevent socket\n");
		exit(EXIT_FAILURE);
	}
	ufd.events = POLLIN;
	ufd.fd = fd;

	/* Install sighandler.  */
	sighandler.sa_handler = destroy_tree;
	sigemptyset(&sighandler.sa_mask);
	sighandler.sa_flags = 0;
	sigaction(SIGTERM, &sighandler, NULL);

	init_tree();

	/* Populate with the exiting devices.  */
	populate_from_sysfs();

	for (;;) {
		ufd.revents = 0;
		int nr = poll(&ufd, 1, -1);
		if (nr <= 0)
			continue;
		if (ufd.revents == POLLIN)
			handle_events(fd);
	}

	close(fd);
	destroy_tree(SIGTERM);

	return EXIT_SUCCESS;
}
