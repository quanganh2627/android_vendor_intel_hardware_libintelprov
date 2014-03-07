/*
 * Copyright 2011-2014 Intel Corporation
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

#include <unistd.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "common.h"

#define FILE_PERMISSION (S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP)

int set_file_permission(const char *filename)
{
	int ret = -1;
	struct passwd *pwd = getpwnam("radio");
	if (pwd) {
		uid_t uid = pwd->pw_uid;
		if (!chown(filename, uid, uid))
			ret = chmod(filename, FILE_PERMISSION);
	}
	return ret;
}

int create_config_folder(void)
{
	int ret = mkdir(TELEPHONY_PROVISIONING, FILE_PERMISSION);
	if (!ret)
		ret = set_file_permission(TELEPHONY_PROVISIONING);
	return ret;
}
