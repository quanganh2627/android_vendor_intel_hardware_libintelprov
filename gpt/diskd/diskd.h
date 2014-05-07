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

#ifndef _DISKD_H_
#define _DISKD_H_

#define DISK_BASE_DIR		"/dev/disk"
#define DISK_BY_LABEL_DIR	DISK_BASE_DIR"/by-label"
#define DISK_BY_UUID_DIR	DISK_BASE_DIR"/by-uuid"

void diskd_populate_tree(void);
int diskd_run(int argc, char **argv);

#endif	/* _DISKD_H_ */
