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

#include <libgen.h>
#include <limits.h>
#include <stdio.h>

#include "common.h"
#include "util.h"

void cmd_push_mdm_fw(const char *filename)
{
	char output[PATH_MAX];
	snprintf(output, sizeof(output), "%s/%s", TELEPHONY_PROVISIONING,
			basename(filename));
	if (!file_copy(filename, output)) {
		fprintf(stdout, "file %s successfully written\n", output);
		set_file_permission(filename);
	} else
		fprintf(stderr, "failed to write %s\n", output);
}
