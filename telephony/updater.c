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

#include <edify/expr.h>
#include <updater/updater.h>
#include <libgen.h>

#include "common.h"
#include "util.h"

static Value* push_file(const char *name, State * state, int argc, Expr * argv[])
{
	Value *ret = NULL;
	char output[PATH_MAX];
	char *filename = NULL;

	create_config_folder();

	if (ReadArgs(state, argv, 1, &filename) < 0) {
		ErrorAbort(state, "wrong parameter");
		goto out;
	}

	if (filename == NULL || strlen(filename) == 0) {
		ErrorAbort(state, "filename argument %s cannot be empty", name);
		goto out;
	}

	snprintf(output, sizeof(output), "%s/%s", TELEPHONY_PROVISIONING, basename(filename));
	if (!file_copy(filename, output) && ! set_file_permission(output))
		ret = StringValue(strdup(""));
	else
		ErrorAbort(state, "failed to create file %s", filename);

out:
	free(filename);
	return ret;
}

void RegisterTelephonyFunctions(void)
{
	RegisterFunction("flash_modem", push_file);
}
