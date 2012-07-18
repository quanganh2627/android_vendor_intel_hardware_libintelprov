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

#ifndef MODEM_NVM_H
#define MODEM_NVM_H

#include <cmfwdl.h>
#include "modem_fw.h"

#define OUTPUT_DEBUG                1
#define OUTPUT_FASTBOOT_INFO        2

#define MIN(a,b) ((a) < (b) ? (a) : (b))

typedef void (*modem_nvm_status_callback)(const char *msg, int output);

int flash_modem_nvm(const char *nvm_filename, modem_nvm_status_callback cb);
int read_modem_nvm_id(char* out_buffer, size_t max_out_size, modem_nvm_status_callback cb);

#endif
