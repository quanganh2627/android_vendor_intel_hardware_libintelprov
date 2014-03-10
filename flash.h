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

#ifndef _FLASH_H_
#define _FLASH_H_

#include <sys/types.h>

#define ANDROID_OS_NAME     "boot"
#define RECOVERY_OS_NAME    "recovery"
#define FASTBOOT_OS_NAME    "fastboot"
#define DROIDBOOT_OS_NAME   "droidboot"
#define TEST_OS_NAME        "testos"
#define SPLASHSCREEN_NAME   "splashscreen"
#define ESP_PART_NAME       "ESP"

int flash_token_umip(void *data, size_t size);
int update_ifwi_image(void *data, size_t size, unsigned reset_flag);
int update_ifwi_file(void *data, size_t size);
int check_ifwi_file(void *data, size_t size);
int flash_ulpmc(void *data, unsigned sz);
int flash_dnx(void *data, size_t size);
int flash_ifwi(void *data, unsigned sz);
int flash_token_umip(void *data, size_t size);
int flash_capsule(void *data, unsigned sz);

int flash_image(void *data, unsigned sz, const char *name);
int read_image(const char *name, void **data);
int read_image_signature(void **buf, char *name);
int flash_android_kernel(void *data, unsigned sz);
int flash_recovery_kernel(void *data, unsigned sz);
int flash_fastboot_kernel(void *data, unsigned sz);
int flash_splashscreen_image(void *data, unsigned sz);
int flash_esp(void *data, unsigned sz);
int flash_testos(void *data, unsigned sz);

/* Returns:
 * -1: error
 * 0: unsigned image
 * 1: signed image
 */
int is_image_signed(const char *name);
int flash_token_umip(void *data, size_t size);

#endif	/* _FLASH_H_ */
