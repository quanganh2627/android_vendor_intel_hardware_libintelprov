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

#ifndef UTIL_H
#define UTIL_H

int file_write(const char *filename, const void *what, size_t sz);
int file_string_write(const char *filename, const char *what);
void dump_trace_file(const char *filename);
int file_read(const char *filename, void **datap, size_t *szp);
int safe_read(int fd, void *data, size_t size);
int snhexdump(char *str, size_t size, const unsigned char *data, unsigned int sz);
void hexdump_buffer(const unsigned char *buffer, unsigned int buffer_size, void
		(*printrow)(const char *text), unsigned int bytes_per_row);
void twoscomplement( unsigned char *cs, unsigned char *buf, unsigned int size);
int is_hex(char c);

#endif
