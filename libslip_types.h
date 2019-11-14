/*
 * Copyright © 2018-2019, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU Lesser General Public License,
 * version 2.1, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 */

#ifndef LIBSLIP_TYPES_H
#define LIBSLIP_TYPES_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SLIP_END	0xc0
#define SLIP_ESC	0xdb
#define SLIP_ESC_END	0xdc
#define SLIP_ESC_ESC	0xdd

typedef struct {
	int esc;
	int end;
	uint8_t *data;
	uint8_t len;
	uint8_t *buf;
	size_t buf_len;
} slip_t;

#ifdef __cplusplus
}
#endif

#endif /* LIBSLIP_TYPES_H */
