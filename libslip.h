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

#ifndef LIBSLIP_H
#define LIBSLIP_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void libslip_t;

libslip_t *libslip_init(void);
int libslip_input(libslip_t *l, uint8_t in, uint8_t **out, size_t *out_len);
void libslip_output(uint8_t *in, size_t len, uint8_t *out, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* LIBSLIP_H */
