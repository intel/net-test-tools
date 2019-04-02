/*
 * Copyright © 2018, Intel Corporation.
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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <libslip.h>
#include <libslip_types.h>

libslip_t *libslip_init(void)
{
	slip_t *s = calloc(1, sizeof(slip_t));

	s->buf_len = 1522;

	s->buf = malloc(s->buf_len);

	s->data = s->buf;

	return s;
}

static void slip(slip_t *s, uint8_t in)
{
	switch(in) {
	case SLIP_END:
		s->end = 1;
		break;
	case SLIP_ESC:
		s->esc = 1;
		break;
	case SLIP_ESC_ESC:
	case SLIP_ESC_END:
		if (s->esc) {
			if (in == SLIP_ESC_ESC) {
				in = SLIP_ESC;
			} else {
				in = SLIP_END;
			}
			s->esc = 0;
		}
		/* fallthrough */
	default:
		s->data[s->len++] = in;
	}
}

int libslip_input(libslip_t *l, uint8_t in, uint8_t **out, size_t *out_len)
{
	slip_t *s = (void *) l;

	if (s->end) {
		s->data = s->buf;
		s->len = 0;
		s->end = 0;
	}

	slip(s, in);

	if (s->end) {
		*out = s->data;
		*out_len = s->len;
	}

	return (s->end) && (s->len);
}

void libslip_output(uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len)
{
	int i, j;
	for(i = j = 0; i < in_len; i++) {
		switch(in[i]) {
		case SLIP_END:
			out[j++] = SLIP_ESC;
			out[j++] = SLIP_ESC_END;
			break;
		case SLIP_ESC:
			out[j++] = SLIP_ESC;
			out[j++] = SLIP_ESC_ESC;
			break;
		default:
			out[j++] = in[i];
			break;
		}
	}
	out[j++] = SLIP_END;
	*out_len = j;
}
