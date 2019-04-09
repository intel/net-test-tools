/*
 * Copyright © 2019, Intel Corporation.
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

#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "slipcat.h"

static int opt_debug = 1;

/*
  Input:
    - ipv4:port
    - ipv4
    - :port
 */
struct sockaddr_in *s_in_new(const char *s)
{
	struct sockaddr_in *s_in = calloc(1, sizeof(*s_in));
	int r, addr_len = strlen(s);
	const char *addr, *sp = strchr(s, ':');

	if (sp) {
		int port = atoi(sp + 1);

		if (port > 0 && port <= 65535) {
			s_in->sin_port = htons(port);
		}

		addr_len = sp - s;
	}

	if (addr_len) {
		addr = (const char *) strndupa(s, addr_len);

		r = inet_pton(AF_INET, addr, &s_in->sin_addr);

		if (r <= 0) {
			if (r == 0)
				fprintf(stderr, "Not in presentation format");
			else
				perror("inet_pton");
			exit(EXIT_FAILURE);
		}
	}

	D("in: '%s', out: %s:%hu", s,
		inet_ntoa(s_in->sin_addr), ntohs(s_in->sin_port));

	s_in->sin_family = AF_INET;

	return s_in;
}
