/*
 * Copyright © 2017-2018, Intel Corporation.
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

#ifndef __SLIPCAT_H
#define __SLIPCAT_H

#include <stdio.h>
#include <errno.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

#define P(fmt, args...)	do {						\
	printf(fmt "\n", ## args);					\
} while (0)

#define D(fmt, args...)	do {						\
	if (opt_debug) {						\
		printf("%s:%s() " fmt "\n",				\
			__FILE__, __func__, ## args);			\
	}								\
} while (0)

#define W(fmt, args...)	do {						\
	printf("%s:%s() Error: " fmt "(): %s\n",			\
		__FILE__, __func__, ## args, strerror(errno));		\
} while (0)

#define E(fmt, args...)	do {						\
	printf("%s:%s() Error: " fmt "(): %s\n",			\
		__FILE__, __func__, ## args, strerror(errno));		\
	exit(EXIT_FAILURE);						\
} while (0)

#define _E(fmt, args...) do {						\
	printf("%s:%s() Error: " fmt "\n",				\
		__FILE__, __func__, ## args);				\
	exit(EXIT_FAILURE);						\
} while (0)

#ifdef __cplusplus
}
#endif

#endif /* __SLIPCAT_H */
