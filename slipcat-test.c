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

#include <stdio.h>
#include <stdlib.h>

#include <libslipcat.h>

int main(int argc, char *argv[])
{
	int exit_status = EXIT_FAILURE;
	FILE *fp = (argc > 1) ? fopen(argv[1], "r") : stdin;

end_test:
	printf("TEST: %s\n", exit_status == EXIT_SUCCESS ? "PASSED" : "FAILED");

	return exit_status;
}
