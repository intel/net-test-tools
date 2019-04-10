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
#include <errno.h>

#include <glib.h>

#include "slipcat.h"
#include "libslipcat.h"

void line_parse(char *line)
{
	GVariant *v = g_variant_parse(G_VARIANT_TYPE("a{ss}"),
						line, NULL, NULL, NULL);
	GVariant *vin, *vex;

	printf("%s\n", g_variant_print(v, TRUE));

	if (vin = g_variant_lookup_value(v, "input", G_VARIANT_TYPE("as"))) {

		printf("input: %s\n", g_variant_print(vin, TRUE));
	}

	if (vex = g_variant_lookup_value(v, "expected_output",
					G_VARIANT_TYPE("as"))) {

		printf("expected_output: %s\n", g_variant_print(vex, TRUE));
	}
}

void test_load(FILE *f)
{
	char *line = NULL;
	size_t line_len = 0;
	ssize_t chars_read;

	while ((chars_read = getline(&line, &line_len, f)) > 0) {

		printf("line: %s", line);

		if (line[0] != '#') {
			line_parse(line);
		}

		free(line);
		line = NULL;
		line_len = 0;
	}

	if (chars_read < 0 && errno) {
		_E("getline");
	}
}

int main(int argc, char *argv[])
{
	int exit_status = EXIT_FAILURE;
	FILE *fp = (argc > 1) ? fopen(argv[1], "r") : stdin;

	test_load(fp);
end_test:
	printf("TEST: %s\n", exit_status == EXIT_SUCCESS ? "PASSED" : "FAILED");

	return exit_status;
}
