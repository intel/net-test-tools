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

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <glib.h>

#include <libslip.h>
#include <libslip_types.h>

#define E(fmt, args...)                                                 \
do {                                                                    \
        fprintf(stderr, "%s:%s() Error: " fmt,				\
		__FILE__, __func__, ## args);				\
	exit(EXIT_FAILURE);						\
} while (0)

#define _E(fmt, args...)                                                 \
do {                                                                    \
        fprintf(stderr, "%s:%s() Error: " fmt "(): %s",			\
		__FILE__, __func__, ## args, strerror(errno));		\
	exit(EXIT_FAILURE);						\
} while (0)

#define EQ(_s1, _s2) (strcmp(_s1, _s2) == 0)

uint8_t s_to_u8(char *s)
{
	uint16_t b;

	if (EQ(s, "SLIP_ESC")) {
		b = SLIP_ESC;
		goto out;
	}

	if (EQ(s, "SLIP_END")) {
		b = SLIP_END;
		goto out;
	}

	if (EQ(s, "SLIP_ESC_ESC")) {
		b = SLIP_ESC_ESC;
		goto out;
	}

	if (EQ(s, "SLIP_ESC_END")) {
		b = SLIP_ESC_END;
		goto out;
	}

	sscanf(s, "%hu", &b);
out:
	if (b > UINT8_MAX) {
		E("%hu > UINT8_MAX", b);
	}

	return b;
}

struct pdu {
	ssize_t len;
	uint8_t *data;
	GList e;
};

typedef struct pdu pdu_t;

static GQueue input = G_QUEUE_INIT;
static GQueue output = G_QUEUE_INIT;
static GQueue expected_output = G_QUEUE_INIT;

pdu_t *pdu_new(void)
{
	pdu_t *pdu = calloc(1, sizeof(pdu_t));

	pdu->e.data = pdu;

	return pdu;
}

void input_line(FILE *f, GQueue *pdus)
{
	char *line = NULL;
	size_t line_len = 0;
	ssize_t len = getline(&line, &line_len, f);

	if (len <= 0) {
		_E("getline");
	}

	printf("line: %s", line);

	{
		GVariant *v = g_variant_parse(G_VARIANT_TYPE ("aas"),
						line, NULL, NULL, NULL);
		GVariant *v_pdu;
		GVariantIter i, i_pdu;
		gchar *s;
		pdu_t *pdu;
		int j;

		g_variant_iter_init(&i, v);

		while (g_variant_iter_loop(&i, "*", &v_pdu)) {

			g_variant_iter_init(&i_pdu, v_pdu);

			pdu = pdu_new();

			pdu->len = g_variant_n_children(v_pdu);
			pdu->data = malloc(pdu->len);

			j = 0;

			while (g_variant_iter_loop(&i_pdu, "s", &s)) {

				pdu->data[j++] = s_to_u8(s);

			}

			g_queue_push_tail_link(pdus, &pdu->e);
		}
	}
}

void input_line2(FILE *f)
{
	char *line = NULL;
	size_t line_len = 0;
	ssize_t len = getline(&line, &line_len, f);

	if (len <= 0) {
		_E("getline");
	}

	printf("line: %s", line);

	{
		GVariant *v = g_variant_parse(G_VARIANT_TYPE("a{sa{ss}}"),
						line, NULL, NULL, NULL);

		printf("%s\n", g_variant_print(v, TRUE));

		GVariant *slip;

		slip = g_variant_lookup_value(v, "slip", G_VARIANT_TYPE("a{ss}"));

		printf("%s\n", g_variant_print(slip, TRUE));

		GVariantIter i;

		g_variant_iter_init(&i, slip);

		char *key, *value;

		while (g_variant_iter_loop(&i, "{ss}", &key, &value)) {

			printf("%s=%s\n", key, value);
		}
	}
}

void test_slip_input(libslip_t *l, GQueue *input, GQueue *output)
{
	int i;
	pdu_t *in, *out;
	uint8_t *data_out;
	size_t data_out_len;
	GList *n;

	for (n = input->head; n; n = n->next) {

		in = n->data;

		for (i = 0; i < in->len; i++) {

			if (libslip_input(l, in->data[i],
						&data_out, &data_out_len)) {

				out = pdu_new();

				out->len = data_out_len;
				out->data = malloc(out->len);

				memcpy(out->data, data_out, out->len);

				g_queue_push_tail_link(output, &out->e);
			}
		}
	}
}

int main(int argc, char *argv[])
{
	FILE *f = (argc > 1) ? fopen(argv[1], "r") : stdin;
	int exit_status = EXIT_FAILURE;
	libslip_t *l;

	input_line(f, &input);

	input_line(f, &expected_output);

	//input_line2(f);

	l = libslip_init();

	test_slip_input(l, &input, &output);

	while (!g_queue_is_empty(&output)) {

		GList *no = g_queue_peek_head_link(&output);
		GList *ne = g_queue_peek_head_link(&expected_output);

		pdu_t *o = no->data, *e = ne->data;

		if (o->len == e->len &&
			memcmp(o->data, e->data, o->len) == 0) {
			exit_status = EXIT_SUCCESS;
		}

		g_queue_unlink(&output, no);
		g_queue_unlink(&expected_output, ne);
	}

	printf("TEST: %s\n", exit_status == EXIT_SUCCESS ? "PASSED" : "FAILED");

	exit(exit_status);

	return 0;
}
