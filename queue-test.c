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
#include <unistd.h>

#include <glib.h>

#include "queue.h"

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

static GVariant *input;
static GQueue output = G_QUEUE_INIT;
static GQueue expected_output = G_QUEUE_INIT;

struct item {
	int val;
	GList e;
};

typedef struct item item_t;

item_t *item_new(int val)
{
	item_t *item = calloc(1, sizeof(item_t));

	item->val = val;

	item->e.data = item;

	return item;
}

void expected_output_get(GVariant *v, GQueue *q)
{
	GVariantIter i;
	char *s;
	item_t *item;
	int val;

	g_variant_iter_init(&i, v);

	while (g_variant_iter_loop(&i, "s", &s)) {

		sscanf(s, "%d", &val);

		item = item_new(val);

		g_queue_push_tail_link(q, &item->e);
	}
}

GVariant *input_add(GVariant *input, GVariant *new_input)
{
	GVariantBuilder b;
	GVariantIter i;
	GVariant *out;
	char *s;

	if (!input) {
		out = new_input;
		goto exit;
	}

	g_variant_builder_init(&b, G_VARIANT_TYPE_STRING_ARRAY);

	g_variant_iter_init(&i, input);

	while (g_variant_iter_loop(&i, "s", &s)) {
		g_variant_builder_add(&b, "s", s);
	}

	g_variant_iter_init(&i, new_input);

	while (g_variant_iter_loop(&i, "s", &s)) {
		g_variant_builder_add(&b, "s", s);
	}

	out =  g_variant_builder_end(&b);
exit:
	return out;
}

void line_parse(char *line)
{
	GVariant *v = g_variant_parse(G_VARIANT_TYPE("a{sas}"),
						line, NULL, NULL, NULL);
	GVariant *vin, *vex;

	printf("%s\n", g_variant_print(v, TRUE));

	if (vin = g_variant_lookup_value(v, "input", G_VARIANT_TYPE("as"))) {

		printf("input: %s\n", g_variant_print(vin, TRUE));

		input = input_add(input, vin);
	}

	if (vex = g_variant_lookup_value(v, "expected_output",
					G_VARIANT_TYPE("as"))) {

		printf("expected_output: %s\n", g_variant_print(vex, TRUE));

		expected_output_get(vex, &expected_output);
	}
}

struct node {
	int val;
	S_QUEUE_ENTRY(node) e;
};

typedef struct node node_t;

S_QUEUE(node) q;

node_t *node_new(int val)
{
	node_t *n = malloc(sizeof(node_t));
	n->val = val;
	return n;
}

node_t *node_find(int val)
{
	node_t *n;
	gboolean found = FALSE;

	S_QUEUE_FOREACH(&q, n, e) {

		if (n->val == val) {
			found = TRUE;
			break;
		}
	}

	return found ? n : NULL;
}

void s_queue_test(GVariant *v)
{
	S_QUEUE_INIT(&q);

	int v_len = g_variant_n_children(v);

	int op_idx = 0;
	GVariant *v_op, *v_p1, *v_p2;
	char *op, *p1, *p2;

more_input:
	v_op = g_variant_get_child_value(v, op_idx);

	v_p1 = g_variant_get_child_value(v, op_idx + 1);

	g_variant_get(v_op, "s", &op);

	printf("op: %s %s\n", g_variant_print(v_op, TRUE), op);

	g_variant_get(v_p1, "s", &p1);

	printf("p1: %s %s\n", g_variant_print(v_p1, TRUE), p1);

	if (EQ(op, "S_QUEUE_INSERT_HEAD")) {
		node_t *n = node_new(atoi(p1));
		S_QUEUE_INSERT_HEAD(&q, n, e);
	}

	if (EQ(op, "S_QUEUE_INSERT_TAIL")) {
		node_t *n = node_new(atoi(p1));
		S_QUEUE_INSERT_TAIL(&q, n, e);
	}

	if (EQ(op, "S_QUEUE_INSERT_AFTER")) {

		node_t *p, *n;

		p = node_find(atoi(p1));

		v_p2 = g_variant_get_child_value(v, op_idx + 2);

		g_variant_get(v_p2, "s", &p2);

		op_idx += 1;
		v_len -= 1;

		n = node_new(atoi(p2));

		S_QUEUE_INSERT_AFTER(&q, p, n, e);
	}

	if (EQ(op, "S_QUEUE_REMOVE")) {

		node_t *n = node_find(atoi(p1));

		S_QUEUE_REMOVE(&q, n, e);
	}

	op_idx += 2;
	v_len -= 2;

	if (v_len) {
		goto more_input;
	}

	{
		node_t *x;
		S_QUEUE_FOREACH(&q, x, e) {
			item_t *item = item_new(x->val);
			g_queue_push_tail_link(&output, &item->e);
		}
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
	FILE *f = (argc > 1) ? fopen(argv[1], "r") : stdin;
	int exit_status = EXIT_FAILURE;
	gboolean eq = TRUE;

	test_load(f);

	s_queue_test(input);

	if (g_queue_get_length(&output) !=
		g_queue_get_length(&expected_output)) {
		goto end_test;
	}

	while (!g_queue_is_empty(&output)) {

		GList *no = g_queue_peek_head_link(&output);
		GList *ne = g_queue_peek_head_link(&expected_output);

		item_t *o = no->data, *e = ne->data;

		if (o->val != e->val)
			eq = FALSE;

		g_queue_unlink(&output, no);
		g_queue_unlink(&expected_output, ne);
	}

	if (eq = TRUE) {
		exit_status = EXIT_SUCCESS;
	}
end_test:
	printf("TEST: %s\n", exit_status == EXIT_SUCCESS ? "PASSED" : "FAILED");

	return exit_status;
}
