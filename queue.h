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

#ifndef _S_QUEUE_H
#define _S_QUEUE_H

#define S_QUEUE(_t) struct { struct _t *head, *tail; }

#define S_QUEUE_HEAD(_q) ({ (_q)->head;	})
#define S_QUEUE_TAIL(_q) ({ (_q)->tail; })

#define	S_QUEUE_INIT(_q) do {				\
	S_QUEUE_HEAD(_q) = S_QUEUE_TAIL(_q) = NULL;	\
} while (0)

#define	S_QUEUE_EMPTY(_q) ({ (S_QUEUE_HEAD(_q) == NULL); })

#define S_QUEUE_ENTRY(_t) struct { struct _t *next, *prev; }

#define S_QUEUE_NEXT(_n, _e) ({ (_n)->_e.next; })
#define S_QUEUE_PREV(_n, _e) ({ (_n)->_e.prev; })

#define	S_QUEUE_FOREACH(_q, _n, _e) \
	for ((_n) = S_QUEUE_HEAD(_q); (_n); (_n) = S_QUEUE_NEXT(_n, _e))

#define	S_QUEUE_FOREACH_REVERSE(_q, _n, _e) \
	for ((_n) = S_QUEUE_TAIL(_q); (_n); (_n) = S_QUEUE_PREV(_n, _e))

#define S_QUEUE_INSERT_HEAD(_q, _n, _e) do {				\
	S_QUEUE_PREV(_n, _e) = NULL;					\
	S_QUEUE_NEXT(_n, _e) = S_QUEUE_HEAD(_q);			\
	S_QUEUE_HEAD(_q) = (_n);					\
	if (S_QUEUE_NEXT(_n, _e)) {					\
		S_QUEUE_PREV(S_QUEUE_NEXT(_n, _e), _e) = (_n);		\
	} else {							\
		S_QUEUE_TAIL(_q) = (_n);				\
	}								\
} while (0)

#define S_QUEUE_INSERT_TAIL(_q, _n, _e) do {				\
	S_QUEUE_PREV(_n, _e) = S_QUEUE_TAIL(_q);			\
	S_QUEUE_TAIL(_q) = (_n);					\
	S_QUEUE_NEXT(_n, _e) = NULL;					\
	if (S_QUEUE_PREV(_n, _e)) {					\
		S_QUEUE_NEXT(S_QUEUE_PREV(_n, _e), _e) = (_n);		\
	} else {							\
		S_QUEUE_HEAD(_q) = (_n);				\
	}								\
} while (0)

#define S_QUEUE_INSERT_AFTER(_q, _n, _new, _e) do {			\
	if (S_QUEUE_NEXT(_n, _e)) {					\
		S_QUEUE_PREV(_new, _e) = (_n);				\
		S_QUEUE_NEXT(_new, _e) = S_QUEUE_NEXT(_n, _e);		\
		S_QUEUE_NEXT(_n, _e) = (_new);				\
		S_QUEUE_PREV(S_QUEUE_NEXT(_new, _e), _e) = (_new);	\
	} else {							\
		S_QUEUE_INSERT_TAIL(_q, _new, _e);			\
	}								\
} while (0)

#define	S_QUEUE_REMOVE(_q, _n, _e) do {					\
	if (S_QUEUE_PREV(_n, _e)) {					\
		S_QUEUE_NEXT(S_QUEUE_PREV(_n, _e), e) =			\
			S_QUEUE_NEXT(_n, _e);				\
	} else {							\
		S_QUEUE_HEAD(_q) = S_QUEUE_NEXT(_n, _e);		\
	}								\
	if (S_QUEUE_NEXT(_n, _e)) {					\
		S_QUEUE_PREV(S_QUEUE_NEXT(_n, _e), e) =			\
			S_QUEUE_PREV(_n, _e);				\
	} else {							\
		S_QUEUE_TAIL(_q) = S_QUEUE_PREV(_n, _e);		\
	}								\
} while (0)

#endif /* _S_QUEUE_H */
