/*
 * list.c
 *
 *  Created on: 5 Dec 2017
 *      Author: Ander Juaristi
 */
#include <string.h>
#include <malloc.h>
#include "list.h"

void list_init(list_head_t *h)
{
	if (h) {
		memset(h, 0, sizeof(struct list_head_st));
		h->last = NULL;
	}
}

void list_push_back_noalloc(list_head_t *h, void *elem)
{
	struct list_node_st *new_elem;

	/* We don't allow NULL elements in this function */
	if (!h)
		return;

	new_elem = malloc(sizeof(struct list_node_st));
	new_elem->value = elem;
	new_elem->next = NULL;

	if (!h->last) {
		h->first = new_elem;
		h->last = new_elem;
	} else {
		h->last->next = new_elem;
		h->last = new_elem;
	}
}

void list_destroy(list_head_t *h, void (*destroyer_fn) (void **))
{
	struct list_node_st *next;

	if (!h)
		return;

	for (struct list_node_st *cur = h->first; cur; cur = next) {
		next = cur->next;

		if (cur->value) {
			if (destroyer_fn)
				destroyer_fn(&cur->value);
			else
				free(cur->value);
		}
		free(cur);
	}

	memset(h, 0, sizeof(struct list_head_st));
}

size_t list_count(list_head_t *h)
{
	size_t count = 0;

	if (h) {
		for (struct list_node_st *cur = h->first; cur; cur = cur->next)
			count++;
	}

	return count;
}
