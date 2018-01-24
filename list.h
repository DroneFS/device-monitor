/*
 * list.h
 *
 *  Created on: 5 Dec 2017
 *      Author: Ander Juaristi
 */
#ifndef __LIST_H__
#define __LIST_H__
#include <stddef.h>
#include <stdbool.h>

#define LIST_HEAD_INIT() \
	{ \
		.first = NULL, \
		.last = NULL \
	}

/*
 * Singly-linked list with a pointer to the last element.
 */
struct list_node_st {
	struct list_node_st *next;
	void *value;
};
struct list_head_st {
	struct list_node_st *first;
	struct list_node_st *last;
};
typedef struct list_head_st list_head_t;

void list_init(list_head_t *);
void list_destroy(list_head_t *, void (*) (void **));

void list_push_back_noalloc(list_head_t *, void *);

size_t list_count(list_head_t *);

#endif
