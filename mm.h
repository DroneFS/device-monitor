/*
 * mm.h - Memory management functions
 *
 *  Created on: 22 Nov 2016
 *      Author: Ander Juaristi
 */
#ifndef __MM_H__
#define __MM_H__
#include <malloc.h>

void __attribute__((__malloc__)) *mm_malloc0(size_t len);
void __attribute__((__malloc__)) *mm_mallocn0(size_t count, size_t len);

#define mm_new(n, type) mm_mallocn0(n, sizeof(type))
#define mm_new0(type)   mm_malloc0(sizeof(type))
#define mm_new0n(n)     mm_malloc0(n)
#define mm_free(ptr)    do { if (ptr) free(ptr); ptr = NULL; } while (0)

void *mm_reallocn(void *ptr, size_t count, size_t len);
void *mm_realloc(void *ptr, size_t count);

#endif

