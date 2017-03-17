#include <stdio.h>
#include <string.h>
#include "mm.h"

struct fsroot_path {
	char **parts;
	size_t num_parts;
	char has_basename;
};

static void __fsroot_invert_array(const char **arr, size_t len)
{
	const char *tmp;
	for (size_t i = 0; i < (len / 2); i++) {
		tmp = arr[i];
		arr[i] = arr[len - i - 1];
		arr[len - i - 1] = tmp;
	}
}

static char **__fsroot_path_split(const char *path_start, const char *path_end, size_t *outlen, int *needs_normalize)
{
	char *part;
	size_t parts_len = 10, count = 0, idx = 0;
	char **parts = mm_new(parts_len, char *);

	*needs_normalize = 0;

	while (path_end > path_start) {
		while (*path_end == '/') {
			path_end--;
			if (path_end < path_start)
				goto fail;
		}
		while (path_end >= path_start && *path_end != '/') {
			if (*path_end <= 0x20 || *path_end > 0x7E)
				goto fail;

			count++;
			path_end--;
		}

		part = strndup(path_end + 1, count);
		if (strcmp(part, ".") == 0 || strcmp(part, "..") == 0)
			*needs_normalize = 1;

		parts[idx++] = part;

		if (idx == parts_len) {
			parts_len <<= 1;
			parts = mm_reallocn(parts, parts_len, sizeof(char *));
		}

		count = 0;
	}

	if (idx == 0)
		goto fail;

	__fsroot_invert_array((const char **) parts, idx);
	*outlen = idx;
	return parts;
fail:
	free(parts);
	return NULL;
}

static size_t *__fsroot_compute_path_indexes(const char **path, size_t len, size_t *outlen)
{
	size_t idx = 0, count = 0;
	size_t *indexes = mm_new(len, size_t);

	while (idx < len) {
		if (strcmp(path[idx], "..") == 0) {
			idx++;
			/* We can't let count wrap around itself */
			if (count-- == 0)
				goto fail;
			continue;
		} else if (strcmp(path[idx], ".") == 0) {
			idx++;
			continue;
		}

		if (count == len) {
			len <<= 1;
			indexes = mm_reallocn(indexes, len, sizeof(size_t));
		}

		indexes[count++] = idx++;
	}

	if (count == 0)
		goto fail;

	*outlen = count;
	return indexes;
fail:
	free(indexes);
	return NULL;
}

static int __fsroot_path_normalize(struct fsroot_path *p)
{
	size_t index_idx;
	size_t *indexes = NULL, indexes_len = 0;

	indexes = __fsroot_compute_path_indexes((const char **) p->parts, p->num_parts, &indexes_len);

	if (indexes_len == p->num_parts)
		return 1;
	else if (indexes_len == 0)
		return 0;
	if (!indexes)
		return 0;

	for (index_idx = 0; index_idx < indexes_len; index_idx++)
		p->parts[index_idx] = strdup(p->parts[indexes[index_idx]]);

	for (size_t part_idx = index_idx; part_idx < p->num_parts; part_idx++)
		mm_free(p->parts[part_idx]);
	p->num_parts = index_idx;

	return 1;
}

static char *__fsroot_build_path(const char **parts, size_t start, size_t end)
{
	const char *cur_part;
	const char slash = '/';
	char *fullpath = NULL;
	size_t fullpath_len = 1; /* Count the NULL terminator */

	for (size_t i = start; i < end; i++) {
		cur_part = parts[i];
		if (!cur_part || !*cur_part)
			continue;

		fullpath_len += strlen(cur_part) + 1; /* +1 for the trailing slash ('/') */
	}

	fullpath = mm_new(fullpath_len, char);

	for (size_t i = start; i < end; i++) {
		strcat(fullpath, parts[i]);
		if (i + 1 < end)
			strncat(fullpath, &slash, 1);
	}

	return fullpath;
}

struct fsroot_path *fsroot_path_new(const char *path)
{
	size_t *indexes = NULL, indexes_len = 0;
	const char *path_end;
	int needs_normalize;
	struct fsroot_path *p;

	if (!path)
		return NULL;

	p = mm_new0(struct fsroot_path);
	if (!*path)
		goto end;

	path_end = path + strlen(path) - 1;
	p->parts = __fsroot_path_split(path, path_end, &p->num_parts, &needs_normalize);

	if (needs_normalize)
		__fsroot_path_normalize(p);

	if (*path_end == '/')
		p->has_basename = 0;
	else
		p->has_basename = 1;

end:
	return p;
}

void fsroot_path_destroy(struct fsroot_path *path)
{
	if (path) {
		for (size_t i = 0; i < path->num_parts; i++)
			mm_free(path->parts[i]);
		mm_free(path->parts);
		path->num_parts = 0;
	}
}

char *fsroot_path_get_basename(const struct fsroot_path *path)
{
	char *basename = NULL;

	if (!path || !path->parts || path->num_parts == 0)
		return NULL;
	if (!path->has_basename)
		return NULL;

	basename = path->parts[path->num_parts - 1];
	if (!basename)
		return NULL;

	return strdup(basename);
}

char *fsroot_path_get_dir(const struct fsroot_path *path)
{
	if (!path || !path->parts || path->num_parts == 0)
		return NULL;

	if (path->has_basename) {
		/*
		 * Return everything except the last component,
		 * which is the basename.
		 */
		return __fsroot_build_path((const char **) path->parts, 0, path->num_parts - 1);
	} else {
		/* Return everything */
		return __fsroot_build_path((const char **) path->parts, 0, path->num_parts);
	}
}

char *fsroot_path_get_path(const struct fsroot_path *path)
{
	if (!path || !path->parts || path->num_parts == 0)
		return NULL;

	return __fsroot_build_path((const char **) path->parts, 0, path->num_parts);
}
