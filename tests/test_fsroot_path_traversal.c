#include <stdlib.h>
#include <malloc.h>
#include <check.h>
#include "../fsroot-path.h"

static void test_basename(struct fsroot_path *p, const char *expected_basename, int lineno)
{
	char *basename = fsroot_path_get_basename(p);
	ck_assert_msg(basename != NULL, "fsroot_path_get_basename() returned NULL\n");
	ck_assert_msg(strcmp(basename, expected_basename) == 0,
		"Basename test failed (line: %d): Returned: '%s'; Expected: '%s'\n",
		lineno, basename, expected_basename);
	/* String returned by fsroot_path_get_basename() to be freed by caller */
	free(basename);
}

static void test_dir(struct fsroot_path *p, const char *expected_dir, int lineno)
{
	char *dir = fsroot_path_get_dir(p);
	ck_assert_msg(dir != NULL, "fsroot_path_get_dir() returned NULL\n");
	ck_assert_msg(strcmp(dir, expected_dir) == 0,
		"Directory test failed (line: %d): Returned: '%s'; Expected: '%s'\n",
		lineno, dir, expected_dir);
	/* String returned by fsroot_path_get_dir() to be freed by the caller */
	free(dir);
}

static void test_path(struct fsroot_path *p, const char *expected_path, int lineno)
{
	char *path = fsroot_path_get_path(p);
	ck_assert_msg(path != NULL, "fsroot_path_get_path() returned NULL\n");
	ck_assert_msg(strcmp(path, expected_path) == 0,
		"Path test failed (line: %d): Returned: '%s'; Expected: '%s'\n",
		lineno, path, expected_path);
	/* String returned by fsroot_path_get_path() to be freed by the caller */
	free(path);
}

START_TEST(test_fsroot_path_previous)
{
	char *path = "foo/bar/../filename.txt";
	struct fsroot_path *p = fsroot_path_new(path);
	ck_assert_msg(p != NULL, "fsroot_path_new(\"%s\") returned NULL\n", path);

	test_basename(p, "filename.txt", __LINE__);
	test_dir(p, "foo", __LINE__);
	test_path(p, "foo/filename.txt", __LINE__);

	fsroot_path_destroy(p);

	char *path2 = "foo/bar/baz/../foo/../filename.txt";
	p = fsroot_path_new(path2);
	ck_assert_msg(p != NULL, "fsroot_path_new(\"%s\") returned NULL\n", path2);

	test_basename(p, "filename.txt", __LINE__);
	test_dir(p, "foo/bar", __LINE__);
	test_path(p, "foo/bar/filename.txt", __LINE__);

	fsroot_path_destroy(p);

	char *path3 = "foo/bar/baz/../foo/../../filename.txt";
	p = fsroot_path_new(path3);
	ck_assert_msg(p != NULL, "fsroot_path_new(\"%s\") returned NULL\n", path3);

	test_basename(p, "filename.txt", __LINE__);
	test_dir(p, "foo", __LINE__);
	test_path(p, "foo/filename.txt", __LINE__);

	fsroot_path_destroy(p);
}
END_TEST

START_TEST(test_fsroot_path_current)
{
	char *path = "foo/bar/./filename.txt";
	struct fsroot_path *p = fsroot_path_new(path);
	ck_assert_msg(p != NULL, "fsroot_path_new(\"%s\") returned NULL\n", path);

	test_basename(p, "filename.txt", __LINE__);
	test_dir(p, "foo/bar", __LINE__);
	test_path(p, "foo/bar/filename.txt", __LINE__);

	fsroot_path_destroy(p);

	char *path2 = "foo/././filename.txt";
	p = fsroot_path_new(path2);
	ck_assert_msg(p != NULL, "fsroot_path_new(\"%s\") returned NULL\n", path2);

	test_basename(p, "filename.txt", __LINE__);
	test_dir(p, "foo", __LINE__);
	test_path(p, "foo/filename.txt", __LINE__);

	fsroot_path_destroy(p);

	char *path3 = "foo/./././././filename.txt";
	p = fsroot_path_new(path3);
	ck_assert_msg(p != NULL, "fsroot_path_new(\"%s\") returned NULL\n", path3);

	test_basename(p, "filename.txt", __LINE__);
	test_dir(p, "foo", __LINE__);
	test_path(p, "foo/filename.txt", __LINE__);
}
END_TEST

Suite *fsroot_suite()
{
	Suite *s;
	TCase *tc;

	s = suite_create("fsroot-path tests");

	tc = tcase_create("core");
	tcase_add_test(tc, test_fsroot_path_previous);
	tcase_add_test(tc, test_fsroot_path_current);

	suite_add_tcase(s, tc);
	return s;
}

int main()
{
	int failed;
	Suite *s;
	SRunner *sr;

	s = fsroot_suite();
	sr = srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);
	failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
