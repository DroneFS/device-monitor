#include <stdlib.h>
#include <malloc.h>
#include <check.h>
#include "../linux/fsroot-path.h"

static void test_basename(struct fsroot_path *p, const char *expected_basename)
{
	char *basename = fsroot_path_get_basename(p);
	ck_assert_msg(basename != NULL, "fsroot_path_get_basename() returned NULL\n");
	ck_assert_str_eq(basename, expected_basename);
	/* String returned by fsroot_path_get_basename() to be freed by caller */
	free(basename);
}

START_TEST(test_fsroot_path_basename)
{
	char *path = "foo/bar/filename.txt";
	struct fsroot_path *p = fsroot_path_new(path);
	ck_assert_msg(p != NULL, "fsroot_path_new(\"%s\") returned NULL\n", path);

	test_basename(p, "filename.txt");
	fsroot_path_destroy(p);
}
END_TEST

START_TEST(test_fsroot_path_basename_with_leading_slash)
{
	char *path = "/foo/bar/filename.txt";
	struct fsroot_path *p = fsroot_path_new(path);
	ck_assert_msg(p != NULL, "fsroot_path_new(\"%s\") returned NULL\n", path);

	test_basename(p, "filename.txt");
	fsroot_path_destroy(p);
}
END_TEST

START_TEST(test_fsroot_path_basename_with_trailing_slash)
{
	char *path = "foo/bar/filename.txt/";
	struct fsroot_path *p = fsroot_path_new(path);
	ck_assert_msg(p != NULL, "fsroot_path_new(\"%s\") returned NULL\n", path);

	/* There's no basename, technically */
	ck_assert(fsroot_path_get_basename(p) == NULL);
	fsroot_path_destroy(p);
}
END_TEST

START_TEST(test_fsroot_path_basename_with_leading_and_trailing_slash)
{
	char *path = "/foo/bar/filename.txt/";
	struct fsroot_path *p = fsroot_path_new(path);
	ck_assert_msg(p != NULL, "fsroot_path_new(\"%s\") returned NULL\n", path);

	/* Likewise, there's no basename here either */
	ck_assert(fsroot_path_get_basename(p) == NULL);
	fsroot_path_destroy(p);
}
END_TEST

START_TEST(test_fsroot_path_basename_rootdir)
{
	char *path = "/";
	struct fsroot_path *p = fsroot_path_new(path);
	ck_assert_msg(p != NULL, "fsroot_path_new(\"%s\") returned NULL\n", path);
	ck_assert(fsroot_path_get_basename(p) == NULL);
	fsroot_path_destroy(p);

	char *path2 = "";
	p = fsroot_path_new(path2);
	ck_assert_msg(p != NULL, "fsroot_path_new(\"%s\") returned NULL\n", path2);
	ck_assert(fsroot_path_get_basename(p) == NULL);
	fsroot_path_destroy(p);
}
END_TEST

START_TEST(test_fsroot_path_basename_single_file)
{
	struct fsroot_path *p;

	char *path = "/filename.txt";
	p = fsroot_path_new(path);
	ck_assert_msg(p != NULL, "fsroot_path_new(\"%s\") returned NULL\n", path);
	test_basename(p, "filename.txt");
	fsroot_path_destroy(p);

	char *path2 = "filename.txt";
	p = fsroot_path_new(path2);
	ck_assert_msg(p != NULL, "fsroot_path_new(\"%s\") returned NULL\n", path2);
	test_basename(p, "filename.txt");
	fsroot_path_destroy(p);

	char *path3 = "filename.txt/";
	p = fsroot_path_new(path3);
	ck_assert_msg(p != NULL, "fsroot_path_new(\"%s\") returned NULL\n", path3);
	ck_assert(fsroot_path_get_basename(p) == NULL);
	fsroot_path_destroy(p);

	char *path4 = "/filename.txt/";
	p = fsroot_path_new(path4);
	ck_assert_msg(p != NULL, "fsroot_path_new(\"%s\") returned NULL\n", path4);
	ck_assert(fsroot_path_get_basename(p) == NULL);
	fsroot_path_destroy(p);
}
END_TEST

Suite *fsroot_suite()
{
	Suite *s;
	TCase *tc;

	s = suite_create("fsroot-path tests");

	tc = tcase_create("core");
	tcase_add_test(tc, test_fsroot_path_basename);
	tcase_add_test(tc, test_fsroot_path_basename_with_leading_slash);
	tcase_add_test(tc, test_fsroot_path_basename_with_trailing_slash);
	tcase_add_test(tc, test_fsroot_path_basename_with_leading_and_trailing_slash);
	tcase_add_test(tc, test_fsroot_path_basename_rootdir);
	tcase_add_test(tc, test_fsroot_path_basename_single_file);

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
