#include <check.h>
#include <unistd.h>
#include <sys/stat.h>
#include "../linux/fsroot.h"
#include "utils.h"

START_TEST(test_fsroot_delete_file_released)
{
	fsroot_t *fs;
	int retval;
	char *foo = "foo", *bar = "bar";

	retval = fsroot_init(&fs, root_dir);
	ck_assert_msg(retval == S_OK, "fsroot_init(\"%s\") returned %d\n",
			root_dir, retval);

	fsroot_set_root_directory(fs, dir);
	retval = fsroot_start(fs, 1000, 1000, 0040754);
	ck_assert_msg(retval == S_OK, "fsroot_start() returned %d\n", retval);

	create_file(foo);
	release_file(foo);
	create_file(bar);
	release_file(bar);

	retval = fsroot_delete(fs, foo);
	ck_assert_msg(retval == S_OK, "fsroot_delete(\"%s\") returned %d\n",
			foo, retval);

	check_file(foo, (const struct check_file_opts *) {
		.file_type = REGULAR,
		.should_exist = 0
	});
	check_file(bar, (const struct check_file_opts *) {
		.file_type = REGULAR,
		.should_exist = 1
	});

	retval = fsroot_delete(bar);
	ck_assert_msg(retval == S_OK, "fsroot_delete(\"%s\") returned %d\n",
			bar, retval);

	check_file(foo, (const struct check_file_opts *) {
		.file_type = REGULAR,
		.should_exist = 0
	});
	check_file(bar, (const struct check_file_opts *) {
		.file_type = REGULAR,
		.should_exist = 0
	});

	fsroot_deinit();
}
END_TEST

START_TEST(test_fsroot_delete_file_in_use)
{
	int retval, err, foo_fd, bar_fd;
	char *foo = "foo", *bar = "bar";

	retval = fsroot_init(root_dir, NULL);
	ck_assert_msg(retval == S_OK, "fsroot_init(\"%s\") returned %d\n",
			root_dir, retval);

	foo_fd = create_file(foo, O_RDWR);
	bar_fd = create_file(bar, 0);

	retval = fsroot_write(foo_fd, foo_data, sizeof(foo_data) - 1, 0, &err);
	ck_assert_msg(retval == (sizeof(foo_data) - 1), "fsroot_write(\"%s\") returned %d (err: %d)\n",
			foo, get_fsroot_error_str(retval), get_errno_str(err));

	retval = fsroot_delete(foo);
	ck_assert_msg(retval == S_OK, "fsroot_delete(\"%s\") returned %s\n",
			foo, get_fsroot_error_str(retval));
	retval = fsroot_delete(bar);
	ck_assert_msg(retval == S_OK, "fsroot_delete(\"%s\") returned %s\n",
			bar, get_fsroot_error_str(retval));

	check_file(foo, {
		.file_type = REGULAR,
		.should_exist = 1,
		.contents = foo_data
	});
	check_file(bar, {
		.file_type = REGULAR,
		.should_exist = 1
	});

	release_file(foo);
	/* At this point, 'foo' should have been deleted; 'bar' should remain */
	check_file(foo, {
		.file_type = REGULAR,
		.should_exist = 0
	});
	check_file(bar, {
		.file_type = REGULAR,
		.should_exist = 1
	});

	release_file(bar);
	check_file(foo, {
		.file_type = REGULAR,
		.should_exist = 0
	});
	check_file(bar, {
		.file_type = REGULAR,
		.should_exist = 0
	});

	fsroot_deinit();
}
END_TEST
