AM_LDFLAGS = -ldl $(LDFLAGS)

if HAVE_CHECK
TESTS = test_fsroot_create test_fsroot_symlink test_fsroot_rename test_fsroot_chmod_chown \
	test_fsroot_getattr test_fsroot_mkdir test_fsroot_readdir test_fsroot_root_path \
	test_fsroot_persistence

check_PROGRAMS = test_fsroot_create test_fsroot_symlink test_fsroot_rename test_fsroot_chmod_chown \
	test_fsroot_getattr test_fsroot_mkdir test_fsroot_readdir test_fsroot_root_path \
	test_fsroot_persistence

test_fsroot_create_SOURCES = test_fsroot_create.c $(top_builddir)/linux/fsroot.h
test_fsroot_create_CFLAGS = @CHECK_CFLAGS@
test_fsroot_create_LDADD = $(top_builddir)/linux/libfsroot.la @CHECK_LIBS@

test_fsroot_symlink_SOURCES = test_fsroot_symlink.c $(top_builddir)/linux/fsroot.h
test_fsroot_symlink_CFLAGS = @CHECK_CFLAGS@
test_fsroot_symlink_LDADD = $(top_builddir)/linux/libfsroot.la @CHECK_LIBS@

test_fsroot_rename_SOURCES = test_fsroot_rename.c $(top_builddir)/linux/fsroot.h
test_fsroot_rename_CFLAGS = @CHECK_CFLAGS@
test_fsroot_rename_LDADD = $(top_builddir)/linux/libfsroot.la @CHECK_LIBS@

test_fsroot_chmod_chown_SOURCES = test_fsroot_chmod_chown.c $(top_builddir)/linux/fsroot.h
test_fsroot_chmod_chown_CFLAGS = @CHECK_CFLAGS@
test_fsroot_chmod_chown_LDADD = $(top_builddir)/linux/libfsroot.la @CHECK_LIBS@

test_fsroot_getattr_SOURCES = test_fsroot_getattr.c $(top_builddir)/linux/fsroot.h
test_fsroot_getattr_CFLAGS = @CHECK_CFLAGS@
test_fsroot_getattr_LDADD = $(top_builddir)/linux/libfsroot.la @CHECK_LIBS@

test_fsroot_mkdir_SOURCES = test_fsroot_mkdir.c $(top_builddir)/linux/fsroot.h
test_fsroot_mkdir_CFLAGS = @CHECK_CFLAGS@
test_fsroot_mkdir_LDADD = $(top_builddir)/linux/libfsroot.la @CHECK_LIBS@

test_fsroot_readdir_SOURCES = test_fsroot_readdir.c $(top_builddir)/linux/fsroot.h
test_fsroot_readdir_CFLAGS = @CHECK_CFLAGS@
test_fsroot_readdir_LDADD = $(top_builddir)/linux/libfsroot.la @CHECK_LIBS@

test_fsroot_root_path_SOURCES = test_fsroot_root_path.c $(top_builddir)/linux/fsroot.h
test_fsroot_root_path_CFLAGS = @CHECK_CFLAGS@
test_fsroot_root_path_LDADD = $(top_builddir)/linux/libfsroot.la @CHECK_LIBS@

test_fsroot_persistence_SOURCES = test_fsroot_persistence.c $(top_builddir)/linux/fsroot.h
test_fsroot_persistence_CFLAGS = @CHECK_CFLAGS@
test_fsroot_persistence_LDADD = $(top_builddir)/linux/libfsroot.la -lsqlite3 @CHECK_LIBS@
else
TESTS =
check_PROGRAMS =
endif
