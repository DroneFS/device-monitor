SUBDIRS = . tests $(DOCS_FOLDER)

# Portable across other Autotools
# This must be consistent with AC_CONFIG_MACRO_DIR, in configure.ac
ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS = fuse-main
fuse_main_SOURCES = fuse-main.c
fuse_main_CFLAGS = $(FUSE_CFLAGS) $(CFLAGS)
fuse_main_LDFLAGS = $(FUSE_LIBS)
fuse_main_LDADD = libfsroot.la
# fuse_main_LDADD = libfsroot
# fuse_main_LDFLAGS = $(pkg-config --cflags --libs fuse)

lib_LTLIBRARIES = libfsroot.la
libfsroot_la_SOURCES = fsroot.c hash.c mm.c fsroot-path.c fsroot-crypto.c fsroot-db.c fsroot-config.c
libfsroot_la_CFLAGS = $(CFLAGS)
libfsroot_la_LDFLAGS = -pthread -lsqlite3 -lgcrypt -llua5.1

lib_LTLIBRARIES += libdch.la
libdch_la_SOURCES = dummy-challenge.c
libdch_la_CFLAGS = $(CFLAGS)
