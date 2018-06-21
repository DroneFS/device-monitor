# Portable across other Autotools
# This must be consistent with AC_CONFIG_MACRO_DIR, in configure.ac
ACLOCAL_AMFLAGS = -I ../m4

bin_PROGRAMS = fuse-main
fuse_main_SOURCES = fuse-main.c ../return-codes.c
fuse_main_CFLAGS = $(FUSE_CFLAGS) $(CFLAGS)
fuse_main_LDFLAGS = $(FUSE_LIBS)
fuse_main_LDADD = libfsroot.la

lib_LTLIBRARIES = libfsroot.la
libfsroot_la_SOURCES = fsroot.c fsroot.h hash.c hash.h ../mm.c ../mm.h ../list.c ../list.h \
											 fsroot-db.c fsroot-db.h ../log.c ../log.h
libfsroot_la_CFLAGS = $(CFLAGS)
libfsroot_la_LDFLAGS = -pthread -lsqlite3
libfsroot_la_LIBADD = ../chall/libchall.la

lib_LTLIBRARIES += libdch.la
libdch_la_SOURCES = dummy-challenge.c
libdch_la_CFLAGS = $(CFLAGS)

lib_LTLIBRARIES += libdch2.la
libdch2_la_SOURCES = dummy-challenge-2.c
libdch2_la_CFLAGS = $(CFLAGS)

