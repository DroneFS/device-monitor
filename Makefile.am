SUBDIRS = . tests $(DOCS_FOLDER)

# Portable across other Autotools
# This must be consistent with AC_CONFIG_MACRO_DIR, in configure.ac
ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS = fuse-main
fuse_main_SOURCES = fuse-main.c
fuse_main_CFLAGS = $(FUSE_CFLAGS) $(CFLAGS)
fuse_main_LDFLAGS = $(FUSE_LIBS)
fuse_main_LDADD = libfsroot.la

lib_LTLIBRARIES = libchall.la
libchall_la_SOURCES = configuration.c configuration.h config-lua.c config-xml.c crypto-internal.h \
											crypto.c crypto.h return-codes.h list.c list.h mm.c mm.h
libchall_la_CFLAGS = $(CFLAGS)
libchall_la_LDFLAGS = -llua5.1

if HAVE_LIBXML
libchall_la_CFLAGS += -I/usr/include/libxml2
libchall_la_LDFLAGS += -lxml2
endif

if HAVE_GCRYPT
libchall_la_SOURCES += crypto-gcrypt.c
libchall_la_LDFLAGS += -lgcrypt
endif
if HAVE_OPENSSL
libchall_la_SOURCES += crypto-openssl.c
libchall_la_LDFLAGS += -lcrypto
endif

lib_LTLIBRARIES += libfsroot.la
libfsroot_la_SOURCES = fsroot.c fsroot.h hash.c hash.h mm.c mm.h list.c list.h \
											 fsroot-db.c fsroot-db.h log.c log.h
libfsroot_la_CFLAGS = $(CFLAGS)
libfsroot_la_LDFLAGS = -pthread -lsqlite3
libfsroot_la_LIBADD = libchall.la

lib_LTLIBRARIES += libdch.la
libdch_la_SOURCES = dummy-challenge.c
libdch_la_CFLAGS = $(CFLAGS)
