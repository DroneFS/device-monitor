ACLOCAL_AMFLAGS = -I ../m4

lib_LTLIBRARIES = libchall.la
libchall_la_SOURCES = configuration.c configuration.h chall.c config-lua.c config-xml.c \
	crypto-internal.h crypto-private.h \
	crypto.c crypto.h crypto-algo.c \
	formatter.h formatter-xml.c formatter-xml.h \
	base64.c base64.h \
	../return-codes.h ../list.c ../list.h ../mm.c ../mm.h
libchall_la_CFLAGS = $(CFLAGS)
libchall_la_LDFLAGS = $(LDFLAGS)

if HAVE_LIBXML
libchall_la_CFLAGS += -I/usr/include/libxml2
libchall_la_LDFLAGS += -lxml2
else
libchall_la_LDFLAGS += -llua5.1
endif

if HAVE_GCRYPT
libchall_la_SOURCES += crypto-gcrypt.c
libchall_la_LDFLAGS += -lgcrypt
endif
if HAVE_OPENSSL
libchall_la_SOURCES += crypto-openssl.c
libchall_la_LDFLAGS += -lcrypto
endif

