AC_INIT([libfsroot], [1.0], [ander.juaristi AT tecnalia.com])

AM_INIT_AUTOMAKE([gnu -Wall -Werror])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile tests/Makefile])
AC_CONFIG_MACRO_DIR([m4])

PKG_CHECK_MODULES([FUSE], [fuse])
PKG_CHECK_MODULES([CHECK], [check >= 0.9.6],
  [enable_check=yes],
  [enable_check=no])
# FIXME These are probably temporary
PKG_CHECK_MODULES([LUA], [lua-5.1 >= 5.1.5])
PKG_CHECK_MODULES([SQLITE], [sqlite3 >= 3.8])

AC_ARG_WITH([openssl],
  [AS_HELP_STRING([--with-openssl], [Use OpenSSL instead of libgcrypt])],
  [crypto_lib=openssl],
  [crypto_lib=gcrypt])
if test "$crypto_lib" == "gcrypt"; then
  AC_CHECK_LIB([gcrypt], [gcry_cipher_close],
    [libgcrypt_available=yes],
    [libgcrypt_available=no])
  if test "$libgcrypt_available" == "no"; then
    echo "ERROR: libgcrypt was not found"
    exit
  fi
else
  AC_CHECK_LIB([crypto], [EVP_aes_128_cbc],
    [openssl_available=yes],
    [openssl_available=no])
  if test "$openssl_available" == "no"; then
    echo "ERROR: libcrypto (OpenSSL) was not found"
    exit
  fi
fi

AM_CONDITIONAL([HAVE_GCRYPT], [test "$crypto_lib" == "gcrypt"])

AC_PROG_CC
# This is needed for the '-std=gnu99' flag, which is also needed
AC_PROG_CC_STDC
AM_PROG_AR
# Turn on processing for libtool
AC_PROG_LIBTOOL

LT_INIT

#
# Check for 'check'
#
AM_CONDITIONAL([HAVE_CHECK], [test "$enable_check" == "yes"])
if test "$enable_check" == "yes"; then
  TESTS="Unit tests will be compiled. You can run them with 'make check'."
else
  TESTS="Unit tests will NOT be compiled, since 'check' is not installed. 'make check' will not work."
fi

#
# Check for Doxygen (unless docs disabled by user)
#
AC_ARG_ENABLE(doc, AS_HELP_STRING([--disable-doc], [Do not generate Doxygen docs]),
  enable_doc=$enableval, enable_doc=yes)
if test "$enable_doc" == "yes"; then
  AC_CHECK_PROGS([DOXYGEN], [doxygen])
  AS_IF([test -n "$DOXYGEN"], [
    AC_CONFIG_FILES([docs/Makefile docs/device-monitor.doxy])
    AC_SUBST([DOCS_FOLDER], [docs])
    DOCS="Yes. Doxygen docs will be generated"
  ], [
    DOCS="No. Doxygen docs were requested but 'doxygen' executable was not found"
  ])
else
  DOCS="No. Doxygen docs were disabled"
fi

AC_OUTPUT

echo
echo "C compiler flags: $CFLAGS"
echo -n "Installation prefix: $prefix"
if ! test -d "$prefix"; then
  echo " (not a directory)"
else
  echo " (OK)"
fi
echo "Docs: $DOCS"
echo "Unit tests: $TESTS"
echo

