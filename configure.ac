AC_INIT([libfsroot], [1.0], [ander.juaristi AT tecnalia.com])

AM_INIT_AUTOMAKE([gnu -Wall -Werror])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile tests/Makefile])
AC_CONFIG_MACRO_DIR([m4])

PKG_CHECK_MODULES([FUSE], [fuse])
PKG_CHECK_MODULES([CHECK], [check >= 0.9.6])

AC_PROG_CC
# This is needed for the '-std=gnu99' flag, which is also needed
AC_PROG_CC_STDC
AM_PROG_AR
# Turn on processing for libtool
AC_PROG_LIBTOOL

LT_INIT

#
# Check for Doxygen (unless docs disbled by user)
#
AC_ARG_ENABLE(doc, AS_HELP_STRING([--disable-doc], [Do not generate Doxygen docs]),
  enable_doc=$enableval, enable_doc=yes)
if test "$enable_doc" == "yes"; then
  AC_CHECK_PROGS([DOXYGEN], [doxygen])
  AS_IF([test "$DOXYGEN" == "doxygen"], [
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
echo
