AC_INIT([slipcat], [0.1])

AC_CONFIG_MACRO_DIRS([m4])
AC_CONFIG_SRCDIR([slipcat.c])

AM_INIT_AUTOMAKE([foreign subdir-objects])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AM_MAINTAINER_MODE

LT_INIT([dlopen])

AC_PROG_CC

PKG_CHECK_MODULES([deps], [glib-2.0],
	AC_SUBST([deps_CFLAGS])
	AC_SUBST([deps_LIBS]),
	AC_MSG_ERROR(glib-2.0 is required))

AC_SEARCH_LIBS([openpty], [util], , [AC_MSG_ERROR(util is required)])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
