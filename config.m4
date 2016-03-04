dnl $Id$
dnl config.m4 for extension suhosin7

PHP_ARG_ENABLE(suhosin7, whether to enable suhosin support,
[  --enable-suhosin7        Enable suhosin support])

if test "$PHP_SUHOSIN7" != "no"; then
	PHP_NEW_EXTENSION(suhosin7, suhosin7.c ifilter.c memory_limit.c aes.c treat_data.c log.c execute.c execute_ih.c execute_rnd.c crypt.c cookiecrypt.c header.c, $ext_shared,, [-DZEND_ENABLE_STATIC_TSRMLS_CACHE=1])
	PHP_ADD_EXTENSION_DEP(suhosin7, hash)
	echo "===== WARNING ============================================"
	echo "  Suhosin7 for PHP 7 is in alpha stage at the moment and"
	echo "  not ready for production yet."
	echo "=========================================================="
fi

PHP_ARG_ENABLE(suhosin7-experimental, whether to enable experimental suhosin7 features,
[  --enable-suhosin7-experimental       Enable experimental suhosin7 features], no, no)

if test "$PHP_SUHOSIN7_EXPERIMENTAL" != "no"; then
	AC_DEFINE(SUHOSIN7_EXPERIMENTAL, 1, [Whether to enable experimental suhosin7 features])
fi

PHP_ARG_ENABLE(suhosin7-debug, whether to enable suhosin7 debugging,
[  --enable-suhosin7-debug       Enable suhosin7 debugging], no, no)

if test "$PHP_SUHOSIN7_DEBUG" != "no"; then
	AC_DEFINE(SUHOSIN7_DEBUG, 1, [Whether to enable suhosin7 debugging])
fi

AC_MSG_CHECKING([for C11 support with -std=c11])
old_CFLAGS="$CFLAGS"
CFLAGS+=" -std=c11"
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],[])],[AC_MSG_RESULT([yes])],[
	AC_MSG_RESULT([no])
	CFLAGS="$old_CFLAGS"
	echo "===== WARNING ============================================"
	echo "  Suhosin7 is written in C11, but your compiler lacks C11"
	echo "  support. Trying C99 instead, but compiling may fail."
	echo "=========================================================="
	AC_MSG_CHECKING([for C99 support with -std=c99])
	CFLAGS+=" -std=c99"
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],[])],[AC_MSG_RESULT([yes])],[
		AC_MSG_RESULT([no])
		CFLAGS="$old_CFLAGS"
	])
])
