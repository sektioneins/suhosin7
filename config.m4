dnl $Id$
dnl config.m4 for extension suhosin7

PHP_ARG_ENABLE(suhosin7, whether to enable suhosin support,
[  --enable-suhosin7        Enable suhosin support])

if test "$PHP_SUHOSIN7" != "no"; then
	PHP_NEW_EXTENSION(suhosin7, suhosin7.c ifilter.c memory_limit.c aes.c treat_data.c log.c execute.c execute_ih.c crypt.c cookiecrypt.c header.c, $ext_shared,, -DZEND_ENABLE_STATIC_ACHE=1)
	PHP_ADD_EXTENSION_DEP(suhosin7, hash)
fi

PHP_ARG_ENABLE(suhosin7-experimental, whether to enable experimental suhosin7 features,
[  --enable-suhosin7-experimental       Enable experimental suhosin7 features], no, no)

if test "$PHP_SUHOSIN7_EXPERIMENTAL" != "no"; then
	AC_DEFINE(SUHOSIN7_EXPERIMENTAL, 1, [Whether to enable experimental suhosin7 features])
fi
