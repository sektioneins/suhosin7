dnl $Id$
dnl config.m4 for extension suhosin7

PHP_ARG_ENABLE(suhosin, whether to enable suhosin support,
[  --enable-suhosin        Enable suhosin support])

if test "$PHP_SUHOSIN" != "no"; then
  PHP_NEW_EXTENSION(suhosin7, suhosin7.c aes.c ifilter.c memory_limit.c sha256.c treat_data.c log.c execute.c, $ext_shared,, -DZEND_ENABLE_STATIC_ACHE=1)
fi

PHP_ARG_ENABLE(suhosin7-experimental, whether to enable experimental suhosin7 features,
[  --enable-suhosin7-experimental       Enable experimental suhosin7 features], no, no)

if test "$PHP_SUHOSIN7_EXPERIMENTAL" != "no"; then
  AC_DEFINE(SUHOSIN7_EXPERIMENTAL, 1, [Whether to enable experimental suhosin7 features])
fi
