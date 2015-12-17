/*
  +----------------------------------------------------------------------+
  | PHP Version 7                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 1997-2015 The PHP Group                                |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author:                                                              |
  +----------------------------------------------------------------------+
*/

/* $Id$ */

#ifndef PHP_SUHOSIN7_H
#define PHP_SUHOSIN7_H

extern zend_module_entry suhosin7_module_entry;
#define phpext_suhosin7_ptr &suhosin7_module_entry

#define SUHOSIN7_EXT_VERSION  "0.10.0"

#ifdef PHP_WIN32
#	define PHP_SUHOSIN7_API __declspec(dllexport)
#elif defined(__GNUC__) && __GNUC__ >= 4
#	define PHP_SUHOSIN7_API __attribute__ ((visibility("default")))
#else
#	define PHP_SUHOSIN7_API
#endif

#ifdef ZTS
#include "TSRM.h"
#endif

#define BYTE unsigned char       /* 8 bits  */
#define WORD unsigned int          /* 32 bits */

ZEND_BEGIN_MODULE_GLOBALS(suhosin7)
	zend_long  global_value;
	char *global_string;
	zend_bool	protectkey;

	zend_bool	simulation;
	zend_bool	already_scanned;
	zend_bool	abort_request;

/*	request variables */
	zend_long  max_request_variables;
	zend_long  cur_request_variables;
	zend_long  att_request_variables;
	zend_long  max_varname_length;
	zend_long  max_totalname_length;
	zend_long  max_value_length;
	zend_long  max_array_depth;
	zend_long  max_array_index_length;
	char* array_index_whitelist;
	char* array_index_blacklist;
	zend_bool  disallow_nul;
	zend_bool  disallow_ws;
/*	cookie variables */
	zend_long  max_cookie_vars;
	zend_long  cur_cookie_vars;
	zend_long  att_cookie_vars;
	zend_long  max_cookie_name_length;
	zend_long  max_cookie_totalname_length;
	zend_long  max_cookie_value_length;
	zend_long  max_cookie_array_depth;
	zend_long  max_cookie_array_index_length;
	zend_bool  disallow_cookie_nul;
	zend_bool  disallow_cookie_ws;
/*	get variables */
	zend_long  max_get_vars;
	zend_long  cur_get_vars;
	zend_long  att_get_vars;
	zend_long  max_get_name_length;
	zend_long  max_get_totalname_length;
	zend_long  max_get_value_length;
	zend_long  max_get_array_depth;
	zend_long  max_get_array_index_length;
	zend_bool  disallow_get_nul;
	zend_bool  disallow_get_ws;
/*	post variables */
	zend_long  max_post_vars;
	zend_long  cur_post_vars;
	zend_long  att_post_vars;
	zend_long  max_post_name_length;
	zend_long  max_post_totalname_length;
	zend_long  max_post_value_length;
	zend_long  max_post_array_depth;
	zend_long  max_post_array_index_length;
	zend_bool  disallow_post_nul;
	zend_bool  disallow_post_ws;

/*	fileupload */
	zend_long  upload_limit;
	zend_long  upload_max_newlines;
	zend_long  num_uploads;
	zend_bool  upload_disallow_elf;
	zend_bool  upload_disallow_binary;
	zend_bool  upload_remove_binary;
#ifdef SUHOSIN_EXPERIMENTAL
	zend_bool  upload_allow_utf8;
#endif
	char *upload_verification_script;
        
	zend_bool  no_more_variables;
	zend_bool  no_more_get_variables;
	zend_bool  no_more_post_variables;
	zend_bool  no_more_cookie_variables;
	zend_bool  no_more_uploads;
	
	BYTE fi[24],ri[24];
	WORD fkey[120];
	WORD rkey[120];
	
/*	memory_limit */
	zend_long	memory_limit;
	zend_long 	hard_memory_limit;

	char*	decrypted_cookie;
	char*	raw_cookie;
	zend_bool	cookie_encrypt;
	char*	cookie_cryptkey;
	zend_bool	cookie_cryptua;
	zend_bool	cookie_cryptdocroot;
	long		cookie_cryptraddr;
	long		cookie_checkraddr;
	HashTable *cookie_plainlist;
	HashTable *cookie_cryptlist;
ZEND_END_MODULE_GLOBALS(suhosin7)

/* Always refer to the globals in your function as SUHOSIN7_G(variable).
   You are encouraged to rename these macros something shorter, see
   examples in any other php module directory.
*/
#define SUHOSIN7_G(v) ZEND_MODULE_GLOBALS_ACCESSOR(suhosin7, v)

#if defined(ZTS) && defined(COMPILE_DL_SUHOSIN7)
ZEND_TSRMLS_CACHE_EXTERN();
#endif

/* Error Constants */
#ifndef S_MEMORY
#define S_MEMORY			(1<<0L)
#define S_MISC				(1<<1L)
#define S_VARS				(1<<2L)
#define S_FILES				(1<<3L)
#define S_INCLUDE			(1<<4L)
#define S_SQL				(1<<5L)
#define S_EXECUTOR			(1<<6L)
#define S_MAIL				(1<<7L)
#define S_SESSION			(1<<8L)
#define S_INTERNAL			(1<<29L)
#define S_ALL (S_MEMORY | S_VARS | S_INCLUDE | S_FILES | S_MAIL | S_SESSION | S_MISC | S_SQL | S_EXECUTOR)
#endif

#ifndef S_GETCALLER
#define S_GETCALLER         (1<<30L)
#endif

#define SUHOSIN_NORMAL	0
#define SUHOSIN_EVAL	1

#define SUHOSIN_FLAG_CREATED_BY_EVAL 1
#define SUHOSIN_FLAG_NOT_EVALED_CODE 2

ZEND_EXTERN_MODULE_GLOBALS(suhosin7)

unsigned int suhosin_input_filter(int arg, char *var, char **val, size_t val_len, size_t *new_val_len);
unsigned int suhosin_input_filter_wrapper(int arg, char *var, char **val, size_t val_len, size_t *new_val_len);
void suhosin_log(int loglevel, char *fmt, ...);
extern unsigned int (*old_input_filter)(int arg, char *var, char **val, size_t val_len, size_t *new_val_len);


#endif	/* PHP_SUHOSIN7_H */


/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
