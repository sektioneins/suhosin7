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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "SAPI.h"
#include "php_suhosin7.h"
#include "suhosin7_logo.h"
#include "ext/standard/base64.h"
#include "ext/standard/info.h"


ZEND_DECLARE_MODULE_GLOBALS(suhosin7)

/* True global resources - no need for thread safety here */
static int le_suhosin7;

/* {{{ PHP_INI
 */
PHP_INI_BEGIN()
    STD_ZEND_INI_BOOLEAN("suhosin.protectkey",      "1", ZEND_INI_SYSTEM, OnUpdateBool, protectkey, zend_suhosin7_globals, suhosin7_globals)
	STD_ZEND_INI_BOOLEAN("suhosin.cookie.cryptkey",      "1", ZEND_INI_SYSTEM, OnUpdateBool, protectkey, zend_suhosin7_globals, suhosin7_globals)
    STD_PHP_INI_ENTRY("suhosin.global_value",      "42", PHP_INI_ALL, OnUpdateLong, global_value, zend_suhosin7_globals, suhosin7_globals)
    STD_PHP_INI_ENTRY("suhosin.global_string", "foobar", PHP_INI_ALL, OnUpdateString, global_string, zend_suhosin7_globals, suhosin7_globals)
PHP_INI_END()
/* }}} */



/* {{{ php_suhosin7_init_globals
 */
static void php_suhosin7_init_globals(zend_suhosin7_globals *suhosin7_globals)
{
	memset(suhosin7_globals, 0, sizeof(zend_suhosin7_globals));
}
/* }}} */


/* {{{ PHP_MINIT_FUNCTION
 */
PHP_MINIT_FUNCTION(suhosin7)
{
	REGISTER_INI_ENTRIES();
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION
 */
PHP_MSHUTDOWN_FUNCTION(suhosin7)
{
	UNREGISTER_INI_ENTRIES();
	return SUCCESS;
}
/* }}} */

/* Remove if there's nothing to do at request start */
/* {{{ PHP_RINIT_FUNCTION
 */
PHP_RINIT_FUNCTION(suhosin7)
{
#if defined(COMPILE_DL_SUHOSIN7) && defined(ZTS)
	ZEND_TSRMLS_CACHE_UPDATE();
#endif
	return SUCCESS;
}
/* }}} */

/* Remove if there's nothing to do at request end */
/* {{{ PHP_RSHUTDOWN_FUNCTION
 */
PHP_RSHUTDOWN_FUNCTION(suhosin7)
{
	return SUCCESS;
}
/* }}} */

/* {{{ suhosin_ini_displayer(zend_ini_entry *ini_entry, int type)
 */
static void suhosin_ini_displayer(zend_ini_entry *ini_entry, int type)
{
    PHPWRITE("[ protected ]", strlen("[ protected ]"));
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(suhosin7)
{
	php_info_print_box_start(0);
	if (!sapi_module.phpinfo_as_text) {
		do {
			zend_string *enc_logo;
			
			PUTS("<a href=\"http://www.suhosin.org/\"><img border=\"0\" src=\"data:image/jpeg;base64,");
			enc_logo = php_base64_encode(suhosin_logo, sizeof(suhosin_logo));
			if (ZSTR_LEN(enc_logo)) {
				PHPWRITE(ZSTR_VAL(enc_logo), ZSTR_LEN(enc_logo));
			}
			zend_string_free(enc_logo);
			PUTS("\" alt=\"Suhosin logo\" /></a>\n");
		} while(0);
	}
	PUTS("This server is protected with the Suhosin Extension " SUHOSIN7_EXT_VERSION);
	PUTS(!sapi_module.phpinfo_as_text?"<br /><br />":"\n\n");
	if (sapi_module.phpinfo_as_text) {
		PUTS("Copyright (c) 2006-2007 Hardened-PHP Project\n");
		PUTS("Copyright (c) 2007-2015 SektionEins GmbH\n");
	} else {
		PUTS("Copyright (c) 2006-2007 <a href=\"http://www.hardened-php.net/\">Hardened-PHP Project</a><br />\n");
		PUTS("Copyright (c) 2007-2015 <a href=\"http://www.sektioneins.de/\">SektionEins GmbH</a>\n");
	}
	php_info_print_box_end();

    if (SUHOSIN7_G(protectkey)) {
        zend_ini_entry *i;

		if ((i=zend_hash_str_find_ptr(EG(ini_directives), "suhosin.cookie.cryptkey", sizeof("suhosin.cookie.cryptkey")-1))) {
            i->displayer = suhosin_ini_displayer;
        }
		if ((i=zend_hash_str_find_ptr(EG(ini_directives), "suhosin.session.cryptkey", sizeof("suhosin.session.cryptkey")-1))) {
            i->displayer = suhosin_ini_displayer;
        }
		if ((i=zend_hash_str_find_ptr(EG(ini_directives), "suhosin.rand.seedingkey", sizeof("suhosin.rand.seedingkey")-1))) {
            i->displayer = suhosin_ini_displayer;
        }
    }
    
	DISPLAY_INI_ENTRIES();

    if (SUHOSIN7_G(protectkey)) {
        zend_ini_entry *i;
		
		if ((i=zend_hash_str_find_ptr(EG(ini_directives), "suhosin.cookie.cryptkey", sizeof("suhosin.cookie.cryptkey")))) {
            i->displayer = NULL;
        }
		if ((i=zend_hash_str_find_ptr(EG(ini_directives), "suhosin.session.cryptkey", sizeof("suhosin.session.cryptkey")-1))) {
            i->displayer = NULL;
        }
		if ((i=zend_hash_str_find_ptr(EG(ini_directives), "suhosin.rand.seedingkey", sizeof("suhosin.rand.seedingkey")-1))) {
            i->displayer = NULL;
        }
    }

}
/* }}} */

/* {{{ suhosin7_functions[]
 *
 * Every user visible function must have an entry in suhosin7_functions[].
 */
const zend_function_entry suhosin7_functions[] = {
//	PHP_FE(confirm_suhosin7_compiled,	NULL)		/* For testing, remove later. */
	PHP_FE_END
};
/* }}} */

/* {{{ suhosin7_module_entry
 */
zend_module_entry suhosin7_module_entry = {
	STANDARD_MODULE_HEADER,
	"suhosin7",
	suhosin7_functions,
	PHP_MINIT(suhosin7),
	PHP_MSHUTDOWN(suhosin7),
	PHP_RINIT(suhosin7),		/* Replace with NULL if there's nothing to do at request start */
	PHP_RSHUTDOWN(suhosin7),	/* Replace with NULL if there's nothing to do at request end */
	PHP_MINFO(suhosin7),
	SUHOSIN7_EXT_VERSION,
	STANDARD_MODULE_PROPERTIES
};
/* }}} */

#ifdef COMPILE_DL_SUHOSIN7
#ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE();
#endif
ZEND_GET_MODULE(suhosin7)
#endif

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
