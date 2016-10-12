/*
  +----------------------------------------------------------------------+
  | Suhosin Version 1                                                    |
  +----------------------------------------------------------------------+
  | Copyright (c) 2006-2007 The Hardened-PHP Project                     |
  | Copyright (c) 2007-2016 SektionEins GmbH                             |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Authors: Stefan Esser <sesser@sektioneins.de>                        |
  |          Ben Fuhrmannek <ben.fuhrmannek@sektioneins.de>              |
  +----------------------------------------------------------------------+
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "php_suhosin7.h"
#include "SAPI.h"
#include "php_variables.h"
#include "php_content_types.h"
#include "suhosin_rfc1867.h"
#include "ext/standard/url.h"
#include "ext/standard/php_smart_string.h"

#if defined(PHP_WIN32)
#include "win32/php_inttypes.h"
#endif

SAPI_POST_HANDLER_FUNC(suhosin_rfc1867_post_handler);

static void suhosin_post_handler_modification(sapi_post_entry *spe)
{
	char *content_type = estrndup(spe->content_type, spe->content_type_len);
	suhosin_log(S_VARS, "some extension replaces the POST handler for %s - Suhosin's protection might be incomplete", content_type);
	efree(content_type);
}

// static PHP_INI_MH((*old_OnUpdate_mbstring_encoding_translation)) = NULL;
//
// /* {{{ static PHP_INI_MH(suhosin_OnUpdate_mbstring_encoding_translation) */
// static PHP_INI_MH(suhosin_OnUpdate_mbstring_encoding_translation)
// {
// 	zend_bool *p;
// #ifndef ZTS
// 	char *base = (char *) mh_arg2;
// #else
// 	char *base;
//
// 	base = (char *) ts_resource(*((int *) mh_arg2));
// #endif
//
// 	p = (zend_bool *) (base+(size_t) mh_arg1);
//
// 	if (new_value_length == 2 && strcasecmp("on", new_value) == 0) {
// 			*p = (zend_bool) 1;
// 	}
// 	else if (new_value_length == 3 && strcasecmp("yes", new_value) == 0) {
// 		*p = (zend_bool) 1;
// 	}
// 	else if (new_value_length == 4 && strcasecmp("true", new_value) == 0) {
// 		*p = (zend_bool) 1;
// 	}
// 	else {
// 		*p = (zend_bool) atoi(new_value);
// 	}
// 	if (*p) {
// 		suhosin_log(S_VARS, "Dynamic configuration (maybe a .htaccess file) tried to activate mbstring.encoding_translation which is incompatible with suhosin");
// 	}
// 	return SUCCESS;
// }
/* }}} */

/* {{{ php_post_entries[]
 */
static sapi_post_entry suhosin_post_entries[] = {
	// { DEFAULT_POST_CONTENT_TYPE, sizeof(DEFAULT_POST_CONTENT_TYPE)-1, sapi_read_standard_form_data,	suhosin_std_post_handler },
	{ ZEND_STRL(MULTIPART_CONTENT_TYPE), NULL, suhosin_rfc1867_post_handler },
	{ NULL, 0, NULL, NULL }
};
/* }}} */

void suhosin_hook_post_handlers()
{
	HashTable tempht;
	// zend_ini_entry *ini_entry;

	sapi_unregister_post_entry(&suhosin_post_entries[0]);
	// sapi_unregister_post_entry(&suhosin_post_entries[1]);
	sapi_register_post_entries(suhosin_post_entries);

	/* we want to get notified if another extension deregisters the suhosin post handlers */

	/* we need to tell suhosin patch that there is a new valid destructor */
	/* therefore we have create HashTable that has this destructor */
	// zend_hash_init(&tempht, 0, NULL, (dtor_func_t)suhosin_post_handler_modification, 0);
	// zend_hash_destroy(&tempht);
	/* And now we can overwrite the destructor for post entries */
	// SG(known_post_content_types).pDestructor = (dtor_func_t)suhosin_post_handler_modification;

	/* we have to stop mbstring from replacing our post handler */
	// if (zend_hash_find(EG(ini_directives), "mbstring.encoding_translation", sizeof("mbstring.encoding_translation"), (void **) &ini_entry) == FAILURE) {
	// 	return;
	// }
	/* replace OnUpdate_mbstring_encoding_translation handler */
	// old_OnUpdate_mbstring_encoding_translation = ini_entry->on_modify;
	// ini_entry->on_modify = suhosin_OnUpdate_mbstring_encoding_translation;
}

// void suhosin_unhook_post_handlers()
// {
// 	zend_ini_entry *ini_entry;
//
// 	/* Restore to an empty destructor */
// 	SG(known_post_content_types).pDestructor = NULL;
//
// 	/* Now restore the ini entry handler */
// 	if (zend_hash_find(EG(ini_directives), "mbstring.encoding_translation", sizeof("mbstring.encoding_translation"), (void **) &ini_entry) == FAILURE) {
// 		return;
// 	}
// 	/* replace OnUpdate_mbstring_encoding_translation handler */
// 	ini_entry->on_modify = old_OnUpdate_mbstring_encoding_translation;
// 	old_OnUpdate_mbstring_encoding_translation = NULL;
// }

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
