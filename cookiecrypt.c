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
/*
  $Id: header.c,v 1.1.1.1 2007-11-28 01:15:35 sesser Exp $ 
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "ext/standard/url.h"
#include "php_suhosin7.h"
#include "php_variables.h"


zend_string *suhosin_encrypt_single_cookie(char *name, int name_len, char *value, int value_len, char *key)
{
	int l;

	name = estrndup(name, name_len);	
	name_len = php_url_decode(name, name_len);
	suhosin_normalize_varname(name);
	name_len = strlen(name);
	
	if ((SUHOSIN7_G(cookie_plainlist) && zend_hash_str_exists(SUHOSIN7_G(cookie_plainlist), name, name_len)) ||
		(SUHOSIN7_G(cookie_plainlist) == NULL && SUHOSIN7_G(cookie_cryptlist) && !zend_hash_str_exists(SUHOSIN7_G(cookie_cryptlist), name, name_len))) {
		efree(name);
		return zend_string_init(value, value_len, 0);
	}

	value = estrndup(value, value_len);
	value_len = php_url_decode(value, value_len);
	
	zend_string *d = suhosin_encrypt_string(value, value_len, name, name_len, key);
	zend_string *d_url = php_url_encode(ZSTR_VAL(d), ZSTR_LEN(d));
	zend_string_release(d);
	efree(name);
	efree(value);
	return d_url;
}

char *suhosin_decrypt_single_cookie(char *name, int name_len, char *value, int value_len, char *key, char **out)
{
	char *name2 = estrndup(name, name_len);
	int name2_len = php_url_decode(name2, name_len);
	suhosin_normalize_varname(name2);
	name2_len = strlen(name2);
	
	if ((SUHOSIN7_G(cookie_plainlist) && zend_hash_str_exists(SUHOSIN7_G(cookie_plainlist), name2, name2_len)) ||
		(SUHOSIN7_G(cookie_plainlist) == NULL && SUHOSIN7_G(cookie_cryptlist) && !zend_hash_str_exists(SUHOSIN7_G(cookie_cryptlist), name2, name2_len))) {
	// if (1) {
		efree(name2);
		memcpy(*out, name, name_len);
		*out += name_len;
		**out = '='; *out +=1;
		memcpy(*out, value, value_len);
		*out += value_len;
		return *out;
	}
	
	value = estrndup(value, value_len);
	value_len = php_url_decode(value, value_len);
	
	zend_string *d = suhosin_decrypt_string(value, value_len, name2, name2_len, key, SUHOSIN7_G(cookie_checkraddr));
	if (d) {
		zend_string *d_url = php_url_encode(ZSTR_VAL(d), ZSTR_LEN(d));
		zend_string_release(d);
		memcpy(*out, name, name_len);
		*out += name_len;
		**out = '='; *out += 1;
		memcpy(*out, ZSTR_VAL(d_url), ZSTR_LEN(d_url));
		*out += ZSTR_LEN(d_url);
		zend_string_release(d_url);
	}

	efree(name2);
	efree(value);
	
	return *out;
}

/* {{{ suhosin_cookie_decryptor
 */
char *suhosin_cookie_decryptor(char *raw_cookie)
{
	// SDEBUG("raw cookie: %s", raw_cookie);
	char *decrypted, *ret;
	// int j;
	char cryptkey[33];

	// suhosin_generate_key(SUHOSIN7_G(cookie_cryptkey), SUHOSIN7_G(cookie_cryptua), SUHOSIN7_G(cookie_cryptdocroot), SUHOSIN7_G(cookie_cryptraddr), cryptkey);
	S7_GENERATE_KEY(cookie, cryptkey);
	// SDEBUG("cryptkey=%02x.%02x.%02x", cryptkey[0], cryptkey[1], cryptkey[2]);
	
	ret = decrypted = emalloc(strlen(raw_cookie)*4+1);
	raw_cookie = estrdup(raw_cookie);
	SUHOSIN7_G(raw_cookie) = estrdup(raw_cookie);

	char *strtok_buf = NULL;
	char *var, *val;
	const char *separator = ";\0";
	for (char *var = php_strtok_r(raw_cookie, separator, &strtok_buf); var; var = php_strtok_r(NULL, separator, &strtok_buf)) {
		val = strchr(var, '=');
		while (isspace(*var)) { var++; }
		if (var == val || *var == '\0') { continue; }
		if (val) {
			*val++ = '\0';
			// size_t var_len = php_url_decode(var, strlen(var));
			size_t var_len = strlen(var);
			// size_t val_len = php_url_decode(val, strlen(val));
			size_t val_len = strlen(val);
			SDEBUG("decrypting cookie |%s|%s|", var, val);
			suhosin_decrypt_single_cookie(var, var_len, val, val_len, cryptkey, &decrypted);
			SDEBUG("ret is now %s", ret);
			*decrypted++ = ';';
		} else {
			// ??
		}
	}

	*decrypted++ = 0;
	ret = erealloc(ret, decrypted-ret);
	
	SUHOSIN7_G(decrypted_cookie) = ret;
	efree(raw_cookie);
		
	return ret;
}
/* }}} */
