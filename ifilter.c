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
  $Id: ifilter.c,v 1.1.1.1 2007-11-28 01:15:35 sesser Exp $ 
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "php_suhosin7.h"
#include "php_variables.h"
#include "ext/standard/php_var.h"

static void (*orig_register_server_variables)(zval *track_vars_array) = NULL;

#if !HAVE_STRNLEN
static size_t strnlen(const char *s, size_t maxlen) {
	char *r = memchr(s, '\0', maxlen);
	return r ? r-s : maxlen;
}
#endif

size_t suhosin_strnspn(const char *input, size_t n, const char *accept)
{
	size_t count = 0;
	for (; *input != '\0' && count < n; input++, count++) {
		if (strchr(accept, *input) == NULL)
			break;
	}
	return count;
}

size_t suhosin_strncspn(const char *input, size_t n, const char *reject)
{
	size_t count = 0;
	for (; *input != '\0' && count < n; input++, count++) {
		if (strchr(reject, *input) != NULL)
			break;
	}
	return count;
}


/* {{{ normalize_varname
 */
void normalize_varname(char *varname)
{
	char *s=varname, *index=NULL, *indexend=NULL, *p;
	
	/* overjump leading space */
	while (*s == ' ') {
		s++;
	}
	
	/* and remove it */
	if (s != varname) {
		memmove(varname, s, strlen(s)+1);
	}

	for (p=varname; *p && *p != '['; p++) {
		switch(*p) {
			case ' ':
			case '.':
				*p='_';
				break;
		}
	}

	/* find index */
	index = strchr(varname, '[');
	if (index) {
		index++;
		s=index;
	} else {
		return;
	}

	/* done? */
	while (index) {

		while (*index == ' ' || *index == '\r' || *index == '\n' || *index=='\t') {
			index++;
		}
		indexend = strchr(index, ']');
		indexend = indexend ? indexend + 1 : index + strlen(index);
		
		if (s != index) {
			memmove(s, index, strlen(index)+1);
			s += indexend-index;
		} else {
			s = indexend;
		}

		if (*s == '[') {
			s++;
			index = s;
		} else {
			index = NULL;
		}	
	}
	*s++='\0';
}
/* }}} */

static unsigned char suhosin_hexchars[] = "0123456789ABCDEF";

static const char suhosin_is_dangerous_char[256] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/* {{{ suhosin_server_encode
 */
static void suhosin_server_strip(HashTable *arr, char *key, int klen)
{
	zval *zv;
	unsigned char *t;

	if ((zv = zend_hash_str_find(arr, key, klen)) == NULL ||
			Z_TYPE_P(zv) != IS_STRING) {
		return;
	}
		
	t = (unsigned char *)Z_STRVAL_P(zv);
	// SDEBUG()
	for (; *t; t++) {
		if (suhosin_is_dangerous_char[*t]) {
			*t = '?';
		}
	}
	zend_string_forget_hash_val(Z_STR_P(zv));
}
/* }}} */

/* {{{ suhosin_server_encode
 */
static void suhosin_server_encode(HashTable *arr, char *key, int klen)
{
	zval *zv;
	int extra = 0;

	if ((zv = zend_hash_str_find(arr, key, klen)) == NULL ||
			Z_TYPE_P(zv) != IS_STRING) {
		return;
	}
		
	unsigned char *orig = (unsigned char *)Z_STRVAL_P(zv);
	unsigned char *t;
	for (t = orig; *t; t++) {
		if (suhosin_is_dangerous_char[*t]) {
			extra += 2;
		}
	}
	
	/* no extra bytes required */
	if (extra == 0) {
		return;
	}
	
	size_t dest_len = t - orig + 1 + extra;
	unsigned char dest[dest_len];
	unsigned char *n = dest;
	for (t = orig; *t; t++, n++) {
		if (suhosin_is_dangerous_char[*t]) {
			*n++ = '%';
			*n++ = suhosin_hexchars[*t >> 4];
			*n = suhosin_hexchars[*t & 15];
		} else {
			*n = *t;
		}
	}
	*n = 0;

	zend_string *zs = zend_string_extend(Z_STR_P(zv), dest_len, 0);
	memcpy(ZSTR_VAL(zs), dest, dest_len);
	ZSTR_LEN(zs) = dest_len-1;
	zend_string_forget_hash_val(zs);
	Z_STR_P(zv) = zs;
}
/* }}} */

/* {{{ suhosin_register_server_variables
 */
void suhosin_register_server_variables(zval *track_vars_array)
{
	HashTable *svars;
	int retval = 0, failure = 0;

	orig_register_server_variables(track_vars_array);

	svars = Z_ARRVAL_P(track_vars_array);
	if (!SUHOSIN7_G(simulation)) {
		retval = zend_hash_str_del(svars, ZEND_STRL("HTTP_GET_VARS"));
		if (retval == SUCCESS) failure = 1;
		retval = zend_hash_str_del(svars, ZEND_STRL("HTTP_POST_VARS"));
		if (retval == SUCCESS) failure = 1;
		retval = zend_hash_str_del(svars, ZEND_STRL("HTTP_COOKIE_VARS"));
		if (retval == SUCCESS) failure = 1;
		retval = zend_hash_str_del(svars, ZEND_STRL("HTTP_ENV_VARS"));
		if (retval == SUCCESS) failure = 1;
		retval = zend_hash_str_del(svars, ZEND_STRL("HTTP_SERVER_VARS"));
		if (retval == SUCCESS) failure = 1;
		retval = zend_hash_str_del(svars, ZEND_STRL("HTTP_SESSION_VARS"));
		if (retval == SUCCESS) failure = 1;
		retval = zend_hash_str_del(svars, ZEND_STRL("HTTP_POST_FILES"));
		if (retval == SUCCESS) failure = 1;
		retval = zend_hash_str_del(svars, ZEND_STRL("HTTP_RAW_POST_DATA"));
		if (retval == SUCCESS) failure = 1;
	} else {
		retval = zend_hash_str_exists(svars, ZEND_STRL("HTTP_GET_VARS"));
		retval+= zend_hash_str_exists(svars, ZEND_STRL("HTTP_POST_VARS"));
		retval+= zend_hash_str_exists(svars, ZEND_STRL("HTTP_COOKIE_VARS"));
		retval+= zend_hash_str_exists(svars, ZEND_STRL("HTTP_ENV_VARS"));
		retval+= zend_hash_str_exists(svars, ZEND_STRL("HTTP_SERVER_VARS"));
		retval+= zend_hash_str_exists(svars, ZEND_STRL("HTTP_SESSION_VARS"));
		retval+= zend_hash_str_exists(svars, ZEND_STRL("HTTP_POST_FILES"));
		retval+= zend_hash_str_exists(svars, ZEND_STRL("HTTP_RAW_POST_DATA"));
		if (retval > 0) failure = 1;
	}

	if (failure) {
		suhosin_log(S_VARS, "Attacker tried to overwrite a superglobal through a HTTP header");
	}
	
	if (SUHOSIN7_G(raw_cookie)) {
		zval z;
		ZVAL_STRING(&z, SUHOSIN7_G(raw_cookie));
		zend_hash_str_add(svars, "RAW_HTTP_COOKIE", sizeof("RAW_HTTP_COOKIE")-1, &z);
	}
	if (SUHOSIN7_G(decrypted_cookie)) {
		zval z;
		ZVAL_STRING(&z, SUHOSIN7_G(decrypted_cookie));
		zend_hash_str_update(svars, "HTTP_COOKIE", sizeof("HTTP_COOKIE")-1, &z);
		SUHOSIN7_G(decrypted_cookie) = NULL;
	}
	
	if (SUHOSIN7_G(server_encode)) {
		/* suhosin_server_encode(svars, ZEND_STRL("argv")); */
		suhosin_server_encode(svars, ZEND_STRL("REQUEST_URI"));
		suhosin_server_encode(svars, ZEND_STRL("QUERY_STRING"));
	}
	if (SUHOSIN7_G(server_strip)) {
		suhosin_server_strip(svars, ZEND_STRL("PHP_SELF"));
		suhosin_server_strip(svars, ZEND_STRL("PATH_INFO"));
		suhosin_server_strip(svars, ZEND_STRL("PATH_TRANSLATED"));
		suhosin_server_strip(svars, ZEND_STRL("HTTP_USER_AGENT"));
	}
}
/* }}} */


/* Old Input filter */
// unsigned int (*old_input_filter)(int arg, char *var, char **val, unsigned int val_len, unsigned int *new_val_len) = NULL;
unsigned int (*old_input_filter)(int arg, char *var, char **val, size_t val_len, size_t *new_val_len);

/* {{{ suhosin_input_filter_wrapper
 */
unsigned int suhosin_input_filter_wrapper(int arg, char *var, char **val, size_t val_len, size_t *new_val_len)
{
	// zend_bool already_scanned = SUHOSIN7_G(already_scanned);
	// SUHOSIN7_G(already_scanned) = 0;
	// SDEBUG("ifilter arg=%d var=%s do_not_scan=%d already_scanned=%d", arg, var, SUHOSIN7_G(do_not_scan), already_scanned);
	// SDEBUG("ifilter arg=%d var=%s do_not_scan=%d", arg, var, SUHOSIN7_G(do_not_scan));
	SDEBUG("ifilter arg=%d var=%s", arg, var);
	
	// if (SUHOSIN7_G(do_not_scan)) {
	// 	SDEBUG("do_not_scan");
	// 	if (new_val_len) {
	// 		*new_val_len = val_len;
	// 	}
	// 	return 1;
	// }
	
	// if (!already_scanned) {
		if (suhosin_input_filter(arg, var, val, val_len, new_val_len)==0) {
			SUHOSIN7_G(abort_request)=1;
			return 0;
		}
		if (new_val_len) {
			val_len = *new_val_len;
		}
	// }
	if (old_input_filter) {
		return old_input_filter(arg, var, val, val_len, new_val_len);
	} else {
		return 1;
	}
}

/* {{{ suhosin_input_filter
 */
unsigned int suhosin_input_filter(int arg, char *var, char **val, size_t val_len, size_t *new_val_len)
{
	SDEBUG("%s=%s arg=%d", var, *val, arg);
	char *index, *prev_index = NULL;
	unsigned int var_len, total_len, depth = 0;

	/* Mark that we were called */
	// SUHOSIN7_G(already_scanned) = 1;

	if (new_val_len) {
		*new_val_len = 0;
	}

	/* Drop this variable if the limit was reached */
	switch (arg) {
		case PARSE_GET:
			SUHOSIN7_G(att_get_vars)++;
			SUHOSIN7_G(att_request_variables)++;
			if (SUHOSIN7_G(no_more_get_variables)) {
				return 0;
			}
			break;
		case PARSE_POST:
			SUHOSIN7_G(att_post_vars)++;
			SUHOSIN7_G(att_request_variables)++;
			if (SUHOSIN7_G(no_more_post_variables)) {
				return 0;
			}
			break;
		case PARSE_COOKIE:
			SUHOSIN7_G(att_cookie_vars)++;
			SUHOSIN7_G(att_request_variables)++;
			if (SUHOSIN7_G(no_more_cookie_variables)) {
				return 0;
			}
			break;
		default:	/* we do not want to protect parse_str() and friends */
			if (new_val_len) {
				*new_val_len = val_len;
			}
			return 1;
		}
		
	/* Drop this variable if the limit is now reached */
	switch (arg) {
		case PARSE_GET:
			if (SUHOSIN7_G(max_get_vars) && SUHOSIN7_G(max_get_vars) <= SUHOSIN7_G(cur_get_vars)) {
				suhosin_log(S_VARS, "configured GET variable limit exceeded - dropped variable '%s' - all further GET variables are dropped", var);
				if (!SUHOSIN7_G(simulation)) {
					SUHOSIN7_G(no_more_get_variables) = 1;
					return 0;
				}
			}
			break;
		case PARSE_COOKIE:
			if (SUHOSIN7_G(max_cookie_vars) && SUHOSIN7_G(max_cookie_vars) <= SUHOSIN7_G(cur_cookie_vars)) {
				suhosin_log(S_VARS, "configured COOKIE variable limit exceeded - dropped variable '%s' - all further COOKIE variables are dropped", var);
				if (!SUHOSIN7_G(simulation)) {
					SUHOSIN7_G(no_more_cookie_variables) = 1;
					return 0;
				}
			}
			break;
		case PARSE_POST:
			if (SUHOSIN7_G(max_post_vars) && SUHOSIN7_G(max_post_vars) <= SUHOSIN7_G(cur_post_vars)) {
				suhosin_log(S_VARS, "configured POST variable limit exceeded - dropped variable '%s' - all further POST variables are dropped", var);
				if (!SUHOSIN7_G(simulation)) {
					SUHOSIN7_G(no_more_post_variables) = 1;
					return 0;
				}
			}
			break;
	}
	
	/* Drop this variable if it begins with whitespace which is disallowed */
	// SDEBUG("checking '%c'", *var);
	if (isspace(*var)) {
		SDEBUG("is WS");
		if (SUHOSIN7_G(disallow_ws)) {
			suhosin_log(S_VARS, "request variable name begins with disallowed whitespace - dropped variable '%s'", var);
			if (!SUHOSIN7_G(simulation)) { return 0; }
		}
		switch (arg) {
			case PARSE_GET:
				if (SUHOSIN7_G(disallow_get_ws)) {
					suhosin_log(S_VARS, "GET variable name begins with disallowed whitespace - dropped variable '%s'", var);
					if (!SUHOSIN7_G(simulation)) { return 0; }
				}
				break;
			case PARSE_POST:
				if (SUHOSIN7_G(disallow_post_ws)) {
					suhosin_log(S_VARS, "POST variable name begins with disallowed whitespace - dropped variable '%s'", var);
					if (!SUHOSIN7_G(simulation)) { return 0; }
				}
				break;
			case PARSE_COOKIE:
				if (SUHOSIN7_G(disallow_cookie_ws)) {
					suhosin_log(S_VARS, "COOKIE variable name begins with disallowed whitespace - dropped variable '%s'", var);
					if (!SUHOSIN7_G(simulation)) { return 0; }
				}
				break;
		}
	}
	// else { SDEBUG("not WS");}
	
	/* Drop this variable if it exceeds the value length limit */
	if (SUHOSIN7_G(max_value_length) && SUHOSIN7_G(max_value_length) < val_len) {
		suhosin_log(S_VARS, "configured request variable value length limit exceeded - dropped variable '%s'", var);
		if (!SUHOSIN7_G(simulation)) { return 0; }
	}
	switch (arg) {
		case PARSE_GET:
			if (SUHOSIN7_G(max_get_value_length) && SUHOSIN7_G(max_get_value_length) < val_len) {
				suhosin_log(S_VARS, "configured GET variable value length limit exceeded - dropped variable '%s'", var);
				if (!SUHOSIN7_G(simulation)) { return 0; }
			}
			break;
		case PARSE_COOKIE:
			if (SUHOSIN7_G(max_cookie_value_length) && SUHOSIN7_G(max_cookie_value_length) < val_len) {
				suhosin_log(S_VARS, "configured COOKIE variable value length limit exceeded - dropped variable '%s'", var);
				if (!SUHOSIN7_G(simulation)) { return 0; }
			}
			break;
		case PARSE_POST:
			if (SUHOSIN7_G(max_post_value_length) && SUHOSIN7_G(max_post_value_length) < val_len) {
				suhosin_log(S_VARS, "configured POST variable value length limit exceeded - dropped variable '%s'", var);
				if (!SUHOSIN7_G(simulation)) { return 0; }
			}
			break;
	}
	
	/* Normalize the variable name */
	normalize_varname(var);
	
	/* Find length of variable name */
	index = strchr(var, '[');
	total_len = strlen(var);
	var_len = index ? index-var : total_len;
	
	/* Drop this variable if it exceeds the varname/total length limit */
	if (SUHOSIN7_G(max_varname_length) && SUHOSIN7_G(max_varname_length) < var_len) {
		suhosin_log(S_VARS, "configured request variable name length limit exceeded - dropped variable '%s'", var);
		if (!SUHOSIN7_G(simulation)) { return 0; }
	}
	if (SUHOSIN7_G(max_totalname_length) && SUHOSIN7_G(max_totalname_length) < total_len) {
		suhosin_log(S_VARS, "configured request variable total name length limit exceeded - dropped variable '%s'", var);
		if (!SUHOSIN7_G(simulation)) { return 0; }
	}
	switch (arg) {
		case PARSE_GET:
			if (SUHOSIN7_G(max_get_name_length) && SUHOSIN7_G(max_get_name_length) < var_len) {
				suhosin_log(S_VARS, "configured GET variable name length limit exceeded - dropped variable '%s'", var);
				if (!SUHOSIN7_G(simulation)) { return 0; }
			}
			if (SUHOSIN7_G(max_get_totalname_length) && SUHOSIN7_G(max_get_totalname_length) < total_len) {
				suhosin_log(S_VARS, "configured GET variable total name length limit exceeded - dropped variable '%s'", var);
				if (!SUHOSIN7_G(simulation)) { return 0; }
			}
			break;
		case PARSE_COOKIE:
			if (SUHOSIN7_G(max_cookie_name_length) && SUHOSIN7_G(max_cookie_name_length) < var_len) {
				suhosin_log(S_VARS, "configured COOKIE variable name length limit exceeded - dropped variable '%s'", var);
				if (!SUHOSIN7_G(simulation)) { return 0; }
			}
			if (SUHOSIN7_G(max_cookie_totalname_length) && SUHOSIN7_G(max_cookie_totalname_length) < total_len) {
				suhosin_log(S_VARS, "configured COOKIE variable total name length limit exceeded - dropped variable '%s'", var);
				if (!SUHOSIN7_G(simulation)) { return 0; }
			}
			break;
		case PARSE_POST:
			if (SUHOSIN7_G(max_post_name_length) && SUHOSIN7_G(max_post_name_length) < var_len) {
				suhosin_log(S_VARS, "configured POST variable name length limit exceeded - dropped variable '%s'", var);
				if (!SUHOSIN7_G(simulation)) { return 0; }
			}
			if (SUHOSIN7_G(max_post_totalname_length) && SUHOSIN7_G(max_post_totalname_length) < total_len) {
				suhosin_log(S_VARS, "configured POST variable total name length limit exceeded - dropped variable '%s'", var);
				if (!SUHOSIN7_G(simulation)) { return 0; }
			}
			break;
	}
	
	/* Find out array depth */
	while (index) {
		char *index_end;
		unsigned int index_length;
		
		/* overjump '[' */
		index++;
		
		/* increase array depth */
		depth++;
				
		index_end = strchr(index, ']');
		if (index_end == NULL) {
			index_end = index+strlen(index);
		}
		
		index_length = index_end - index;
		
		/* max. array index length */
		if (SUHOSIN7_G(max_array_index_length) && SUHOSIN7_G(max_array_index_length) < index_length) {
			suhosin_log(S_VARS, "configured request variable array index length limit exceeded - dropped variable '%s'", var);
			if (!SUHOSIN7_G(simulation)) { return 0; }
		} 
		switch (arg) {
			case PARSE_GET:
				if (SUHOSIN7_G(max_get_array_index_length) && SUHOSIN7_G(max_get_array_index_length) < index_length) {
					suhosin_log(S_VARS, "configured GET variable array index length limit exceeded - dropped variable '%s'", var);
					if (!SUHOSIN7_G(simulation)) { return 0; }
				} 
				break;
			case PARSE_COOKIE:
				if (SUHOSIN7_G(max_cookie_array_index_length) && SUHOSIN7_G(max_cookie_array_index_length) < index_length) {
					suhosin_log(S_VARS, "configured COOKIE variable array index length limit exceeded - dropped variable '%s'", var);
					if (!SUHOSIN7_G(simulation)) { return 0; }
				} 
				break;
			case PARSE_POST:
				if (SUHOSIN7_G(max_post_array_index_length) && SUHOSIN7_G(max_post_array_index_length) < index_length) {
					suhosin_log(S_VARS, "configured POST variable array index length limit exceeded - dropped variable '%s'", var);
					if (!SUHOSIN7_G(simulation)) { return 0; }
				} 
				break;
		}
		
		/* index whitelist/blacklist */
		if (SUHOSIN7_G(array_index_whitelist) && *(SUHOSIN7_G(array_index_whitelist))) {
			if (suhosin_strnspn(index, index_length, SUHOSIN7_G(array_index_whitelist)) != index_length) {
				suhosin_log(S_VARS, "array index contains not whitelisted characters - dropped variable '%s'", var);
				if (!SUHOSIN7_G(simulation)) { return 0; }
			}
		} else if (SUHOSIN7_G(array_index_blacklist) && *(SUHOSIN7_G(array_index_blacklist))) {
			if (suhosin_strncspn(index, index_length, SUHOSIN7_G(array_index_blacklist)) != index_length) {
				suhosin_log(S_VARS, "array index contains blacklisted characters - dropped variable '%s'", var);
				if (!SUHOSIN7_G(simulation)) { return 0; }
			}
		}
		
		index = strchr(index, '[');
	}
	
	/* Drop this variable if it exceeds the array depth limit */
	if (SUHOSIN7_G(max_array_depth) && SUHOSIN7_G(max_array_depth) < depth) {
		suhosin_log(S_VARS, "configured request variable array depth limit exceeded - dropped variable '%s'", var);
		if (!SUHOSIN7_G(simulation)) { return 0; }
	}
	switch (arg) {
		case PARSE_GET:
			if (SUHOSIN7_G(max_get_array_depth) && SUHOSIN7_G(max_get_array_depth) < depth) {
				suhosin_log(S_VARS, "configured GET variable array depth limit exceeded - dropped variable '%s'", var);
				if (!SUHOSIN7_G(simulation)) { return 0; }
			}
			break;
		case PARSE_COOKIE:
			if (SUHOSIN7_G(max_cookie_array_depth) && SUHOSIN7_G(max_cookie_array_depth) < depth) {
				suhosin_log(S_VARS, "configured COOKIE variable array depth limit exceeded - dropped variable '%s'", var);
				if (!SUHOSIN7_G(simulation)) { return 0; }
			}
			break;
		case PARSE_POST:
			if (SUHOSIN7_G(max_post_array_depth) && SUHOSIN7_G(max_post_array_depth) < depth) {
				suhosin_log(S_VARS, "configured POST variable array depth limit exceeded - dropped variable '%s'", var);
				if (!SUHOSIN7_G(simulation)) { return 0; }
			}
			break;
	}

	/* Check if variable value is truncated by a \0 */
	
	if (val && *val && val_len != strnlen(*val, val_len)) {
	
		if (SUHOSIN7_G(disallow_nul)) {
			suhosin_log(S_VARS, "ASCII-NUL chars not allowed within request variables - dropped variable '%s'", var);
			if (!SUHOSIN7_G(simulation)) { return 0; }
		}
		switch (arg) {
			case PARSE_GET:
				if (SUHOSIN7_G(disallow_get_nul)) {
					suhosin_log(S_VARS, "ASCII-NUL chars not allowed within GET variables - dropped variable '%s'", var);
					if (!SUHOSIN7_G(simulation)) { return 0; }
				}
				break;
			case PARSE_COOKIE:
				if (SUHOSIN7_G(disallow_cookie_nul)) {
					suhosin_log(S_VARS, "ASCII-NUL chars not allowed within COOKIE variables - dropped variable '%s'", var);
					if (!SUHOSIN7_G(simulation)) { return 0; }
				}
				break;
			case PARSE_POST:
				if (SUHOSIN7_G(disallow_post_nul)) {
					suhosin_log(S_VARS, "ASCII-NUL chars not allowed within POST variables - dropped variable '%s'", var);
					if (!SUHOSIN7_G(simulation)) { return 0; }
				}
				break;
		}
	}
	
	/* Drop this variable if it is one of GLOBALS, _GET, _POST, ... */
	/* This is to protect several silly scripts that do globalizing themself */
	if (suhosin_is_protected_varname(var, var_len)) {
		suhosin_log(S_VARS, "tried to register forbidden variable '%s' through %s variables", var, arg == PARSE_GET ? "GET" : arg == PARSE_POST ? "POST" : "COOKIE");
		if (!SUHOSIN7_G(simulation)) { return 0; }
	}

	/* Okay let PHP register this variable */
	SUHOSIN7_G(cur_request_variables)++;
	switch (arg) {
		case PARSE_GET:
			SUHOSIN7_G(cur_get_vars)++;
			break;
		case PARSE_COOKIE:
			SUHOSIN7_G(cur_cookie_vars)++;
			break;
		case PARSE_POST:
			SUHOSIN7_G(cur_post_vars)++;
			break;
	}
	
	if (new_val_len) {
		*new_val_len = val_len;
	}

	return 1;
}
/* }}} */



/* {{{ suhosin_hook_register_server_variables
 */
void suhosin_hook_register_server_variables()
{
	if (sapi_module.register_server_variables) {
		orig_register_server_variables = sapi_module.register_server_variables;
		sapi_module.register_server_variables = suhosin_register_server_variables;
	}
}
/* }}} */


/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
