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

  Note: The following code is based on ext/standard/array.c from PHP 7.
  | Copyright (c) 1997-2016 The PHP Group                                |
  Original PHP Version 7 Authors:
  |          Andi Gutmans <andi@zend.com>                                |
  |          Zeev Suraski <zeev@zend.com>                                |
  |          Rasmus Lerdorf <rasmus@php.net>                             |
  |          Andrei Zmievski <andrei@php.net>                            |
  |          Stig Venaas <venaas@php.net>                                |
  |          Jason Greene <jason@php.net>                                |

*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/php_smart_string.h"
#include "ext/standard/php_var.h"
#include "php_suhosin7.h"


#define EXTR_OVERWRITE			0
#define EXTR_SKIP				1
#define EXTR_PREFIX_SAME		2
#define	EXTR_PREFIX_ALL			3
#define	EXTR_PREFIX_INVALID		4
#define	EXTR_PREFIX_IF_EXISTS	5
#define	EXTR_IF_EXISTS			6

#define EXTR_REFS				0x100


static zend_always_inline int php_valid_var_name(char *var_name, size_t var_name_len) /* {{{ */
{
#if 1
	/* first 256 bits for first character, and second 256 bits for the next */
	static const uint32_t charset[16] = {
	     /*  31      0   63     32   95     64   127    96 */
			0x00000000, 0x00000000, 0x87fffffe, 0x07fffffe,
			0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
	     /*  31      0   63     32   95     64   127    96 */
			0x00000000, 0x03ff0000, 0x87fffffe, 0x07fffffe,
			0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff
		};
#endif
	size_t i;
	uint32_t ch;

	if (UNEXPECTED(!var_name_len)) {
		return 0;
	}

	/* These are allowed as first char: [a-zA-Z_\x7f-\xff] */
	ch = (uint32_t)((unsigned char *)var_name)[0];
#if 1
	if (UNEXPECTED(!(charset[ch >> 5] & (1 << (ch & 0x1f))))) {
#else
	if (var_name[0] != '_' &&
		(ch < 65  /* A    */ || /* Z    */ ch > 90)  &&
		(ch < 97  /* a    */ || /* z    */ ch > 122) &&
		(ch < 127 /* 0x7f */ || /* 0xff */ ch > 255)
	) {
#endif
		return 0;
	}

	/* And these as the rest: [a-zA-Z0-9_\x7f-\xff] */
	if (var_name_len > 1) {
		i = 1;
		do {
			ch = (uint32_t)((unsigned char *)var_name)[i];
#if 1
			if (UNEXPECTED(!(charset[8 + (ch >> 5)] & (1 << (ch & 0x1f))))) {
#else
			if (var_name[i] != '_' &&
				(ch < 48  /* 0    */ || /* 9    */ ch > 57)  &&
				(ch < 65  /* A    */ || /* Z    */ ch > 90)  &&
				(ch < 97  /* a    */ || /* z    */ ch > 122) &&
				(ch < 127 /* 0x7f */ || /* 0xff */ ch > 255)
			) {
#endif
				return 0;
			}
		} while (++i < var_name_len);
	}

	if (suhosin_is_protected_varname(var_name, var_name_len)) {
		return 0;
	}

	return 1;
}

/* {{{ proto int extract(array var_array [, int extract_type [, string prefix]])
   Imports variables into symbol table from an array */
PHP_FUNCTION(suhosin_extract)
{
	zval *var_array_param, *prefix = NULL;
	zend_long extract_type = EXTR_OVERWRITE;
	zval *entry;
	zend_string *var_name;
	zend_ulong num_key;
	int var_exists, count = 0;
	int extract_refs = 0;
	zend_array *symbol_table;
	zval var_array;

#ifndef FAST_ZPP
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "a|lz/", &var_array_param, &extract_type, &prefix) == FAILURE) {
		return;
	}
#else
	ZEND_PARSE_PARAMETERS_START(1, 3)
		Z_PARAM_ARRAY(var_array_param)
		Z_PARAM_OPTIONAL
		Z_PARAM_LONG(extract_type)
		Z_PARAM_ZVAL_EX(prefix, 0, 1)
	ZEND_PARSE_PARAMETERS_END();
#endif

	extract_refs = (extract_type & EXTR_REFS);
	if (extract_refs) {
		SEPARATE_ZVAL(var_array_param);
	}
	extract_type &= 0xff;

	if (extract_type < EXTR_OVERWRITE || extract_type > EXTR_IF_EXISTS) {
		php_error_docref(NULL, E_WARNING, "Invalid extract type");
		return;
	}

	if (extract_type > EXTR_SKIP && extract_type <= EXTR_PREFIX_IF_EXISTS && ZEND_NUM_ARGS() < 3) {
		php_error_docref(NULL, E_WARNING, "specified extract type requires the prefix parameter");
		return;
	}

	if (prefix) {
		convert_to_string(prefix);
		if (Z_STRLEN_P(prefix) && !php_valid_var_name(Z_STRVAL_P(prefix), Z_STRLEN_P(prefix))) {
			php_error_docref(NULL, E_WARNING, "prefix is not a valid identifier");
			return;
		}
	}

	symbol_table = zend_rebuild_symbol_table();
#if 0
	if (!symbol_table) {
		php_error_docref(NULL, E_WARNING, "failed to build symbol table");
		return;
	}
#endif

	/* The array might be stored in a local variable that will be overwritten. To avoid losing the
	 * reference in that case we work on a copy. */
	ZVAL_COPY(&var_array, var_array_param);

	ZEND_HASH_FOREACH_KEY_VAL_IND(Z_ARRVAL(var_array), num_key, var_name, entry) {
		zval final_name;

		ZVAL_NULL(&final_name);
		var_exists = 0;

		if (var_name) {
			var_exists = zend_hash_exists_ind(symbol_table, var_name);
		} else if (extract_type == EXTR_PREFIX_ALL || extract_type == EXTR_PREFIX_INVALID) {
			zend_string *str = zend_long_to_str(num_key);
			php_prefix_varname(&final_name, prefix, ZSTR_VAL(str), ZSTR_LEN(str), 1);
			zend_string_release(str);
		} else {
			continue;
		}

		switch (extract_type) {
			case EXTR_IF_EXISTS:
				if (!var_exists) break;
				/* break omitted intentionally */

			case EXTR_OVERWRITE:
				/* GLOBALS protection */
				if (var_exists && ZSTR_LEN(var_name) == sizeof("GLOBALS")-1 && !strcmp(ZSTR_VAL(var_name), "GLOBALS")) {
					break;
				}
				if (var_exists && ZSTR_LEN(var_name) == sizeof("this")-1  && !strcmp(ZSTR_VAL(var_name), "this") /* && EG(scope) && ZSTR_LEN(EG(scope)->name) != 0 */) {
					break;
				}
				ZVAL_STR_COPY(&final_name, var_name);
				break;

			case EXTR_PREFIX_IF_EXISTS:
				if (var_exists) {
					php_prefix_varname(&final_name, prefix, ZSTR_VAL(var_name), ZSTR_LEN(var_name), 1);
				}
				break;

			case EXTR_PREFIX_SAME:
				if (!var_exists && ZSTR_LEN(var_name) != 0) {
					ZVAL_STR_COPY(&final_name, var_name);
				}
				/* break omitted intentionally */

			case EXTR_PREFIX_ALL:
				if (Z_TYPE(final_name) == IS_NULL && ZSTR_LEN(var_name) != 0) {
					php_prefix_varname(&final_name, prefix, ZSTR_VAL(var_name), ZSTR_LEN(var_name), 1);
				}
				break;

			case EXTR_PREFIX_INVALID:
				if (Z_TYPE(final_name) == IS_NULL) {
					if (!php_valid_var_name(ZSTR_VAL(var_name), ZSTR_LEN(var_name))) {
						php_prefix_varname(&final_name, prefix, ZSTR_VAL(var_name), ZSTR_LEN(var_name), 1);
					} else {
						ZVAL_STR_COPY(&final_name, var_name);
					}
				}
				break;

			default:
				if (!var_exists) {
					ZVAL_STR_COPY(&final_name, var_name);
				}
				break;
		}

		if (Z_TYPE(final_name) == IS_STRING && php_valid_var_name(Z_STRVAL(final_name), Z_STRLEN(final_name))) {
			zval *orig_var;
			if (extract_refs) {

				ZVAL_MAKE_REF(entry);
				Z_ADDREF_P(entry);

				if ((orig_var = zend_hash_find(symbol_table, Z_STR(final_name))) != NULL) {
					if (Z_TYPE_P(orig_var) == IS_INDIRECT) {
						orig_var = Z_INDIRECT_P(orig_var);
					}
					zval_ptr_dtor(orig_var);
					ZVAL_COPY_VALUE(orig_var, entry);
				} else {
					zend_hash_update(symbol_table, Z_STR(final_name), entry);
				}
			} else {
				ZVAL_DEREF(entry);
				if (Z_REFCOUNTED_P(entry)) Z_ADDREF_P(entry);
				if ((orig_var = zend_hash_find(symbol_table, Z_STR(final_name))) != NULL) {
					if (Z_TYPE_P(orig_var) == IS_INDIRECT) {
						orig_var = Z_INDIRECT_P(orig_var);
					}
					ZVAL_DEREF(orig_var);
					zval_ptr_dtor(orig_var);
					ZVAL_COPY_VALUE(orig_var, entry);
				} else {
					zend_hash_update(symbol_table, Z_STR(final_name), entry);
				}
			}
			count++;
		}
		zval_dtor(&final_name);
	} ZEND_HASH_FOREACH_END();
	zval_ptr_dtor(&var_array);

	RETURN_LONG(count);
}
/* }}} */




ZEND_BEGIN_ARG_INFO_EX(suhosin_arginfo_extract, 0, 0, 1)
	ZEND_ARG_INFO(ZEND_SEND_PREFER_REF, arg) /* ARRAY_INFO(0, arg, 0) */
	ZEND_ARG_INFO(0, extract_type)
	ZEND_ARG_INFO(0, prefix)
ZEND_END_ARG_INFO()


/* {{{ suhosin_ex_imp_functions[]
 */
zend_function_entry suhosin_ex_imp_functions[] = {
	PHP_NAMED_FE(extract, PHP_FN(suhosin_extract), suhosin_arginfo_extract)
	{NULL, NULL, NULL}
};
/* }}} */

void suhosin_hook_ex_imp()
{
	/* replace the extract and import_request_variables functions */
	zend_hash_str_del(CG(function_table), ZEND_STRL("extract"));
	zend_register_functions(NULL, suhosin_ex_imp_functions, NULL, MODULE_PERSISTENT);
}


/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
