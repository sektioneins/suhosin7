/*
  +----------------------------------------------------------------------+
  | Suhosin Version 1                                                    |
  +----------------------------------------------------------------------+
  | Copyright (c) 2006-2007 The Hardened-PHP Project                     |
  | Copyright (c) 2007-2015 SektionEins GmbH                             |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Stefan Esser <sesser@sektioneins.de>                         |
  +----------------------------------------------------------------------+
*/

/* $Id: execute.c,v 1.1.1.1 2007-11-28 01:15:35 sesser Exp $ */
// #if 0
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

// #include <fcntl.h>
#include "php.h"
// #include "php_ini.h"
// #include "zend_hash.h"
#include "zend_extensions.h"
// #include "ext/standard/info.h"
// #include "ext/standard/php_rand.h"
// #include "ext/standard/php_lcg.h"
#include "php_suhosin7.h"
// #include "zend_compile.h"
// #include "zend_llist.h"
#include "SAPI.h"
#include "execute.h"

// #include "sha256.h"

// #ifdef PHP_WIN32
// # include "win32/fnmatch.h"
// # include "win32/winutil.h"
// # include "win32/time.h"
// #else
// # ifdef HAVE_FNMATCH
// #  include <fnmatch.h>
// # endif
// # include <sys/time.h>
// #endif

ZEND_API static void (*old_execute_ex)(zend_execute_data *execute_data);
ZEND_API static void suhosin_execute_ex(zend_execute_data *execute_data);
ZEND_API static void (*old_execute_internal)(zend_execute_data *execute_data, zval *return_value);
ZEND_API static void suhosin_execute_internal(zend_execute_data *execute_data, zval *return_value);
ZEND_API static void (*old_execute)(zend_op_array *op_array, zval *return_value);
ZEND_API static void suhosin_execute(zend_op_array *op_array, zval *return_value);
// static void (*old_execute_ZO)(zend_op_array *op_array, long dummy);
// static void suhosin_execute_ZO(zend_op_array *op_array, long dummy);
// static void *(*zo_set_oe_ex)(void *ptr) = NULL;


// extern zend_extension suhosin_zend_extension_entry;

#ifdef SUHOSIN_STRCASESTR
/* {{{ suhosin_strcasestr */
char *suhosin_strcasestr(char *haystack, char *needle)
{
	unsigned char *t, *h, *n;
	h = (unsigned char *) haystack;
conts:
	while (*h) {
		n = (unsigned char *) needle;
		if (toupper(*h++) == toupper(*n++)) {
			for (t=h; *n; t++, n++) {
				if (toupper(*t) != toupper(*n)) goto conts;
			}
			return ((char*)h-1);
		}
	}

	return (NULL);
}
/* }}} */
#endif

static int match_include_list(HashTable *ht, char *s, size_t slen)
{
	char *h = strstr(s, "://");
	char *h2 = suhosin_strcasestr(s, "data:");
	h2 = h2 == NULL ? NULL : h2 + 4;
	char *t = h = (h == NULL) ? h2 : ( (h2 == NULL) ? h : ( (h <= h2) ? h : h2 ) );
	if (h == NULL) return -1; // no URL
	
	while (t > s && (isalnum(t[-1]) || t[-1]=='_' || t[-1]=='.')) {
		t--;
	}
	
	size_t tlen = slen - (t - s);
	
	zend_ulong num_key;
	zend_string *key;
	ZEND_HASH_FOREACH_KEY(ht, num_key, key) {
		if (tlen < ZSTR_LEN(key)) { continue; }
		if (ZSTR_LEN(key) == 0) { continue; } // ignore empty list entries
		if (strncasecmp(t, ZSTR_VAL(key), ZSTR_LEN(key)) == 0) {
			return 1;
		}
	} ZEND_HASH_FOREACH_END();
	return 0;
}

#define SUHOSIN_CODE_TYPE_UNKNOWN	0
#define SUHOSIN_CODE_TYPE_COMMANDLINE	1
#define SUHOSIN_CODE_TYPE_EVAL		2
// #define SUHOSIN_CODE_TYPE_REGEXP	3
#define SUHOSIN_CODE_TYPE_ASSERT	4
#define SUHOSIN_CODE_TYPE_CFUNC		5
#define SUHOSIN_CODE_TYPE_SUHOSIN	6
#define SUHOSIN_CODE_TYPE_UPLOADED	7
#define SUHOSIN_CODE_TYPE_0FILE		8
#define SUHOSIN_CODE_TYPE_BLACKURL	9
#define SUHOSIN_CODE_TYPE_BADURL	10
#define SUHOSIN_CODE_TYPE_GOODFILE	11
#define SUHOSIN_CODE_TYPE_BADFILE	12
#define SUHOSIN_CODE_TYPE_LONGNAME	13
#define SUHOSIN_CODE_TYPE_MANYDOTS	14
#define SUHOSIN_CODE_TYPE_WRITABLE  15
#define SUHOSIN_CODE_TYPE_MBREGEXP	16

static int suhosin_check_filename(char *s, int slen)
{
	/* check if filename is too long */
	if (slen > MAXPATHLEN) {
		return SUHOSIN_CODE_TYPE_LONGNAME;
	}

	char fname[MAXPATHLEN+1];

	memcpy(fname, s, slen);
	fname[slen] = 0; 
	s = (char *)fname;
	char *e = s + slen;

	/* check if ASCIIZ attack */
	if (slen != strlen(s)) {
		return SUHOSIN_CODE_TYPE_0FILE;
	}
	
	SDEBUG("fn=%s", s);
	/* disallow uploaded files */
	if (SG(rfc1867_uploaded_files)) {
		if (zend_hash_str_exists(SG(rfc1867_uploaded_files), s, slen)) {
			return SUHOSIN_CODE_TYPE_UPLOADED;
		}
	}
		
	/* count number of directory traversals */
	int traversal_conut = 0;
	for (int i = 0; i < slen-3; i++) {
		if (s[i] == '.' && s[i+1] == '.' && IS_SLASH(s[i+2])) {
			traversal_conut++;
			i += 2;
		}
	}
	if (SUHOSIN7_G(executor_include_max_traversal) && traversal_conut > SUHOSIN7_G(executor_include_max_traversal)) {
		return SUHOSIN_CODE_TYPE_MANYDOTS;
	}
	
	SDEBUG("include wl=%p bl=%p", SUHOSIN7_G(include_whitelist), SUHOSIN7_G(include_blacklist));
	/* no black or whitelist then disallow all */
	if (SUHOSIN7_G(include_whitelist) == NULL && SUHOSIN7_G(include_blacklist) == NULL) {
		/* disallow all URLs */
		if (strstr(s, "://") != NULL || suhosin_strcasestr(s, "data:") != NULL) {
			return SUHOSIN_CODE_TYPE_BADURL;
		}
	} else {
		if (SUHOSIN7_G(include_whitelist) != NULL) {
			if (match_include_list(SUHOSIN7_G(include_whitelist), s, slen) == 0) {
				return SUHOSIN_CODE_TYPE_BADURL;
			}
		} else if (SUHOSIN7_G(include_blacklist) != NULL) {
			if (match_include_list(SUHOSIN7_G(include_blacklist), s, slen) == 1) {
				return SUHOSIN_CODE_TYPE_BLACKURL;
			}
		}
	}
	
check_filename_skip_lists:

	/* disallow writable files */
	if (!SUHOSIN7_G(executor_include_allow_writable_files)) {
		/* protection against *REMOTE* attacks, potential
		   race condition of access() is irrelevant */
		if (access(s, W_OK) == 0) {
			return SUHOSIN_CODE_TYPE_WRITABLE;
		}
	}

	return SUHOSIN_CODE_TYPE_GOODFILE;
}


static void suhosin_check_codetype(zend_ulong code_type, char *filename)
{
	switch (code_type) {
		case SUHOSIN_CODE_TYPE_EVAL:
			if (SUHOSIN7_G(executor_disable_eval)) {
				suhosin_log(S_EXECUTOR|S_GETCALLER, "use of eval is forbidden by configuration");
				if (!SUHOSIN7_G(simulation)) {
					zend_error(E_ERROR, "SUHOSIN - Use of eval is forbidden by configuration");
				}
			}
			break;
			
		// case SUHOSIN_CODE_TYPE_REGEXP:
		//     if (SUHOSIN7_G(executor_disable_emod)) {
		// 	    suhosin_log(S_EXECUTOR|S_GETCALLER, "use of preg_replace() with /e modifier is forbidden by configuration");
		// 	    if (!SUHOSIN7_G(simulation)) {
		// 		    zend_error(E_ERROR, "SUHOSIN - Use of preg_replace() with /e modifier is forbidden by configuration");
		// 	    }
		//     }
		//     break;
			
		case SUHOSIN_CODE_TYPE_MBREGEXP:
			if (SUHOSIN7_G(executor_disable_emod)) {
				suhosin_log(S_EXECUTOR|S_GETCALLER, "use of /e modifier in replace function is forbidden by configuration");
				if (!SUHOSIN7_G(simulation)) {
					zend_error(E_ERROR, "SUHOSIN - Use of /e modifier in replace function is forbidden by configuration");
				}
			}
			break;
		
		case SUHOSIN_CODE_TYPE_ASSERT:
			break;
		
		case SUHOSIN_CODE_TYPE_CFUNC:
			break;
		
		case SUHOSIN_CODE_TYPE_LONGNAME:
			suhosin_log(S_INCLUDE|S_GETCALLER, "Include filename is too long: %s", filename);
			suhosin_bailout();
			break;

		case SUHOSIN_CODE_TYPE_MANYDOTS:
			suhosin_log(S_INCLUDE|S_GETCALLER, "Include filename contains too many '../': %s", filename);
			suhosin_bailout();
			break;
		
		case SUHOSIN_CODE_TYPE_UPLOADED:
			suhosin_log(S_INCLUDE|S_GETCALLER, "Include filename is an uploaded file");
			suhosin_bailout();
			break;
			
		case SUHOSIN_CODE_TYPE_0FILE:
			suhosin_log(S_INCLUDE|S_GETCALLER, "Include filename contains an ASCIIZ character");
			suhosin_bailout();
			break;
			
		case SUHOSIN_CODE_TYPE_WRITABLE:
			suhosin_log(S_INCLUDE|S_GETCALLER, "Include filename is writable by PHP process: %s", filename);
			suhosin_bailout();
			break;		    	

		case SUHOSIN_CODE_TYPE_BLACKURL:
			suhosin_log(S_INCLUDE|S_GETCALLER, "Included URL is blacklisted: %s", filename);
			suhosin_bailout();
			break;
			
		case SUHOSIN_CODE_TYPE_BADURL:
			suhosin_log(S_INCLUDE|S_GETCALLER, "Included URL is not allowed: %s", filename);
			suhosin_bailout();
			break;

		case SUHOSIN_CODE_TYPE_BADFILE:
// 		    cs.type = IS_STRING;
// #define DIE_WITH_MSG "die('disallowed_file'.chr(10).chr(10));"
// 		    cs.value.str.val = estrndup(DIE_WITH_MSG, sizeof(DIE_WITH_MSG)-1);
// 		    cs.value.str.len = sizeof(DIE_WITH_MSG)-1;
// 		    new_op_array = compile_string(&cs, "suhosin internal code");
// 		    if (new_op_array) {
// 				op_array = new_op_array;
// 				goto continue_execution;
// 		    }
			suhosin_bailout();
			break;

		case SUHOSIN_CODE_TYPE_COMMANDLINE:
		case SUHOSIN_CODE_TYPE_SUHOSIN:
		case SUHOSIN_CODE_TYPE_UNKNOWN:
		case SUHOSIN_CODE_TYPE_GOODFILE:
			break;
	}

}

ZEND_API static int (*old_zend_stream_open)(const char *filename, zend_file_handle *handle) = NULL;

// 
ZEND_API static int suhosin_zend_stream_open(const char *filename, zend_file_handle *handle)
{
	zend_execute_data *execute_data = EG(current_execute_data);
	
	if ((execute_data != NULL) && (execute_data->opline != NULL) && (execute_data->opline->opcode == ZEND_INCLUDE_OR_EVAL)) {
		int filetype = suhosin_check_filename((char *)filename, strlen(filename));
		suhosin_check_codetype(filetype, (char*)filename);
	}

	return old_zend_stream_open(filename, handle);
}


static inline int suhosin_detect_codetype(zend_op_array *op_array)
{
	if (op_array->filename == NULL) {
		return SUHOSIN_CODE_TYPE_UNKNOWN;
	}

	char *s = (char *)ZSTR_VAL(op_array->filename);

	/* eval, assert, create_function, mb_ereg_replace  */
	if (op_array->type == ZEND_EVAL_CODE) {
	
		if (s == NULL) {
			return SUHOSIN_CODE_TYPE_UNKNOWN;
		}
	
		if (strstr(s, "eval()'d code") != NULL) {
			return SUHOSIN_CODE_TYPE_EVAL;
		}

		// if (strstr(s, "regexp code") != NULL) {
		// 	return SUHOSIN_CODE_TYPE_REGEXP;
		// }

		if (strstr(s, "mbregex replace") != NULL) {
			return SUHOSIN_CODE_TYPE_MBREGEXP;
		}

		if (strstr(s, "assert code") != NULL) {
			return SUHOSIN_CODE_TYPE_ASSERT;
		}

		if (strstr(s, "runtime-created function") != NULL) {
			return SUHOSIN_CODE_TYPE_CFUNC;
		}
		
		if (strstr(s, "Command line code") != NULL) {
			return SUHOSIN_CODE_TYPE_COMMANDLINE;
		}

		if (strstr(s, "Command line begin code") != NULL) {
			return SUHOSIN_CODE_TYPE_COMMANDLINE;
		}

		if (strstr(s, "Command line run code") != NULL) {
			return SUHOSIN_CODE_TYPE_COMMANDLINE;
		}

		if (strstr(s, "Command line end code") != NULL) {
			return SUHOSIN_CODE_TYPE_COMMANDLINE;
		}
		
		if (strstr(s, "suhosin internal code") != NULL) {
			return SUHOSIN_CODE_TYPE_SUHOSIN;
		}
		
	} else {

		return suhosin_check_filename(s, strlen(s));

	}
	
	return SUHOSIN_CODE_TYPE_UNKNOWN;
}

/* {{{ void suhosin_execute_ex(zend_op_array *op_array)
 *    This function provides a hook for execution */
ZEND_API static void suhosin_execute_ex(zend_execute_data *execute_data)
{
	if (execute_data == NULL) {
		return;
	}
	if (execute_data->func == NULL) {
		old_execute_ex(execute_data);
		return;
	}
	
	zend_op_array *new_op_array;
	int op_array_type;//, len;
	// char *fn;
	zval cs;
	zend_ulong orig_code_type;
	unsigned long *suhosin_flags = NULL;
	
	/* log variable dropping statistics */
	if (SUHOSIN7_G(abort_request)) {
		
		SUHOSIN7_G(abort_request) = 0; /* we only want this to happen the first time */
		
		if (SUHOSIN7_G(att_request_variables)-SUHOSIN7_G(cur_request_variables) > 0) {
			suhosin_log(S_VARS, "dropped %u request variables - (%u in GET, %u in POST, %u in COOKIE)",
			SUHOSIN7_G(att_request_variables)-SUHOSIN7_G(cur_request_variables),
			SUHOSIN7_G(att_get_vars)-SUHOSIN7_G(cur_get_vars),
			SUHOSIN7_G(att_post_vars)-SUHOSIN7_G(cur_post_vars),
			SUHOSIN7_G(att_cookie_vars)-SUHOSIN7_G(cur_cookie_vars));
		}
	
		// if (!SUHOSIN7_G(simulation) && SUHOSIN7_G(filter_action)) {
		// 
		// 	char *action = SUHOSIN7_G(filter_action);
		// 	long code = -1;
		// 		
		// 	while (*action == ' ' || *action == '\t') action++;
		// 
		// 	if (*action >= '0' && *action <= '9') {
		// 		char *end = action;
		// 		while (*end && *end != ',' && *end != ';') end++;
		// 		code = zend_atoi(action, end-action);
		// 		action = end;
		// 	}
		// 
		// 	while (*action == ' ' || *action == '\t' || *action == ',' || *action == ';') action++;
		// 
		// 	if (*action) {
		// 	
		// 		if (strncasecmp("http://", action, sizeof("http://")-1)==0
		// 		|| strncasecmp("https://", action, sizeof("https://")-1)==0) {
		// 			sapi_header_line ctr = {0};
		// 		
		// 			if (code == -1) {
		// 				code = 302;
		// 			}
		// 		
		// 			ctr.line_len = spprintf(&ctr.line, 0, "Location: %s", action);
		// 			ctr.response_code = code;
		// 			sapi_header_op(SAPI_HEADER_REPLACE, &ctr);
		// 			efree(ctr.line);
		// 		} else {
		// 			zend_file_handle file_handle;
		// 			zend_op_array *new_op_array;
		// 			zval *result = NULL;
		// 		
		// 			if (code == -1) {
		// 				code = 200;
		// 			}
		// 		
		// 			if (zend_stream_open(action, &file_handle) == SUCCESS) {
		// 				if (!file_handle.opened_path) {
		// 					file_handle.opened_path = estrndup(action, strlen(action));
		// 				}
		// 				new_op_array = zend_compile_file(&file_handle, ZEND_REQUIRE);
		// 				zend_destroy_file_handle(&file_handle);
		// 				if (new_op_array) {
		// 					EG(return_value_ptr_ptr) = &result;
		// 					EG(active_op_array) = new_op_array;
		// 					zend_execute(new_op_array);
		// 					destroy_op_array(new_op_array);
		// 					efree(new_op_array);
		// 
		// 					if (!EG(exception))
		// 					{
		// 						if (EG(return_value_ptr_ptr)) {
		// 							zval_ptr_dtor(EG(return_value_ptr_ptr));
		// 							EG(return_value_ptr_ptr) = NULL;
		// 						}
		// 					}
		// 				} else {
		// 					code = 500;
		// 				}
		// 			} else {
		// 				code = 500;
		// 			}
		// 		}
		// 	}
		// 
		// 	sapi_header_op(SAPI_HEADER_SET_STATUS, (void *)code);
		// 	zend_bailout();
		// }
	}
	
	// SDEBUG("%s %s", op_array->filename, op_array->function_name);
	
	SUHOSIN7_G(execution_depth)++;
	
	if (SUHOSIN7_G(max_execution_depth) && SUHOSIN7_G(execution_depth) > SUHOSIN7_G(max_execution_depth)) {
		suhosin_log(S_EXECUTOR|S_GETCALLER, "maximum execution depth reached - script terminated");
		suhosin_bailout();
	}
	
	// fn = (char *)execute_data->func->op_array.filename;
	// len = strlen(fn);
	
	orig_code_type = SUHOSIN7_G(in_code_type);
	if (execute_data->func->op_array.type == ZEND_EVAL_CODE) {
		SUHOSIN7_G(in_code_type) = SUHOSIN_EVAL;
	} else {
		// if (suhosin_zend_extension_entry.resource_number != -1) {
		// 	suhosin_flags = (unsigned long *) &execute_data->func->op_array.reserved[suhosin_zend_extension_entry.resource_number];
		// 	SDEBUG("suhosin flags: %08lx", *suhosin_flags);
		// 	
		// 	if (*suhosin_flags & SUHOSIN_FLAG_CREATED_BY_EVAL) {
		// 		SUHOSIN7_G(in_code_type) = SUHOSIN_EVAL;
		// 	}
		// 	if (*suhosin_flags & SUHOSIN_FLAG_NOT_EVALED_CODE) {
		// 		goto not_evaled_code;
		// 	}
		// }
		
		if (zend_string_equals_literal(execute_data->func->op_array.filename, "eval()'d code")) {
			SUHOSIN7_G(in_code_type) = SUHOSIN_EVAL;
		} // else {
		// 	if (suhosin_flags) {
		// 		*suhosin_flags |= SUHOSIN_FLAG_NOT_EVALED_CODE;
		// 	}
		// }
	}
not_evaled_code:
	SDEBUG("code type %llu", SUHOSIN7_G(in_code_type));
	if (execute_data->func->op_array.function_name) {
		goto continue_execution;
	}

/*	if (SUHOSIN7_G(deactivate)) {
		goto continue_execution;
	}
*/	

	op_array_type = suhosin_detect_codetype(&execute_data->func->op_array);
	char *filename = execute_data->func->op_array.filename ? ZSTR_VAL(execute_data->func->op_array.filename) : "<unknown>";
	suhosin_check_codetype(op_array_type, filename);

continue_execution:
	old_execute_ex(execute_data);

	/* nothing to do */
	SUHOSIN7_G(in_code_type) = orig_code_type;
	SUHOSIN7_G(execution_depth)--;
}
/* }}} */



// ----------------------------------------------------------------------------

static HashTable ihandler_table;



static suhosin_internal_function_handler ihandlers[] = {
	S7_IH_ENTRY0i(preg_replace)

	// { "preg_replace", ih_preg_replace, NULL, NULL, NULL },
	// { "mail", ih_mail, NULL, NULL, NULL },
	// { "symlink", ih_symlink, NULL, NULL, NULL },
	
	// { "srand", ih_srand, NULL, NULL, NULL },
	// { "mt_srand", ih_mt_srand, NULL, NULL, NULL },
	// { "rand", ih_rand, NULL, NULL, NULL },
	// { "mt_rand", ih_mt_rand, NULL, NULL, NULL },
	// { "getrandmax", ih_getrandmax, NULL, NULL, NULL },
	// { "mt_getrandmax", ih_getrandmax, NULL, NULL, NULL },
	
	// { "function_exists", ih_function_exists, NULL, NULL, NULL },
	
	/* Mysqli */
	// { "mysqli::mysqli", ih_fixusername, (void *)2, NULL, NULL },
	// { "mysqli_connect", ih_fixusername, (void *)2, NULL, NULL },
	// { "mysqli::real_connect", ih_fixusername, (void *)2, NULL, NULL },
	// { "mysqli_real_connect", ih_fixusername, (void *)3, NULL, NULL },
	// { "mysqli_change_user", ih_fixusername, (void *)2, NULL, NULL },
	// { "mysqli::change_user", ih_fixusername, (void *)1, NULL, NULL },
	
	// { "mysqli::query", ih_querycheck, (void *)1, (void *)1, NULL },
	// { "mysqli_query", ih_querycheck, (void *)2, (void *)1, NULL },
	// { "mysqli::multi_query", ih_querycheck, (void *)1, (void *)1, NULL },
	// { "mysqli_multi_query", ih_querycheck, (void *)2, (void *)1, NULL },
	// { "mysqli::prepare", ih_querycheck, (void *)1, (void *)1, NULL },
	// { "mysqli_prepare", ih_querycheck, (void *)2, (void *)1, NULL },
	// { "mysqli::real_query", ih_querycheck, (void *)1, (void *)1, NULL },
	// { "mysqli_real_query", ih_querycheck, (void *)2, (void *)1, NULL },
	// { "mysqli::send_query", ih_querycheck, (void *)1, (void *)1, NULL },
	// { "mysqli_send_query", ih_querycheck, (void *)2, (void *)1, NULL },
	// // removed in PHP 5.3
	// { "mysqli_master_query", ih_querycheck, (void *)2, (void *)1, NULL },
	// { "mysqli_slave_query", ih_querycheck, (void *)2, (void *)1, NULL },
	// ----
	
	/* Mysql API - deprecated in PHP 5.5 */
	// { "mysql_connect", ih_fixusername, (void *)2, NULL, NULL },
	// { "mysql_pconnect", ih_fixusername, (void *)2, NULL, NULL },
	// { "mysql_query", ih_querycheck, (void *)1, (void *)1, NULL },
	// { "mysql_db_query", ih_querycheck, (void *)2, (void *)1, NULL },
	// { "mysql_unbuffered_query", ih_querycheck, (void *)1, (void *)1, NULL },
	
#ifdef SUHOSIN7_EXPERIMENTAL
	/* MaxDB */
	// { "maxdb::maxdb", ih_fixusername, (void *)2, NULL, NULL },
	// { "maxdb_connect", ih_fixusername, (void *)2, NULL, NULL },
	// { "maxdb::real_connect", ih_fixusername, (void *)2, NULL, NULL },
	// { "maxdb_real_connect", ih_fixusername, (void *)3, NULL, NULL },
	// { "maxdb::change_user", ih_fixusername, (void *)1, NULL, NULL },
	// { "maxdb_change_user", ih_fixusername, (void *)2, NULL, NULL },
	// 
	// { "maxdb_master_query", ih_querycheck, (void *)2, NULL, NULL },
	// { "maxdb::multi_query", ih_querycheck, (void *)1, NULL, NULL },
	// { "maxdb_multi_query", ih_querycheck, (void *)2, NULL, NULL },
	// { "maxdb::query", ih_querycheck, (void *)1, NULL, NULL },
	// { "maxdb_query", ih_querycheck, (void *)2, NULL, NULL },
	// { "maxdb::real_query", ih_querycheck, (void *)1, NULL, NULL },
	// { "maxdb_real_query", ih_querycheck, (void *)2, NULL, NULL },
	// { "maxdb::send_query", ih_querycheck, (void *)1, NULL, NULL },
	// { "maxdb_send_query", ih_querycheck, (void *)2, NULL, NULL },
	// { "maxdb::prepare", ih_querycheck, (void *)1, NULL, NULL },
	// { "maxdb_prepare", ih_querycheck, (void *)2, NULL, NULL },

	/* PDO */
		/* note: mysql conditional comments not supported here */
	// { "pdo::__construct", ih_fixusername, (void *)2, NULL, NULL }, /* note: username may come from dsn (param 1) */
	// { "pdo::query", ih_querycheck, (void *)1, NULL, NULL },
	// { "pdo::prepare", ih_querycheck, (void *)1, NULL, NULL },
	// { "pdo::exec", ih_querycheck, (void *)1, NULL, NULL },
	
	/* Oracle OCI8 */
	// { "ocilogon", ih_fixusername, (void *)1, NULL, NULL },
	// { "ociplogon", ih_fixusername, (void *)1, NULL, NULL },
	// { "ocinlogon", ih_fixusername, (void *)1, NULL, NULL },
	// { "oci_connect", ih_fixusername, (void *)1, NULL, NULL },
	// { "oci_pconnect", ih_fixusername, (void *)1, NULL, NULL },
	// { "oci_new_connect", ih_fixusername, (void *)1, NULL, NULL },

	/* FrontBase */
	// { "fbsql_connect", ih_fixusername, (void *)2, NULL, NULL },
	// { "fbsql_pconnect", ih_fixusername, (void *)2, NULL, NULL },
	// { "fbsql_change_user", ih_fixusername, (void *)1, NULL, NULL },
	// { "fbsql_username", ih_fixusername, (void *)2, NULL, NULL },

	/* Informix */
	// { "ifx_connect", ih_fixusername, (void *)2, NULL, NULL },
	// { "ifx_pconnect", ih_fixusername, (void *)2, NULL, NULL },
	// 
	/* Firebird/InterBase */
	// { "ibase_connect", ih_fixusername, (void *)2, NULL, NULL },
	// { "ibase_pconnect", ih_fixusername, (void *)2, NULL, NULL },
	// { "ibase_service_attach", ih_fixusername, (void *)2, NULL, NULL },

	/* Microsoft SQL Server */
	// { "mssql_connect", ih_fixusername, (void *)2, NULL, NULL },
	// { "mssql_pconnect", ih_fixusername, (void *)2, NULL, NULL },
#endif

	{ NULL, NULL, NULL, NULL, NULL }
};

#define FUNCTION_WARNING(fname) zend_error(E_WARNING, "%s() has been disabled for security reasons", (fname));
#define FUNCTION_SIMULATE_WARNING(fname) zend_error(E_WARNING, "SIMULATION - %s() has been disabled for security reasons", (fname));

/* {{{ void suhosin_execute_internal
 *    This function provides a hook for internal execution */

#define EX_T(offset) (*EX_TMP_VAR(execute_data_ptr, offset))

ZEND_API static void suhosin_execute_internal(zend_execute_data *execute_data, zval *return_value)
{
	if (execute_data == NULL) {
		// if (EG(current_execute_data) != NULL) {
		// 	execute_data = EG(current_execute_data);
		// }
		suhosin_log(S_EXECUTOR|S_GETCALLER, "execution without data. something is wrong.");
		suhosin_bailout();
		return;
	}
	
	zend_function *func = execute_data->func;
	if (func == NULL) {
		suhosin_log(S_EXECUTOR|S_GETCALLER, "execution without function context. something is wrong.");
		suhosin_bailout();
	}
	
	
	// zval *return_value;
	// zval **return_value_ptr;
	// zval *this_ptr;
	int ht = 0;
	int retval = SUCCESS;

	
	// if (fci) {
	// 	return_value = *fci->retval_ptr_ptr;
	// 	return_value_ptr = fci->retval_ptr_ptr;
	// 	this_ptr = fci->object_ptr;
	// 	ht = fci->param_count;
	// } else {
	// 	temp_variable *ret = &EX_T(execute_data_ptr->opline->result.var);
	// 	zend_function *fbc = execute_data_ptr->function_state.function;
	// 	return_value = ret->var.ptr;
	// 	return_value_ptr = (fbc->common.fn_flags & ZEND_ACC_RETURN_REFERENCE) ? &ret->var.ptr : NULL;
	// 	this_ptr = execute_data_ptr->object;
		// ht = execute_data->opline->extended_value;
	// }	

	// char *lcname;
	// int function_name_strlen, free_lcname = 0;
	// zend_class_entry *ce = NULL;
	// internal_function_handler *ih;
	// 
	// ce = ((zend_internal_function *) execute_data_ptr->function_state.function)->scope;
	// lcname = (char *)((zend_internal_function *) execute_data_ptr->function_state.function)->function_name;
	// function_name_strlen = strlen(lcname);
	
	/* handle methodcalls correctly */
	// if (ce != NULL) {
	// 	char *tmp = (char *) emalloc(function_name_strlen + 2 + ce->name_length + 1);
	// 	memcpy(tmp, ce->name, ce->name_length);
	// 	memcpy(tmp+ce->name_length, "::", 2);
	// 	memcpy(tmp+ce->name_length+2, lcname, function_name_strlen);
	// 	lcname = tmp;
	// 	free_lcname = 1;
	// 	function_name_strlen += ce->name_length + 2;
	// 	lcname[function_name_strlen] = 0;
	// 	zend_str_tolower(lcname, function_name_strlen);
	// }

	zend_string *function_name = func->common.function_name;
	if (function_name == NULL) {
		function_name = func->op_array.function_name;
	}
	if (function_name == NULL) {
		// no function name -> skip whitelists/blacklists
		goto execute_internal_continue;
	}
		
	SDEBUG("function: [%s]/%zu", ZSTR_VAL(function_name), ZSTR_LEN(function_name)) ;

	if (SUHOSIN7_G(in_code_type) == SUHOSIN_EVAL) {
	
		if (SUHOSIN7_G(eval_whitelist) != NULL) {
			if (!zend_hash_exists(SUHOSIN7_G(eval_whitelist), function_name)) {
				suhosin_log(S_EXECUTOR|S_GETCALLER, "eval'd function not whitelisted: %s()", ZSTR_VAL(function_name));
				if (!SUHOSIN7_G(simulation)) {
				        goto execute_internal_bailout;
				} else {
					FUNCTION_SIMULATE_WARNING(ZSTR_VAL(function_name))
				}
			}
		} else if (SUHOSIN7_G(eval_blacklist) != NULL) {
			if (zend_hash_exists(SUHOSIN7_G(eval_blacklist), function_name)) {
				suhosin_log(S_EXECUTOR|S_GETCALLER, "eval'd function blacklisted: %s()", ZSTR_VAL(function_name));
				if (!SUHOSIN7_G(simulation)) {
				        goto execute_internal_bailout;
				} else {
					FUNCTION_SIMULATE_WARNING(ZSTR_VAL(function_name))
				}
			}
		}
	}
	
	if (SUHOSIN7_G(func_whitelist) != NULL) {
		if (!zend_hash_exists(SUHOSIN7_G(func_whitelist), function_name)) {
			suhosin_log(S_EXECUTOR|S_GETCALLER, "function not whitelisted: %s()", ZSTR_VAL(function_name));
			if (!SUHOSIN7_G(simulation)) {
				goto execute_internal_bailout;
			} else {
				FUNCTION_SIMULATE_WARNING(ZSTR_VAL(function_name))
			}
		}
	} else if (SUHOSIN7_G(func_blacklist) != NULL) {
		if (zend_hash_exists(SUHOSIN7_G(func_blacklist), function_name)) {
			suhosin_log(S_EXECUTOR|S_GETCALLER, "function blacklisted: %s()", ZSTR_VAL(function_name));
			if (!SUHOSIN7_G(simulation)) {
				goto execute_internal_bailout;
			} else {
				FUNCTION_SIMULATE_WARNING(ZSTR_VAL(function_name))
			}
		}
	}
	
	suhosin_internal_function_handler *ih;
	if ((ih = zend_hash_find_ptr(&ihandler_table, function_name))) {
		void *handler = execute_data->func->internal_function.handler;
		
		if (handler != ZEND_FN(display_disabled_function)) {
			retval = ih->handler(S7_IH_HANDLER_PARAM_PASSTHRU);
		}
		
	}

execute_internal_continue:
	
	if (retval == SUCCESS) {
		old_execute_internal(execute_data, return_value);
	}

	return;

execute_internal_bailout:

	if (function_name != NULL) {
		FUNCTION_WARNING(ZSTR_VAL(function_name))
	} else {
		FUNCTION_WARNING("<unknown>");
	}
	suhosin_bailout();
}
/* }}} */


/* {{{ int function_lookup(zend_extension *extension)
 */
// static int function_lookup(zend_extension *extension)
// {
// 	if (zo_set_oe_ex != NULL) {
// 		return ZEND_HASH_APPLY_STOP;
// 	}
// 
// 	if (extension->handle != NULL) {
// 	
// 		zo_set_oe_ex = (void *)DL_FETCH_SYMBOL(extension->handle, "zend_optimizer_set_oe_ex");
// 	
// 	}
// 
// 	return 0;
// }
/* }}} */


/* {{{ void suhosin_hook_execute()
 */
void suhosin_hook_execute()
{
	old_execute_ex = zend_execute_ex;
	zend_execute_ex = suhosin_execute_ex;
	
/*	old_compile_file = zend_compile_file;
	zend_compile_file = suhosin_compile_file; */

// #if ZO_COMPATIBILITY_HACK_TEMPORARY_DISABLED
// 	if (zo_set_oe_ex == NULL) {	
// 		zo_set_oe_ex = (void *)DL_FETCH_SYMBOL(NULL, "zend_optimizer_set_oe_ex");
// 	}
// 	if (zo_set_oe_ex == NULL) {	
// 		zend_llist_apply(&zend_extensions, (llist_apply_func_t)function_lookup);
// 	}
// 
// 	if (zo_set_oe_ex != NULL) {
// 		old_execute_ZO = zo_set_oe_ex(suhosin_execute_ZO);
// 	}
// #endif
	
	old_execute_internal = zend_execute_internal;
	if (old_execute_internal == NULL) {
		old_execute_internal = execute_internal;
	}
	zend_execute_internal = suhosin_execute_internal;
	
	/* register internal function handlers */
	zend_hash_init(&ihandler_table, 16, NULL, NULL, 1);
	suhosin_internal_function_handler *ih = &ihandlers[0];
	while (ih->name) {
		// SDEBUG("adding [%s]/%zu", ih->name, strlen(ih->name));
		// zend_hash_str_add_ptr(&ihandler_table, ZEND_STRL(ih->name), ih);
		zend_hash_str_add_ptr(&ihandler_table, ih->name, strlen(ih->name), ih);
		ih++;
	}
		
	
	/* Add additional protection layer, that SHOULD
	   catch ZEND_INCLUDE_OR_EVAL *before* the engine tries
	   to execute */
	if (old_zend_stream_open == NULL) {
		old_zend_stream_open = zend_stream_open_function;
	}
	zend_stream_open_function = suhosin_zend_stream_open;
	
}
/* }}} */


/* {{{ void suhosin_unhook_execute()
 */
void suhosin_unhook_execute()
{
// #if ZO_COMPATIBILITY_HACK_TEMPORARY_DISABLED
// 	if (zo_set_oe_ex) {
// 		zo_set_oe_ex(old_execute_ZO);
// 	}
// #endif

	zend_execute_ex = old_execute_ex;
		
/*	zend_compile_file = old_compile_file; */

	if (old_execute_internal == execute_internal) {
		old_execute_internal = NULL;
	}
	zend_execute_internal = old_execute_internal;
	zend_hash_clean(&ihandler_table);
	
	/* remove zend_open protection */
	zend_stream_open_function = old_zend_stream_open;
	
}
/* }}} */

// #endif // 0

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
