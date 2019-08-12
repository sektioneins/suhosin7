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

#pragma once

extern zend_module_entry suhosin7_module_entry;
#define phpext_suhosin7_ptr &suhosin7_module_entry

#define SUHOSIN7_EXT_VERSION  "0.10.0dev"

#if PHP_VERSION_ID < 70000 
#error Suhosin7 works with PHP 7.x only! Looking for Suhosin for PHP 5.x? Take a look at https://www.suhosin.org/
#endif

#ifdef PHP_WIN32
#	define SUHOSIN7_API __declspec(dllexport)
#elif defined(__GNUC__) && __GNUC__ >= 4
#	define SUHOSIN7_API __attribute__ ((visibility("default")))
#else
#	define SUHOSIN7_API
#endif

#ifdef ZTS
#include "TSRM.h"
#endif

/* -------------- */

#define SUHOSIN_LOG "/tmp/suhosin_log.txt"

#ifdef PHP_WIN32
#define SDEBUG
#else

#ifdef SUHOSIN7_DEBUG
// #define SDEBUG(msg...) \
	// {FILE *f;f=fopen(SUHOSIN_LOG, "a+");if(f){fprintf(f,"[%u] ",getpid());fprintf(f, msg);fprintf(f,"\n");fclose(f);}}
#define SDEBUG(msg...) \
	{FILE *f;f=fopen(SUHOSIN_LOG, "a+");if(f){fprintf(f,"[%u] %s:%u %s #> ",getpid(), __FILE__, __LINE__, __func__);fprintf(f, msg);fprintf(f,"\n");fclose(f);}}
#else
#define SDEBUG(msg...)
#endif
#endif

/* -------------- */

#define BYTE unsigned char       /* 8 bits  */
#define WORD unsigned int          /* 32 bits */

// PHP_MINIT_FUNCTION(suhosin);
// PHP_MSHUTDOWN_FUNCTION(suhosin);
// PHP_RINIT_FUNCTION(suhosin);
// PHP_RSHUTDOWN_FUNCTION(suhosin);
// PHP_MINFO_FUNCTION(suhosin);

#include "ext/standard/basic_functions.h"
#ifdef HAVE_PHP_SESSION
#include "ext/session/php_session.h"
#endif

static inline int suhosin_is_protected_varname(char *var, int var_len)
{
	switch (var_len) {
		case 18:
		if (memcmp(var, "HTTP_RAW_POST_DATA", 18)==0) goto protected_varname;
		break;
		case 17:
		if (memcmp(var, "HTTP_SESSION_VARS", 17)==0) goto protected_varname;
		break;
		case 16:
		if (memcmp(var, "HTTP_SERVER_VARS", 16)==0) goto protected_varname;
		if (memcmp(var, "HTTP_COOKIE_VARS", 16)==0) goto protected_varname;
		break;
		case 15:
		if (memcmp(var, "HTTP_POST_FILES", 15)==0) goto protected_varname;
		break;
		case 14:
		if (memcmp(var, "HTTP_POST_VARS", 14)==0) goto protected_varname;
		break;
		case 13:
		if (memcmp(var, "HTTP_GET_VARS", 13)==0) goto protected_varname;
		if (memcmp(var, "HTTP_ENV_VARS", 13)==0) goto protected_varname;
		break;
		case 8:
		if (memcmp(var, "_SESSION", 8)==0) goto protected_varname;
		if (memcmp(var, "_REQUEST", 8)==0) goto protected_varname;
		break;
		case 7:
		if (memcmp(var, "GLOBALS", 7)==0) goto protected_varname;
		if (memcmp(var, "_COOKIE", 7)==0) goto protected_varname;
		if (memcmp(var, "_SERVER", 7)==0) goto protected_varname;
		break;
		case 6:
		if (memcmp(var, "_FILES", 6)==0) goto protected_varname;
		break;
		case 5:
		if (memcmp(var, "_POST", 5)==0) goto protected_varname;
		break;
		case 4:
		if (memcmp(var, "_ENV", 4)==0) goto protected_varname;
		if (memcmp(var, "_GET", 4)==0) goto protected_varname;
		break;
	}

	return 0;
protected_varname:
	return 1;
}



ZEND_BEGIN_MODULE_GLOBALS(suhosin7)
	zend_bool	protectkey;

	zend_bool	simulation;
	// zend_bool stealth;
	// zend_bool	already_scanned;
	zend_bool	abort_request;
	//

	/* executor */
	zend_ulong in_code_type;
	zend_bool executor_allow_symlink;
	long execution_depth;
	long max_execution_depth;
	long executor_include_max_traversal;
	zend_bool executor_include_allow_writable_files;
	// char *filter_action;


	HashTable *include_whitelist;
	HashTable *include_blacklist;

	HashTable *func_whitelist;
	HashTable *func_blacklist;
	HashTable *eval_whitelist;
	HashTable *eval_blacklist;

	zend_bool executor_disable_eval;
	zend_bool executor_disable_emod;


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
	zend_long  upload_max_newlines;
	zend_long  upload_limit;
	zend_long  num_uploads;
	zend_bool  upload_disallow_elf;
	zend_bool  upload_disallow_binary;
	zend_bool  upload_remove_binary;
#ifdef SUHOSIN7_EXPERIMENTAL
	zend_bool  upload_allow_utf8;
#endif
	char *upload_verification_script;

	zend_bool  no_more_variables;
	zend_bool  no_more_get_variables;
	zend_bool  no_more_post_variables;
	zend_bool  no_more_cookie_variables;
	zend_bool  no_more_uploads;

	/*	session */
#ifdef HAVE_PHP_SESSION
	void *s_module;
	void *s_original_mod;
	int (*old_s_read)(PS_READ_ARGS);
	int (*old_s_write)(PS_WRITE_ARGS);
	int (*old_s_destroy)(PS_DESTROY_ARGS);
#endif

	/* encryption */
	BYTE fi[24],ri[24];
	WORD fkey[120];
	WORD rkey[120];

	zend_bool	session_encrypt;
	char*	session_cryptkey;
	zend_bool	session_cryptua;
	zend_bool	session_cryptdocroot;
	long		session_cryptraddr;
	long		session_checkraddr;

	long	session_max_id_length;

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

	/* misc */
	zend_bool	coredump;
	// zend_bool	apc_bug_workaround;
	// zend_bool       do_not_scan;
	//
	zend_bool	server_encode;
	zend_bool	server_strip;
	//
	zend_bool	disable_display_errors;

	/* random number generator */
	php_uint32   r_state[625];
	php_uint32   *r_next;
	int          r_left;
	zend_bool    srand_ignore;
	zend_bool    mt_srand_ignore;
	php_uint32   mt_state[625];
	php_uint32   *mt_next;
	int          mt_left;

	char         *seedingkey;
	zend_bool    reseed_every_request;
	//
	zend_bool r_is_seeded;
	zend_bool mt_is_seeded;


/*	memory_limit */
	zend_long	memory_limit;
	zend_long 	hard_memory_limit;




	/* PERDIR Handling */
	// char *perdir;
	zend_bool log_perdir;
	zend_bool exec_perdir;
	zend_bool get_perdir;
	zend_bool post_perdir;
	zend_bool cookie_perdir;
	zend_bool request_perdir;
	zend_bool upload_perdir;
	zend_bool sql_perdir;
	zend_bool misc_perdir;

	/*	log */
	zend_bool log_use_x_forwarded_for;
	// long	log_syslog;
	// long	log_syslog_facility;
	// long	log_syslog_priority;
	// long	log_script;
	long	log_sapi;
	long	log_stdout;
	// char	*log_scriptname;
	// long	log_phpscript;
	// char	*log_phpscriptname;
	// zend_bool log_phpscript_is_safe;
	long	log_file;
	char	*log_filename;
	zend_bool log_file_time;

	/*	header handler */
	zend_bool allow_multiheader;

	/*	mailprotect */
	// long	mailprotect;

	/*  sqlprotect */
	// zend_bool sql_bailout_on_error;
	// char *sql_user_prefix;
	// char *sql_user_postfix;
	// char *sql_user_match;
	// long sql_comment;
	// long sql_opencomment;
	// long sql_union;
	// long sql_mselect;

	// int (*old_php_body_write)(const char *str, unsigned int str_length);

ZEND_END_MODULE_GLOBALS(suhosin7)

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

/* functions */

// unsigned int suhosin_input_filter(int arg, char *var, char **val, size_t val_len, size_t *new_val_len);
// unsigned int suhosin_input_filter_wrapper(int arg, char *var, char **val, size_t val_len, size_t *new_val_len);
SUHOSIN7_API void suhosin_log(int loglevel, char *fmt, ...);
// extern unsigned int (*orig_input_filter)(int arg, char *var, char **val, size_t val_len, size_t *new_val_len);
char *suhosin_getenv(char *name, size_t name_len);

// hooks
void suhosin_hook_memory_limit();
void suhosin_hook_treat_data();
void suhosin_hook_input_filter();
void suhosin_hook_register_server_variables();
void suhosin_hook_header_handler();
void suhosin_unhook_header_handler();
void suhosin_hook_execute();
// void suhosin_hook_sha256();
void suhosin_hook_ex_imp();

#ifdef HAVE_PHP_SESSION
void suhosin_hook_session();
#endif

void suhosin_hook_post_handlers();

// ifilter.c
void suhosin_normalize_varname(char *varname);
size_t suhosin_strnspn(const char *input, size_t n, const char *accept);
size_t suhosin_strncspn(const char *input, size_t n, const char *reject);

// cookiecrypt.c
char *suhosin_cookie_decryptor(char *raw_cookie);
zend_string *suhosin_encrypt_single_cookie(char *name, int name_len, char *value, int value_len, char *key);
char *suhosin_decrypt_single_cookie(char *name, int name_len, char *value, int value_len, char *key, char **out);

// crypt.c
zend_string *suhosin_encrypt_string(char *str, int len, char *var, int vlen, char *key);
zend_string *suhosin_decrypt_string(char *str, int padded_len, char *var, int vlen, char *key, int check_ra);
char *suhosin_generate_key(char *key, zend_bool ua, zend_bool dr, long raddr, char *cryptkey);
#define S7_GENERATE_KEY(type, keyvar) suhosin_generate_key(SUHOSIN7_G(type ## _cryptkey), SUHOSIN7_G(type ## _cryptua), SUHOSIN7_G(type ## _cryptdocroot), SUHOSIN7_G(type ## _cryptraddr), (char *)keyvar);

// aes.c
void suhosin_aes_gentables();
void suhosin_aes_gkey(int nb,int nk,char *key);
void suhosin_aes_encrypt(char *buff);
void suhosin_aes_decrypt(char *buff);


//

static inline void suhosin_bailout()
{
	if (!SUHOSIN7_G(simulation)) {
		zend_bailout();
	}
}

static inline char *suhosin_get_active_function_name() {
	char *fn = (char *)get_active_function_name();
	if (fn == NULL) {
		return "unknown";
	}
	return fn;
}

#ifdef SUHOSIN_STRCASESTR
char *suhosin_strcasestr(char *haystack, char *needle);
#else
#define suhosin_strcasestr(a, b) strcasestr(a, b)
#endif


/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
