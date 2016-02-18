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
// static int le_suhosin7;

/* ------------------------------------------------------------------------ */
/* PERDIR CHECKS */
#define PERDIR_CHECK(lower) \
	if (!SUHOSIN7_G(lower ## _perdir) && stage == ZEND_INI_STAGE_HTACCESS) { \
		return FAILURE; \
	} 

#define LOG_PERDIR_CHECK() PERDIR_CHECK(log)
#define EXEC_PERDIR_CHECK() PERDIR_CHECK(exec)
#define MISC_PERDIR_CHECK() PERDIR_CHECK(misc)
#define GET_PERDIR_CHECK() PERDIR_CHECK(get)
#define POST_PERDIR_CHECK() PERDIR_CHECK(post)
#define COOKIE_PERDIR_CHECK() PERDIR_CHECK(cookie)
#define REQUEST_PERDIR_CHECK() PERDIR_CHECK(request)
#define UPLOAD_PERDIR_CHECK() PERDIR_CHECK(upload)
#define SQL_PERDIR_CHECK() PERDIR_CHECK(sql)

#define dohandler(handler, name, lower) \
	static ZEND_INI_MH(OnUpdate ## name ## handler) \
	{ \
		PERDIR_CHECK(lower) \
		return OnUpdate ## handler (entry, new_value, mh_arg1, mh_arg2, mh_arg3, stage); \
	} \

#define dohandlers(name, lower) \
	dohandler(Bool, name, lower) \
	dohandler(String, name, lower) \
	dohandler(Long, name, lower) \

dohandlers(Log, log)
dohandlers(Exec, exec)
dohandlers(Misc, misc)
dohandlers(Get, get)
dohandlers(Post, post)
dohandlers(Cookie, cookie)
dohandlers(Request, request)
dohandlers(Upload, upload)
dohandlers(SQL, sql)


/* ------------------------------------------------------------------------ */
#define PERDIR_CASE(l, U, name) \
	case l: \
	case U: \
		SUHOSIN7_G(name ## _perdir) = 1; \
		break;

static ZEND_INI_MH(OnUpdateSuhosin_perdir)
{
	char *tmp;

	if (SUHOSIN7_G(perdir)) {
		pefree(SUHOSIN7_G(perdir), 1);
	}
	SUHOSIN7_G(perdir) = NULL;

	/* Initialize the perdir flags */
	SUHOSIN7_G(log_perdir) = 0;
	SUHOSIN7_G(exec_perdir) = 0;
	SUHOSIN7_G(misc_perdir) = 0;
	SUHOSIN7_G(get_perdir) = 0;
	SUHOSIN7_G(post_perdir) = 0;
	SUHOSIN7_G(cookie_perdir) = 0;
	SUHOSIN7_G(request_perdir) = 0;
	SUHOSIN7_G(upload_perdir) = 0;
	SUHOSIN7_G(sql_perdir) = 0;

	if (new_value == NULL) {
		return SUCCESS;
	}
	
	tmp = SUHOSIN7_G(perdir) = pestrdup(ZSTR_VAL(new_value), 1);

	/* trim the whitespace */
	while (isspace(*tmp)) tmp++;

	/* should we deactivate perdir completely? */
	if (*tmp == 0 || *tmp == '0') {
		return SUCCESS;
	}

	/* no deactivation so check the flags */
	while (*tmp) {
		switch (*tmp) {
			PERDIR_CASE('l', 'L', log)
			PERDIR_CASE('e', 'E', exec)
			PERDIR_CASE('g', 'G', get)
			PERDIR_CASE('c', 'C', cookie)
			PERDIR_CASE('p', 'P', post)
			PERDIR_CASE('r', 'R', request)
			PERDIR_CASE('s', 'S', sql)
			PERDIR_CASE('u', 'U', upload)
			PERDIR_CASE('m', 'M', misc)
		}
		tmp++;
	}        
	return SUCCESS;
}

static void parse_list(HashTable **ht, zend_string *zlist, zend_bool lc)
{
	if (zlist == NULL) {
list_destroy:
		if (*ht) {
			zend_hash_destroy(*ht);
			FREE_HASHTABLE(*ht);
		}
		*ht = NULL;
		return;
	}

	char *list = ZSTR_VAL(zlist);
	while (*list && (*list == ' ' || *list == '\t')) list++;
	if (*list == 0) {
		goto list_destroy;
	}

	*ht = pemalloc(sizeof(HashTable), 1);
	zend_hash_init(*ht, 5, NULL, NULL, 1);
	
	char *val = estrndup(list, strlen(list));
	if (lc) {
		zend_str_tolower(val, strlen(list));
	}

	char *e = val;
	char *s = NULL;
	
	while (*e) {
		switch (*e) {
			case ' ':
			case ',':
				if (s) {
					*e = '\0';
					zend_hash_str_add_empty_element(*ht, s, e-s);
					// zend_hash_str_add(*ht, s, e-s, &dummy, sizeof(unsigned long), NULL);
					s = NULL;
				}
				break;
			default:
				if (!s) {
					s = e;
				}
				break;
		}
		e++;
	}
	if (s) {
		// zend_hash_str_add(*ht, s, e-s, &dummy, sizeof(unsigned long), NULL);
		zend_hash_str_add_empty_element(*ht, s, e-s);
	}
	efree(val);

}

#define S7_INI_MH_EXECLIST(name) \
static ZEND_INI_MH(OnUpdateSuhosin_ ## name) \
{ \
	EXEC_PERDIR_CHECK(); \
	parse_list(&SUHOSIN7_G(name), new_value, 1); \
	return SUCCESS; \
}
S7_INI_MH_EXECLIST(include_whitelist)
S7_INI_MH_EXECLIST(include_blacklist)
S7_INI_MH_EXECLIST(eval_whitelist)
S7_INI_MH_EXECLIST(eval_blacklist)
S7_INI_MH_EXECLIST(func_whitelist)
S7_INI_MH_EXECLIST(func_blacklist)

static ZEND_INI_MH(OnUpdateSuhosin_cookie_cryptlist)
{
	COOKIE_PERDIR_CHECK();
	parse_list(&SUHOSIN7_G(cookie_cryptlist), new_value, 0);
	return SUCCESS;
}

static ZEND_INI_MH(OnUpdateSuhosin_cookie_plainlist)
{
	COOKIE_PERDIR_CHECK();
	parse_list(&SUHOSIN7_G(cookie_plainlist), new_value, 0);
	return SUCCESS;
}

/* ------------------------------------------------------------------------ */

#define DEF_LOG_UPDATER(fname, varname, inistr) static ZEND_INI_MH(fname) \
{ \
	LOG_PERDIR_CHECK() \
	if (!new_value) { \
		SUHOSIN7_G(varname) = S_ALL & ~S_MEMORY; \
	} else { \
		if (is_numeric_string(ZSTR_VAL(new_value), ZSTR_LEN(new_value), NULL, NULL, 0) != IS_LONG) { \
			SUHOSIN7_G(varname) = S_ALL & ~S_MEMORY; \
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "unknown constant in %s=%s", inistr, new_value); \
			return FAILURE; \
		} \
		SUHOSIN7_G(varname) = zend_atoi(ZSTR_VAL(new_value), ZSTR_LEN(new_value)) & (~S_MEMORY) & (~S_INTERNAL); \
	} \
	return SUCCESS; \
}

DEF_LOG_UPDATER(OnUpdateSuhosin_log_file, log_file, "suhosin.log.file")
DEF_LOG_UPDATER(OnUpdateSuhosin_log_sapi, log_sapi, "suhosin.log.sapi")
DEF_LOG_UPDATER(OnUpdateSuhosin_log_stdout, log_stdout, "suhosin.log.stdout")

/* ------------------------------------------------------------------------ */

#define STD_S7_INI_ENTRY(name, default_value, modifiable, on_modify, property_name) \
	STD_PHP_INI_ENTRY(name, default_value, modifiable, on_modify, property_name, zend_suhosin7_globals, suhosin7_globals)
#define STD_S7_INI_BOOLEAN(name, default_value, modifiable, on_modify, property_name) \
	STD_PHP_INI_BOOLEAN(name, default_value, modifiable, on_modify, property_name, zend_suhosin7_globals, suhosin7_globals)
// #define STD_S7_INI_LIST(name, modifiable, )

/* {{{ PHP_INI
 */
PHP_INI_BEGIN()
	// STD_S7_INI_BOOLEAN("suhosin.protectkey",      "1", PHP_INI_SYSTEM, OnUpdateBool, protectkey, zend_suhosin7_globals, suhosin7_globals)
	// STD_S7_INI_BOOLEAN("suhosin.cookie.cryptkey",      "1", PHP_INI_SYSTEM, OnUpdateBool, protectkey, zend_suhosin7_globals, suhosin7_globals)
	// STD_S7_INI_ENTRY("suhosin.global_value",      "42", PHP_INI_ALL, OnUpdateLong, global_value, zend_suhosin7_globals, suhosin7_globals)
	// STD_S7_INI_ENTRY("suhosin.global_string", "foobar", PHP_INI_ALL, OnUpdateString, global_string, zend_suhosin7_globals, suhosin7_globals)
	
	PHP_INI_ENTRY("suhosin.perdir",					"0",	PHP_INI_SYSTEM,	OnUpdateSuhosin_perdir)
	// PHP_INI_ENTRY("suhosin.log.syslog",				NULL,	PHP_INI_PERDIR|PHP_INI_SYSTEM,	OnUpdateSuhosin_log_syslog)
	// PHP_INI_ENTRY("suhosin.log.syslog.facility",	NULL,	PHP_INI_PERDIR|PHP_INI_SYSTEM,	OnUpdateSuhosin_log_syslog_facility)
	// PHP_INI_ENTRY("suhosin.log.syslog.priority",	NULL,	PHP_INI_PERDIR|PHP_INI_SYSTEM,	OnUpdateSuhosin_log_syslog_priority)
	PHP_INI_ENTRY("suhosin.log.sapi",				"0",	PHP_INI_PERDIR|PHP_INI_SYSTEM,	OnUpdateSuhosin_log_sapi)
	PHP_INI_ENTRY("suhosin.log.stdout",				"0",	PHP_INI_PERDIR|PHP_INI_SYSTEM,	OnUpdateSuhosin_log_stdout)
	// PHP_INI_ENTRY("suhosin.log.script",				"0",	PHP_INI_PERDIR|PHP_INI_SYSTEM,	OnUpdateSuhosin_log_script)
	// PHP_INI_ENTRY("suhosin.log.script.name",		NULL,		PHP_INI_PERDIR|PHP_INI_SYSTEM,	OnUpdateSuhosin_log_scriptname)
	STD_S7_INI_BOOLEAN("suhosin.log.use-x-forwarded-for",	"0",	PHP_INI_PERDIR|PHP_INI_SYSTEM,	OnUpdateLogBool, log_use_x_forwarded_for)
	// PHP_INI_ENTRY("suhosin.log.phpscript",			"0",	PHP_INI_PERDIR|PHP_INI_SYSTEM,	OnUpdateSuhosin_log_phpscript)
	// STD_S7_INI_ENTRY("suhosin.log.phpscript.name",	NULL,	PHP_INI_PERDIR|PHP_INI_SYSTEM,	OnUpdateLogString, log_phpscriptname)
	PHP_INI_ENTRY("suhosin.log.file",				"0",	PHP_INI_PERDIR|PHP_INI_SYSTEM,	OnUpdateSuhosin_log_file)
	STD_S7_INI_ENTRY("suhosin.log.file.name",		NULL,	PHP_INI_PERDIR|PHP_INI_SYSTEM,	OnUpdateLogString, log_filename)
	STD_S7_INI_BOOLEAN("suhosin.log.file.time",		"1",	PHP_INI_PERDIR|PHP_INI_SYSTEM,	OnUpdateLogBool, log_file_time)
	// STD_S7_INI_BOOLEAN("suhosin.log.phpscript.is_safe",	"0",	PHP_INI_PERDIR|PHP_INI_SYSTEM,	OnUpdateLogBool, log_phpscript_is_safe)

	// STD_S7_INI_ENTRY("suhosin.executor.include.max_traversal",		"0",	PHP_INI_PERDIR|PHP_INI_SYSTEM,	OnUpdateExecLong, executor_include_max_traversal)
	PHP_INI_ENTRY("suhosin.executor.include.whitelist",	NULL,	PHP_INI_PERDIR|PHP_INI_SYSTEM,	OnUpdateSuhosin_include_whitelist)
	PHP_INI_ENTRY("suhosin.executor.include.blacklist",	NULL,	PHP_INI_PERDIR|PHP_INI_SYSTEM,	OnUpdateSuhosin_include_blacklist)
	// STD_S7_INI_BOOLEAN("suhosin.executor.include.allow_writable_files",	"1",		PHP_INI_PERDIR|PHP_INI_SYSTEM,	OnUpdateExecBool, executor_include_allow_writable_files)
	PHP_INI_ENTRY("suhosin.executor.eval.whitelist",	NULL,	PHP_INI_PERDIR|PHP_INI_SYSTEM,	OnUpdateSuhosin_eval_whitelist)
	PHP_INI_ENTRY("suhosin.executor.eval.blacklist",	NULL,	PHP_INI_PERDIR|PHP_INI_SYSTEM,	OnUpdateSuhosin_eval_blacklist)
	PHP_INI_ENTRY("suhosin.executor.func.whitelist",	NULL,	PHP_INI_PERDIR|PHP_INI_SYSTEM,	OnUpdateSuhosin_func_whitelist)
	PHP_INI_ENTRY("suhosin.executor.func.blacklist",	NULL,	PHP_INI_PERDIR|PHP_INI_SYSTEM,	OnUpdateSuhosin_func_blacklist)
	// STD_S7_INI_BOOLEAN("suhosin.executor.disable_eval",	"0",	PHP_INI_PERDIR|PHP_INI_SYSTEM,	OnUpdateExecBool, executor_disable_eval)
	// STD_S7_INI_BOOLEAN("suhosin.executor.disable_emodifier",	"0",	PHP_INI_PERDIR|PHP_INI_SYSTEM,	OnUpdateExecBool, executor_disable_emod)
	// 
	// STD_S7_INI_BOOLEAN("suhosin.executor.allow_symlink",	"0",		PHP_INI_PERDIR|PHP_INI_SYSTEM,	OnUpdateExecBool, executor_allow_symlink)
	// STD_S7_INI_ENTRY("suhosin.executor.max_depth",		"750",		PHP_INI_PERDIR|PHP_INI_SYSTEM,	OnUpdateExecLong, max_execution_depth)
	// 
	// 
	// STD_S7_INI_BOOLEAN("suhosin.multiheader",			"0",	PHP_INI_PERDIR|PHP_INI_SYSTEM,	OnUpdateMiscBool, allow_multiheader)
	// STD_S7_INI_ENTRY("suhosin.mail.protect",			"0",	PHP_INI_PERDIR|PHP_INI_SYSTEM,	OnUpdateMiscLong, mailprotect)
	// STD_S7_INI_ENTRY("suhosin.memory_limit",			"0",	PHP_INI_PERDIR|PHP_INI_SYSTEM,	OnUpdateMiscLong, memory_limit)
	// STD_S7_INI_BOOLEAN("suhosin.simulation",			"0",	PHP_INI_PERDIR|PHP_INI_SYSTEM,	OnUpdateMiscBool, simulation)
	// STD_S7_INI_ENTRY("suhosin.filter.action",			NULL,	PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateMiscString, filter_action)
	// 
	// STD_S7_INI_BOOLEAN("suhosin.protectkey",			"1",	PHP_INI_SYSTEM,	OnUpdateBool, protectkey)
	// STD_S7_INI_BOOLEAN("suhosin.coredump",				"0",	PHP_INI_SYSTEM,	OnUpdateBool, coredump)
	// STD_S7_INI_BOOLEAN("suhosin.stealth",				"1",	PHP_INI_SYSTEM,	OnUpdateBool, stealth)
	// STD_S7_INI_BOOLEAN("suhosin.apc_bug_workaround",	"0",	PHP_INI_SYSTEM,	OnUpdateBool, apc_bug_workaround)
	// STD_S7_INI_BOOLEAN("suhosin.disable.display_errors",	"0",	PHP_INI_SYSTEM,	OnUpdate_disable_display_errors, disable_display_errors)
	
	
	// 
	// STD_S7_INI_ENTRY("suhosin.request.max_vars",	"1000",	PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateRequestLong, max_request_variables)
	// STD_S7_INI_ENTRY("suhosin.request.max_varname_length", "64", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateRequestLong, max_varname_length)
	// STD_S7_INI_ENTRY("suhosin.request.max_value_length", "1000000", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateRequestLong, max_value_length)
	// STD_S7_INI_ENTRY("suhosin.request.max_array_depth", "50", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateRequestLong, max_array_depth)
	// STD_S7_INI_ENTRY("suhosin.request.max_totalname_length", "256", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateRequestLong, max_totalname_length)
	// STD_S7_INI_ENTRY("suhosin.request.max_array_index_length", "64", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateRequestLong, max_array_index_length)
	// STD_S7_INI_ENTRY("suhosin.request.array_index_whitelist", "", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateRequestString, array_index_whitelist)
	// STD_S7_INI_ENTRY("suhosin.request.array_index_blacklist", "'\"+<>;()", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateRequestString, array_index_blacklist)
	// STD_S7_INI_ENTRY("suhosin.request.disallow_nul", "1", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateRequestBool, disallow_nul)
	// STD_S7_INI_ENTRY("suhosin.request.disallow_ws", "0", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateRequestBool, disallow_ws)
	// 
	// STD_S7_INI_ENTRY("suhosin.cookie.max_vars", "100", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateCookieLong, max_cookie_vars)
	// STD_S7_INI_ENTRY("suhosin.cookie.max_name_length", "64", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateCookieLong, max_cookie_name_length)
	// STD_S7_INI_ENTRY("suhosin.cookie.max_totalname_length", "256", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateCookieLong, max_cookie_totalname_length)
	// STD_S7_INI_ENTRY("suhosin.cookie.max_value_length", "10000", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateCookieLong, max_cookie_value_length)
	// STD_S7_INI_ENTRY("suhosin.cookie.max_array_depth", "50", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateCookieLong, max_cookie_array_depth)
	// STD_S7_INI_ENTRY("suhosin.cookie.max_array_index_length", "64", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateCookieLong, max_cookie_array_index_length)
	// STD_S7_INI_ENTRY("suhosin.cookie.disallow_nul", "1", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateCookieBool, disallow_cookie_nul)
	// STD_S7_INI_ENTRY("suhosin.cookie.disallow_ws", "1", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateCookieBool, disallow_cookie_ws)
	// 
	// STD_S7_INI_ENTRY("suhosin.get.max_vars", "100", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateGetLong, max_get_vars)
	// STD_S7_INI_ENTRY("suhosin.get.max_name_length", "64", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateGetLong, max_get_name_length)
	// STD_S7_INI_ENTRY("suhosin.get.max_totalname_length", "256", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateGetLong, max_get_totalname_length)
	// STD_S7_INI_ENTRY("suhosin.get.max_value_length", "512", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateGetLong, max_get_value_length)
	// STD_S7_INI_ENTRY("suhosin.get.max_array_depth", "50", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateGetLong, max_get_array_depth)
	// STD_S7_INI_ENTRY("suhosin.get.max_array_index_length", "64", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateGetLong, max_get_array_index_length)
	// STD_S7_INI_ENTRY("suhosin.get.disallow_nul", "1", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateGetBool, disallow_get_nul)
	// STD_S7_INI_ENTRY("suhosin.get.disallow_ws", "0", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateGetBool, disallow_get_ws)
	// 
	// STD_S7_INI_ENTRY("suhosin.post.max_vars", "1000", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdatePostLong, max_post_vars)
	// STD_S7_INI_ENTRY("suhosin.post.max_name_length", "64", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdatePostLong, max_post_name_length)
	// STD_S7_INI_ENTRY("suhosin.post.max_totalname_length", "256", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdatePostLong, max_post_totalname_length)
	// STD_S7_INI_ENTRY("suhosin.post.max_value_length", "1000000", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdatePostLong, max_post_value_length)
	// STD_S7_INI_ENTRY("suhosin.post.max_array_depth", "50", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdatePostLong, max_post_array_depth)
	// STD_S7_INI_ENTRY("suhosin.post.max_array_index_length", "64", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdatePostLong, max_post_array_index_length)
	// STD_S7_INI_ENTRY("suhosin.post.disallow_nul", "1", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdatePostBool, disallow_post_nul)
	// STD_S7_INI_ENTRY("suhosin.post.disallow_ws", "0", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdatePostBool, disallow_post_ws)
	// 
	// STD_S7_INI_ENTRY("suhosin.upload.max_uploads", "25", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateUploadLong, upload_limit)
	// STD_S7_INI_ENTRY("suhosin.upload.max_newlines", "100", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateUploadLong, upload_max_newlines)
	// STD_S7_INI_ENTRY("suhosin.upload.disallow_elf", "1", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateUploadBool, upload_disallow_elf)
	// STD_S7_INI_ENTRY("suhosin.upload.disallow_binary", "0", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateUploadBool, upload_disallow_binary)
	// STD_S7_INI_ENTRY("suhosin.upload.remove_binary", "0", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateUploadBool, upload_remove_binary)
#ifdef SUHOSIN7_EXPERIMENTAL
	// STD_S7_INI_BOOLEAN("suhosin.upload.allow_utf8", "0", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateUploadBool, upload_allow_utf8)
#endif
	// STD_S7_INI_ENTRY("suhosin.upload.verification_script", NULL, PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateUploadString, upload_verification_script)


	// STD_S7_INI_BOOLEAN("suhosin.sql.bailout_on_error",	"0",		PHP_INI_PERDIR|PHP_INI_SYSTEM,	OnUpdateSQLBool, sql_bailout_on_error)
	// STD_S7_INI_ENTRY("suhosin.sql.user_prefix", NULL, PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateSQLString, sql_user_prefix)
	// STD_S7_INI_ENTRY("suhosin.sql.user_postfix", NULL, PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateSQLString, sql_user_postfix)
	// STD_S7_INI_ENTRY("suhosin.sql.user_match", NULL, PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateSQLString, sql_user_match)
	// STD_S7_INI_ENTRY("suhosin.sql.comment", "0", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateSQLLong, sql_comment)
	// STD_S7_INI_ENTRY("suhosin.sql.opencomment", "0", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateSQLLong, sql_opencomment)
	// STD_S7_INI_ENTRY("suhosin.sql.multiselect", "0", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateSQLLong, sql_mselect)
	// STD_S7_INI_ENTRY("suhosin.sql.union", "0", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateSQLLong, sql_union)

#ifdef HAVE_PHP_SESSION
	// STD_S7_INI_BOOLEAN("suhosin.session.encrypt",		"1",		PHP_INI_PERDIR|PHP_INI_SYSTEM,	OnUpdateMiscBool, session_encrypt)
	// STD_S7_INI_ENTRY("suhosin.session.cryptkey", "", PHP_INI_ALL, OnUpdateMiscString, session_cryptkey)
	// STD_S7_INI_BOOLEAN("suhosin.session.cryptua",		"0",		PHP_INI_PERDIR|PHP_INI_SYSTEM,	OnUpdateMiscBool, session_cryptua)
	// STD_S7_INI_BOOLEAN("suhosin.session.cryptdocroot",		"1",		PHP_INI_PERDIR|PHP_INI_SYSTEM,	OnUpdateMiscBool, session_cryptdocroot)
	// STD_S7_INI_ENTRY("suhosin.session.cryptraddr", "0", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateMiscLong, session_cryptraddr)	
	// STD_S7_INI_ENTRY("suhosin.session.checkraddr", "0", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateMiscLong, session_checkraddr)	
	// STD_S7_INI_ENTRY("suhosin.session.max_id_length", "128", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateMiscLong, session_max_id_length)
#else /* HAVE_PHP_SESSION */
#warning BUILDING SUHOSIN WITHOUT SESSION SUPPORT. THIS IS A BAD IDEA!
#ifndef SUHOSIN_WITHOUT_SESSION
#error Please recompile with -DSUHOSIN_WITHOUT_SESSION if you really know what you are doing.
#endif
#endif /* HAVE_PHP_SESSION */


	// STD_S7_INI_BOOLEAN("suhosin.cookie.encrypt",		"0",		PHP_INI_PERDIR|PHP_INI_SYSTEM,	OnUpdateCookieBool, cookie_encrypt)
	// STD_S7_INI_ENTRY("suhosin.cookie.cryptkey", "", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateCookieString, cookie_cryptkey)
	// STD_S7_INI_BOOLEAN("suhosin.cookie.cryptua",		"1",		PHP_INI_PERDIR|PHP_INI_SYSTEM,	OnUpdateCookieBool, cookie_cryptua)
	// STD_S7_INI_BOOLEAN("suhosin.cookie.cryptdocroot",		"1",		PHP_INI_PERDIR|PHP_INI_SYSTEM,	OnUpdateCookieBool, cookie_cryptdocroot)
	// STD_S7_INI_ENTRY("suhosin.cookie.cryptraddr", "0", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateCookieLong, cookie_cryptraddr)	
	// STD_S7_INI_ENTRY("suhosin.cookie.checkraddr", "0", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateCookieLong, cookie_checkraddr)	
	PHP_INI_ENTRY("suhosin.cookie.cryptlist",	NULL,		PHP_INI_PERDIR|PHP_INI_SYSTEM,	OnUpdateSuhosin_cookie_cryptlist)
	PHP_INI_ENTRY("suhosin.cookie.plainlist",	NULL,		PHP_INI_PERDIR|PHP_INI_SYSTEM,	OnUpdateSuhosin_cookie_plainlist)
	// 
	// STD_S7_INI_BOOLEAN("suhosin.server.encode", "1", PHP_INI_SYSTEM, OnUpdateBool, server_encode)
	// STD_S7_INI_BOOLEAN("suhosin.server.strip", "1", PHP_INI_SYSTEM, OnUpdateBool, server_strip)
	// 
	// STD_S7_INI_ENTRY("suhosin.rand.seedingkey", "", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateMiscString, seedingkey)
	// STD_S7_INI_BOOLEAN("suhosin.rand.reseed_every_request", "0", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateMiscBool, reseed_every_request)
	// STD_S7_INI_BOOLEAN("suhosin.srand.ignore", "1", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateMiscBool, srand_ignore)
	// STD_S7_INI_BOOLEAN("suhosin.mt_srand.ignore", "1", PHP_INI_SYSTEM|PHP_INI_PERDIR, OnUpdateMiscBool, mt_srand_ignore)


PHP_INI_END()
/* }}} */

/* {{{ suhosin_getenv
 */
char *suhosin_getenv(char *name, size_t name_len)
{
	if (sapi_module.getenv) {
		char *value, *tmp = sapi_module.getenv(name, name_len);
		if (tmp) {
			value = estrdup(tmp);
		} else {
			return NULL;
		}
		return value;
	} else {
		/* fallback to the system's getenv() function */
		char *tmp;
		
		name = estrndup(name, name_len);
		tmp = getenv(name);
		efree(name);
		if (tmp) {
			return estrdup(tmp);
		}
	}
	return NULL;
}
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
	SDEBUG("(MINIT)");
	ZEND_INIT_MODULE_GLOBALS(suhosin7, php_suhosin7_init_globals, NULL);

	/* only register constants if they have not previously been registered by a patched PHP */
	// if (zend_hash_str_exists(EG(zend_constants), "S_MEMORY", sizeof("S_MEMORY"))==0) {
		REGISTER_MAIN_LONG_CONSTANT("S_MEMORY", S_MEMORY, CONST_PERSISTENT | CONST_CS);
		REGISTER_MAIN_LONG_CONSTANT("S_VARS", S_VARS, CONST_PERSISTENT | CONST_CS);
		REGISTER_MAIN_LONG_CONSTANT("S_FILES", S_FILES, CONST_PERSISTENT | CONST_CS);
		REGISTER_MAIN_LONG_CONSTANT("S_INCLUDE", S_INCLUDE, CONST_PERSISTENT | CONST_CS);
		REGISTER_MAIN_LONG_CONSTANT("S_SQL", S_SQL, CONST_PERSISTENT | CONST_CS);
		REGISTER_MAIN_LONG_CONSTANT("S_EXECUTOR", S_EXECUTOR, CONST_PERSISTENT | CONST_CS);
		REGISTER_MAIN_LONG_CONSTANT("S_MAIL", S_MAIL, CONST_PERSISTENT | CONST_CS);
		REGISTER_MAIN_LONG_CONSTANT("S_SESSION", S_SESSION, CONST_PERSISTENT | CONST_CS);
		REGISTER_MAIN_LONG_CONSTANT("S_MISC", S_MISC, CONST_PERSISTENT | CONST_CS);
		REGISTER_MAIN_LONG_CONSTANT("S_INTERNAL", S_INTERNAL, CONST_PERSISTENT | CONST_CS);
		REGISTER_MAIN_LONG_CONSTANT("S_ALL", S_ALL, CONST_PERSISTENT | CONST_CS);
	// }

	REGISTER_INI_ENTRIES();
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION
 */
PHP_MSHUTDOWN_FUNCTION(suhosin7)
{
	SDEBUG("(MSHUTDOWN)");
	UNREGISTER_INI_ENTRIES();
	return SUCCESS;
}
/* }}} */

/* Remove if there's nothing to do at request start */
/* {{{ PHP_RINIT_FUNCTION
 */
PHP_RINIT_FUNCTION(suhosin7)
{
	SDEBUG("(RINIT)");
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
	SDEBUG("(RSHUTDOWN)");

	return SUCCESS;
}
/* }}} */

/* {{{ suhosin_ini_displayer(PHP_INI_ENTRY *ini_entry, int type)
 */
static void suhosin_ini_displayer(php_ini_entry *ini_entry, int type)
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
		PUTS("Copyright (c) 2007-2016 SektionEins GmbH\n");
	} else {
		PUTS("Copyright (c) 2006-2007 <a href=\"http://www.hardened-php.net/\">Hardened-PHP Project</a><br />\n");
		PUTS("Copyright (c) 2007-2016 <a href=\"http://www.sektioneins.de/\">SektionEins GmbH</a>\n");
	}
	php_info_print_box_end();

	if (SUHOSIN7_G(protectkey)) {
	    php_ini_entry *i;

		if ((i=zend_hash_str_find_ptr(EG(ini_directives), ZEND_STRL("suhosin.cookie.cryptkey")))) {
			i->displayer = suhosin_ini_displayer;
		}
		if ((i=zend_hash_str_find_ptr(EG(ini_directives), ZEND_STRL("suhosin.session.cryptkey")))) {
			i->displayer = suhosin_ini_displayer;
		}
		if ((i=zend_hash_str_find_ptr(EG(ini_directives), ZEND_STRL("suhosin.rand.seedingkey")))) {
			i->displayer = suhosin_ini_displayer;
		}
	}

	DISPLAY_INI_ENTRIES();

	if (SUHOSIN7_G(protectkey)) {
		php_ini_entry *i;
		
		if ((i=zend_hash_str_find_ptr(EG(ini_directives), ZEND_STRL("suhosin.cookie.cryptkey")))) {
			i->displayer = NULL;
		}
		if ((i=zend_hash_str_find_ptr(EG(ini_directives), ZEND_STRL("suhosin.session.cryptkey")))) {
			i->displayer = NULL;
		}
		if ((i=zend_hash_str_find_ptr(EG(ini_directives), ZEND_STRL("suhosin.rand.seedingkey")))) {
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
