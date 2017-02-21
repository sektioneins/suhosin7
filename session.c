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
#include "SAPI.h"
#include "php_ini.h"
#include "zend_smart_str.h"
#include "ext/standard/php_var.h"
#include <fcntl.h>

#include "php_suhosin7.h"

#include "ext/hash/php_hash.h"

#ifdef HAVE_PHP_SESSION
#include "ext/session/php_session.h"

#ifdef ZTS
static ts_rsrc_id session_globals_id = 0;
#define SESSION_G(v) ZEND_TSRMG(session_globals_id, php_ps_globals *, v)
# ifdef COMPILE_DL_SESSION
ZEND_TSRMLS_CACHE_EXTERN();
# endif
#else
static php_ps_globals *session_globals = NULL;
#define SESSION_G(v) (ps_globals.v)
#endif

#define COND_DUMB_SH key == NULL || ZSTR_LEN(key) == 0 || ZSTR_VAL(key)[0] == 0 \
	|| ZSTR_LEN(key) > SUHOSIN7_G(session_max_id_length) \
	|| ((mod_data == NULL || *mod_data == NULL) && !SESSION_G(mod_user_implemented))

static void suhosin_send_cookie()
{
	int  * session_send_cookie = &SESSION_G(send_cookie);
	char * base;
	zend_ini_entry *ini_entry;

	/* The following is requires to be 100% compatible to PHP
	   versions where the hash extension is not available by default */
	if ((ini_entry = zend_hash_str_find_ptr(EG(ini_directives), ZEND_STRL("session.hash_bits_per_character"))) != NULL) {
#ifndef ZTS
		base = (char *) ini_entry->mh_arg2;
#else
		base = (char *) ts_resource(*((int *) ini_entry->mh_arg2));
#endif
		session_send_cookie = (int *) (base+(size_t) ini_entry->mh_arg1+sizeof(long));
	}
	*session_send_cookie = 1;
}



static ZEND_INI_MH((*old_OnUpdateSaveHandler)) = NULL;
static int (*old_SessionRINIT)(INIT_FUNC_ARGS) = NULL;

static int suhosin_hook_s_read(PS_READ_ARGS)
{
	zend_string *new_key = key;

	/* protect session vars */
/*  if (SESSION_G(http_session_vars) && SESSION_G(http_session_vars)->type == IS_ARRAY) {
		SESSION_G(http_session_vars)->refcount++;
	}*/

	/* protect dumb session handlers */
	if (COND_DUMB_SH) {
regenerate:
		SDEBUG("regenerating key. old key was %s", key ? ZSTR_VAL(key) : "<NULL>");
		zend_string_release(SESSION_G(id));
		new_key = SESSION_G(id) = SESSION_G(mod)->s_create_sid(&SESSION_G(mod_data));
		suhosin_send_cookie();
	} else if (ZSTR_LEN(key) > SUHOSIN7_G(session_max_id_length)) {
		suhosin_log(S_SESSION, "session id ('%s') exceeds maximum length - regenerating", ZSTR_VAL(key));
		if (!SUHOSIN7_G(simulation)) {
			goto regenerate;
		}
	}

	int r = SUHOSIN7_G(old_s_read)(mod_data, new_key, val, maxlifetime);

	if (r == SUCCESS && SUHOSIN7_G(session_encrypt) && val != NULL && *val != NULL && ZSTR_LEN(*val)) {
		char cryptkey[33];

		// SUHOSIN7_G(do_not_scan) = 1;
		S7_GENERATE_KEY(session, cryptkey);

		zend_string *orig_val = *val;
		*val = suhosin_decrypt_string(ZSTR_VAL(*val), ZSTR_LEN(*val), "", 0, (char *)cryptkey, SUHOSIN7_G(session_checkraddr));
		// SUHOSIN7_G(do_not_scan) = 0;
		if (*val == NULL) {
			*val = ZSTR_EMPTY_ALLOC();
		}
		zend_string_release(orig_val);
	}

	return r;
}

static int suhosin_hook_s_write(PS_WRITE_ARGS)
{
	/* protect dumb session handlers */
	if (COND_DUMB_SH) {
		return FAILURE;
	}

	if (ZSTR_LEN(val) > 0 && SUHOSIN7_G(session_encrypt)) {
		char cryptkey[33];
		// SUHOSIN7_G(do_not_scan) = 1;
		S7_GENERATE_KEY(session, cryptkey);

		zend_string *v = suhosin_encrypt_string(ZSTR_VAL(val), ZSTR_LEN(val), "", 0, cryptkey);

		// SUHOSIN7_G(do_not_scan) = 0;
		return SUHOSIN7_G(old_s_write)(mod_data, key, v, maxlifetime);
	}

	return SUHOSIN7_G(old_s_write)(mod_data, key, val, maxlifetime);

// return_write:
	/* protect session vars */
/*  if (SESSION_G(http_session_vars) && SESSION_G(http_session_vars)->type == IS_ARRAY) {
		if (SESSION_G(http_session_vars)->refcount==1) {
			nullify = 1;
		}
		zval_ptr_dtor(&SESSION_G(http_session_vars));
		if (nullify) {
			suhosin_log(S_SESSION, "possible session variables double free attack stopped");
			SESSION_G(http_session_vars) = NULL;
		}
	}*/

	// return r;
}

static int suhosin_hook_s_destroy(PS_DESTROY_ARGS)
{
	/* protect dumb session handlers */
	if (COND_DUMB_SH) {
		return FAILURE;
	}

	return SUHOSIN7_G(old_s_destroy)(mod_data, key);
}

static void suhosin_hook_session_module()
{
	ps_module *old_mod = SESSION_G(mod);
	ps_module *mod;

	if (old_mod == NULL || SUHOSIN7_G(s_module) == old_mod) {
		return;
	}

	if (SUHOSIN7_G(s_module) == NULL) {
		SUHOSIN7_G(s_module) = mod = malloc(sizeof(ps_module));
		if (mod == NULL) {
			return;
		}
	}

	SUHOSIN7_G(s_original_mod) = old_mod;

	mod = SUHOSIN7_G(s_module);
	memcpy(mod, old_mod, sizeof(ps_module));

	SUHOSIN7_G(old_s_read) = mod->s_read;
	mod->s_read = suhosin_hook_s_read;
	SUHOSIN7_G(old_s_write) = mod->s_write;
	mod->s_write = suhosin_hook_s_write;
	SUHOSIN7_G(old_s_destroy) = mod->s_destroy;
	mod->s_destroy = suhosin_hook_s_destroy;

	SESSION_G(mod) = mod;
}

static PHP_INI_MH(suhosin_OnUpdateSaveHandler)
{
	if (stage == PHP_INI_STAGE_RUNTIME
		&& SESSION_G(session_status) == php_session_none
		&& SUHOSIN7_G(s_original_mod)
		&& zend_string_equals_literal(new_value, "user") == 0
		&& strcmp(((ps_module*)SUHOSIN7_G(s_original_mod))->s_name, "user") == 0) {
		return SUCCESS;
	}

	SESSION_G(mod) = SUHOSIN7_G(s_original_mod);

	int r = old_OnUpdateSaveHandler(entry, new_value, mh_arg1, mh_arg2, mh_arg3, stage);

	suhosin_hook_session_module();

	return r;
}


static int suhosin_hook_session_RINIT(INIT_FUNC_ARGS)
{
	if (SESSION_G(mod) == NULL) {
		zend_ini_entry *ini_entry;
		if ((ini_entry = zend_hash_str_find_ptr(EG(ini_directives), ZEND_STRL("session.save_handler")))) {
			if (ini_entry->value) {
				suhosin_OnUpdateSaveHandler(NULL, ini_entry->value, NULL, NULL, NULL, 0);
			}
		}
	}
	return old_SessionRINIT(INIT_FUNC_ARGS_PASSTHRU);
}

void suhosin_hook_session()
{
	zend_module_entry *module;

	if ((module = zend_hash_str_find_ptr(&module_registry, ZEND_STRL("session"))) == NULL) {
		return;
	}
	/* retrieve globals from module entry struct if possible */
#ifdef ZTS
	if (session_globals_id == 0) {
	session_globals_id = *module->globals_id_ptr;
	}
#else
	if (session_globals == NULL) {
	session_globals = module->globals_ptr;
	}
#endif

	if (old_OnUpdateSaveHandler != NULL) {
		return;
	}

	/* hook request startup function of session module */
	old_SessionRINIT = module->request_startup_func;
	module->request_startup_func = suhosin_hook_session_RINIT;

	/* retrieve pointer to session.save_handler ini entry */
	zend_ini_entry *ini_entry;
	if ((ini_entry = zend_hash_str_find_ptr(EG(ini_directives), ZEND_STRL("session.save_handler"))) != NULL) {
		/* replace OnUpdateMemoryLimit handler */
		old_OnUpdateSaveHandler = ini_entry->on_modify;
		ini_entry->on_modify = suhosin_OnUpdateSaveHandler;
	}
	SUHOSIN7_G(s_module) = NULL;

	suhosin_hook_session_module();

#if HAVE_DEV_URANDOM && PHP_VERSION_ID < 70100
	/* increase session identifier entropy */
	if (SESSION_G(entropy_length) == 0 || SESSION_G(entropy_file) == NULL) {
			SESSION_G(entropy_length) = 16;
			SESSION_G(entropy_file) = pestrdup("/dev/urandom", 1);
	}
#endif
}

// void suhosin_unhook_session()
// {
// 	if (old_OnUpdateSaveHandler == NULL) {
// 		return;
// 	}
//
// 	/* retrieve pointer to session.save_handler ini entry */
// 	zend_ini_entry *ini_entry;
// 	if ((ini_entry = zend_hash_find(EG(ini_directives), ZEND_STRL("session.save_handler"))) == NULL) {
// 		return;
// 	}
// 	ini_entry->on_modify = old_OnUpdateSaveHandler;
// 	old_OnUpdateSaveHandler = NULL;
// }

#else /* HAVE_PHP_SESSION */

#warning BUILDING SUHOSIN WITHOUT SESSION SUPPORT

#endif /* HAVE_PHP_SESSION */


/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
