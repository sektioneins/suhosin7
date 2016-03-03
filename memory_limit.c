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
  | Author: Stefan Esser <sesser@sektioneins.de> and others              |
  +----------------------------------------------------------------------+
*/
/*
  $Id: memory_limit.c $ 
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "php_suhosin7.h"


/* {{{ PHP_INI_MH
 */
static PHP_INI_MH(suhosin_OnChangeMemoryLimit)
{
#if SIZEOF_LONG==8
	long hard_memory_limit = 0x7fffffffffffffff;
#elif SIZEOF_LONG==4
	long hard_memory_limit = 0x7fffffff;
#endif /* will produce a compile error or SIZEOF_LONG is not 4 or 8 */
	if (stage == ZEND_INI_STAGE_RUNTIME) {
		if (SUHOSIN7_G(memory_limit) > 0) {
			SUHOSIN7_G(hard_memory_limit) = SUHOSIN7_G(memory_limit);
		} else if (SUHOSIN7_G(hard_memory_limit) == 0) {
			SUHOSIN7_G(hard_memory_limit) = PG(memory_limit);
		}
		hard_memory_limit = SUHOSIN7_G(hard_memory_limit);
	} else {
		SUHOSIN7_G(hard_memory_limit) = 0;
	}
	if (new_value) {
		PG(memory_limit) = zend_atol(ZSTR_VAL(new_value), ZSTR_LEN(new_value));
		if (hard_memory_limit > 0) {
			// SDEBUG("%lld > %lld ?", PG(memory_limit), hard_memory_limit);
			if (PG(memory_limit) > hard_memory_limit) {
				suhosin_log(S_MISC, "script tried to increase memory_limit to " ZEND_LONG_FMT " bytes which is above the allowed value", PG(memory_limit));
				if (!SUHOSIN7_G(simulation)) {
					PG(memory_limit) = hard_memory_limit;
					return FAILURE;
				}
			} else if (PG(memory_limit) < 0) {
				suhosin_log(S_MISC, "script tried to disable memory_limit by setting it to a negative value " ZEND_LONG_FMT " bytes which is not allowed", PG(memory_limit));
				if (!SUHOSIN7_G(simulation)) {
					PG(memory_limit) = hard_memory_limit;
					return FAILURE;
				}
			}
		}
	} else {
		PG(memory_limit) = hard_memory_limit;
	}
	return zend_set_memory_limit(PG(memory_limit));
}
/* }}} */


void suhosin_hook_memory_limit()
{
	zend_ini_entry *ini_entry;

	/* check if we are compiled against memory_limit */
	if ((ini_entry=zend_hash_str_find_ptr(EG(ini_directives), ZEND_STRL("memory_limit")))) {
		/* replace OnUpdateMemoryLimit handler */
		ini_entry->on_modify = suhosin_OnChangeMemoryLimit;
	}
	
}


/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
