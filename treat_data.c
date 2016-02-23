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
  $Id: treat_data.c $ 
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "php_suhosin7.h"
#include "SAPI.h"
#include "php_variables.h"
#include "ext/standard/url.h"

static SAPI_TREAT_DATA_FUNC((*orig_treat_data)) = NULL;

SAPI_TREAT_DATA_FUNC(suhosin_treat_data)
{
	switch (arg) {
		case PARSE_POST:
			if (SUHOSIN7_G(max_request_variables) && (SUHOSIN7_G(max_post_vars) == 0 || 
				SUHOSIN7_G(max_request_variables) <= SUHOSIN7_G(max_post_vars))) {
				SUHOSIN7_G(max_post_vars) = SUHOSIN7_G(max_request_variables);
			}
			break;
		case PARSE_GET:
			if (SUHOSIN7_G(max_request_variables) && (SUHOSIN7_G(max_get_vars) == 0 || 
				SUHOSIN7_G(max_request_variables) <= SUHOSIN7_G(max_get_vars))) {
				SUHOSIN7_G(max_get_vars) = SUHOSIN7_G(max_request_variables);
			}
			break;
		case PARSE_COOKIE:
			if (SUHOSIN7_G(max_request_variables) && (SUHOSIN7_G(max_cookie_vars) == 0 || 
				SUHOSIN7_G(max_request_variables) <= SUHOSIN7_G(max_cookie_vars))) {
				SUHOSIN7_G(max_cookie_vars) = SUHOSIN7_G(max_request_variables);
			}
			break;
	}

	if (arg == PARSE_COOKIE && SUHOSIN7_G(cookie_encrypt) && SG(request_info).cookie_data) {
		SG(request_info).cookie_data = suhosin_cookie_decryptor(SG(request_info).cookie_data);
	}
	
	if (orig_treat_data) {
		orig_treat_data(arg, str, destArray);
	}
}

void suhosin_hook_treat_data()
{
	if (orig_treat_data == NULL) {
		orig_treat_data = sapi_module.treat_data;
	}
	sapi_module.treat_data = suhosin_treat_data;
}


/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
