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
#include "php_suhosin7.h"
#include "SAPI.h"


static int (*orig_header_handler)(sapi_header_struct *sapi_header, sapi_header_op_enum op, sapi_headers_struct *sapi_headers) = NULL;

/* {{{ suhosin_header_handler
 */
static int suhosin_header_handler(sapi_header_struct *sapi_header, sapi_header_op_enum op, sapi_headers_struct *sapi_headers)
{
	int retval = SAPI_HEADER_ADD;

	if (op != SAPI_HEADER_ADD && op != SAPI_HEADER_REPLACE) {
		goto suhosin_skip_header_handling;
	}
	
	if (sapi_header && sapi_header->header) {
	
		char *tmp = sapi_header->header;

		for (int i = 0; i < sapi_header->header_len; i++, tmp++) {
			if (tmp[0] == 0) {
				suhosin_log(S_MISC, "%s() - wanted to send a HTTP header with an ASCII NUL in it", suhosin_get_active_function_name());
				if (!SUHOSIN7_G(simulation)) {
					sapi_header->header_len = i;
				}
			}
			if (SUHOSIN7_G(allow_multiheader)) {
				continue;
			} else if ((tmp[0] == '\r' && (tmp[1] != '\n' || i == 0)) || 
			   (tmp[0] == '\n' && (i == sapi_header->header_len-1 || i == 0 || (tmp[1] != ' ' && tmp[1] != '\t')))) {
				suhosin_log(S_MISC, "%s() - wanted to send multiple HTTP headers at once", suhosin_get_active_function_name());
				if (!SUHOSIN7_G(simulation)) {
					sapi_header->header_len = i;
					tmp[0] = 0;
				}
			}
		}
	}

	/* Handle a potential cookie */

	if (SUHOSIN7_G(cookie_encrypt) && (strncasecmp("Set-Cookie:", sapi_header->header, sizeof("Set-Cookie:")-1) == 0)) {

		char *start, *end, *rend, *tmp;
		char *name, *value;
		int nlen, vlen, len, tlen;
		char cryptkey[33];

		S7_GENERATE_KEY(cookie, cryptkey);
		start = estrndup(sapi_header->header, sapi_header->header_len);
		rend = end = start + sapi_header->header_len;

		tmp = memchr(start, ';', end-start);
		if (tmp != NULL) {
			end = tmp;
		}

		tmp = start + sizeof("Set-Cookie:") - 1;
		while (tmp < end && isspace(*tmp)) {
			tmp++;
		}
		name = tmp;
		nlen = end-name;
		tmp = memchr(name, '=', nlen);
		if (tmp == NULL) {
			value = end;
		} else {
			value = tmp+1;
			nlen = tmp-name;
		}
		vlen = end-value;

		zend_string *zs_val = suhosin_encrypt_single_cookie(name, nlen, value, vlen, (char *)cryptkey); 
		
		len = sizeof("Set-Cookie: ")-1 + nlen + 1 + ZSTR_LEN(zs_val) + rend-end;
		tmp = emalloc(len + 1);
		tlen = sprintf(tmp, "Set-Cookie: %.*s=%s", nlen, name, ZSTR_VAL(zs_val));
		memcpy(tmp + tlen, end, rend-end);
		tmp[len] = 0;

		efree(sapi_header->header);
		// efree(value);
		zend_string_release(zs_val);
		efree(start);

		sapi_header->header = tmp;
		sapi_header->header_len = len;
	}

suhosin_skip_header_handling:
	/* If existing call the sapi header handler */
	if (orig_header_handler) {
		retval = orig_header_handler(sapi_header, op, sapi_headers);
	}

	return retval;
}
/* }}} */


/* {{{ suhosin_hook_header_handler
 */
void suhosin_hook_header_handler()
{
	if (orig_header_handler == NULL) {
		orig_header_handler = sapi_module.header_handler;
		sapi_module.header_handler = suhosin_header_handler;
	}
}
/* }}} */

/* {{{ suhosin_unhook_header_handler
 */
void suhosin_unhook_header_handler()
{
	sapi_module.header_handler = orig_header_handler;
	orig_header_handler = NULL;
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
