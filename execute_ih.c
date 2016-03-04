#include "php.h"
#include "php_suhosin7.h"
#include "execute.h"

// #ifdef SUHOSIN7_PREG_REPLACE_NULL
// preg_replace \0 protection may be redundant, because PHP already checks for \0
S7_IH_FUNCTION(preg_replace)
{
	zval *regex, *replace, *subject, *zcount = NULL;
	zend_long limit = -1;

#ifndef FAST_ZPP
	/* Get function parameters and do error-checking. */
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "zzz|lz/", &regex, &replace, &subject, &limit, &zcount) == FAILURE) {
		return FAILURE;
	}
#else
	ZEND_PARSE_PARAMETERS_START(3, 5)
		Z_PARAM_ZVAL(regex)
		Z_PARAM_ZVAL(replace)
		Z_PARAM_ZVAL(subject)
		Z_PARAM_OPTIONAL
		Z_PARAM_LONG(limit)
		Z_PARAM_ZVAL_EX(zcount, 0, 1)
	ZEND_PARSE_PARAMETERS_END_EX(return FAILURE);
#endif

	if (Z_TYPE_P(regex) != IS_ARRAY) {
		convert_to_string_ex(regex);
		// regex is string
		
		if (strlen(Z_STRVAL_P(regex)) != Z_STRLEN_P(regex)) {
			suhosin_log(S_EXECUTOR, "string termination attack on first preg_replace parameter detected");
			if (!SUHOSIN7_G(simulation)) {
				RETVAL_NULL();
				return FAILURE;
			}
		}
	} else {
		// regex is array
		
		/* For each entry in the regex array, get the entry */
		zval *regex_entry;
		ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(regex), regex_entry) {
			/* Make sure we're dealing with strings. */
			zend_string *regex_str = zval_get_string(regex_entry);

			if (strlen(ZSTR_VAL(regex_str)) != ZSTR_LEN(regex_str)) {
				suhosin_log(S_EXECUTOR, "string termination attack on first preg_replace parameter detected");
				if (!SUHOSIN7_G(simulation)) {
					RETVAL_NULL();
					zend_string_release(regex_str);
					return FAILURE;
				}
			}

			zend_string_release(regex_str);
		} ZEND_HASH_FOREACH_END();

	}

	return SUCCESS;
}

// #endif /* SUHOSIN7_PREG_REPLACE_NULL */


S7_IH_FUNCTION(symlink)
{
	if (SUHOSIN7_G(executor_allow_symlink)) {
		return SUCCESS;
	}
	
	if (PG(open_basedir) && PG(open_basedir)[0]) {
		suhosin_log(S_EXECUTOR, "symlink called during open_basedir");
		if (!SUHOSIN7_G(simulation)) {
			RETVAL_FALSE;
			return FAILURE;
		}
	}
	
	return SUCCESS;
}

S7_IH_FUNCTION(function_exists)
{
	zend_string *name;
	zend_string *lcname;
	
#ifndef FAST_ZPP
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "S", &name) == FAILURE) {
		return FAILURE;
	}
#else
	ZEND_PARSE_PARAMETERS_START(1, 1)
		Z_PARAM_STR(name)
	ZEND_PARSE_PARAMETERS_END_EX(return FAILURE);
#endif

	if (ZSTR_VAL(name)[0] == '\\') {
		/* Ignore leading "\" */
		lcname = zend_string_alloc(ZSTR_LEN(name) - 1, 0);
		zend_str_tolower_copy(ZSTR_VAL(lcname), ZSTR_VAL(name) + 1, ZSTR_LEN(name) - 1);
	} else {
		lcname = zend_string_tolower(name);
	}

	zend_function *func = zend_hash_find_ptr(EG(function_table), lcname);

	/*
	 * A bit of a hack, but not a bad one: we see if the handler of the function
	 * is actually one that displays "function is disabled" message.
	 */
	zend_bool retval = (func && (func->type != ZEND_INTERNAL_FUNCTION ||
		func->internal_function.handler != zif_display_disabled_function));
	if (retval == 0) {
		goto function_exists_return;
	}

	/* Now check if function is forbidden by Suhosin */
	if (SUHOSIN7_G(in_code_type) == SUHOSIN_EVAL) {
		if (SUHOSIN7_G(eval_whitelist) != NULL) {
			if (!zend_hash_exists(SUHOSIN7_G(eval_whitelist), lcname)) {
			    retval = 0;
				goto function_exists_return;
			}
		} else if (SUHOSIN7_G(eval_blacklist) != NULL) {
			if (zend_hash_exists(SUHOSIN7_G(eval_blacklist), lcname)) {
			    retval = 0;
				goto function_exists_return;
			}
		}
	}
	
	if (SUHOSIN7_G(func_whitelist) != NULL) {
		if (!zend_hash_exists(SUHOSIN7_G(func_whitelist), lcname)) {
		    retval = 0;
			goto function_exists_return;
		}
	} else if (SUHOSIN7_G(func_blacklist) != NULL) {
		if (zend_hash_exists(SUHOSIN7_G(func_blacklist), lcname)) {
		    retval = 0;
			goto function_exists_return;
		}
	}

function_exists_return:
	zend_string_release(lcname);
	RETVAL_BOOL(retval);
	return FAILURE;
}

// int ih_mail(IH_HANDLER_PARAMS)
// {
// 	char *to=NULL, *message=NULL, *headers=NULL;
// 	char *subject=NULL, *extra_cmd=NULL;
// 	char *tmp;
// 	int to_len, message_len, headers_len;
// 	int subject_len, extra_cmd_len;
// 
// 	if (SUHOSIN7_G(mailprotect) == 0) {
// 		return (0);
// 	}
// 
// 	if (zend_parse_parameters(ZEND_NUM_ARGS(), "sss|ss",
// 						  &to, &to_len,
// 						  &subject, &subject_len,
// 						  &message, &message_len,
// 						  &headers, &headers_len,
// 						  &extra_cmd, &extra_cmd_len
// 						  ) == FAILURE) {
// 		RETVAL_FALSE;
// 		return (1);
// 	}
// 
// 	if (headers_len > 0 && headers &&
// 		(strstr(headers, "\n\n") || strstr(headers, "\n\r\n") /* double newline */
// 			|| *headers == '\n' || (headers[0] == '\r' && headers[1] == '\n') /* starts with newline */
// 	)) {
// 		suhosin_log(S_MAIL, "mail() - double newline in headers, possible injection, mail dropped");
// 		if (!SUHOSIN7_G(simulation)) {
// 			RETVAL_FALSE;
// 			return (1);
// 		}
// 	}
// 
// 	/* check for spam attempts with buggy webforms */
// 	if (to_len > 0 && to) {
// 		do {
// 			if ((tmp = strchr(to, '\n')) == NULL)
// 				tmp = strchr(to, '\r');
// 			if (tmp == NULL) break;
// 			to = tmp + 1;
// 			if (!isspace(*to)) break;
// 		} while (1);
// 		if (tmp != NULL) {
// 			suhosin_log(S_MAIL, "mail() - newline in To header, possible injection, mail dropped");
// 			if (!SUHOSIN7_G(simulation)) {
// 				RETVAL_FALSE;
// 				return (1);
// 			}
// 		}
// 	}
// 
// 	if (subject_len > 0 && subject) {
// 		do {
// 			if ((tmp = strchr(subject, '\n')) == NULL)
// 				tmp = strchr(subject, '\r');
// 			if (tmp == NULL) break;
// 			subject = tmp + 1;
// 			if (!isspace(*subject)) break;
// 		} while (1);
// 		if (tmp != NULL) {
// 			suhosin_log(S_MAIL, "mail() - newline in Subject header, possible injection, mail dropped");
// 			if (!SUHOSIN7_G(simulation)) {
// 				RETVAL_FALSE;
// 				return (1);
// 			}
// 		}
// 	}
// 		
// 	if (SUHOSIN7_G(mailprotect) > 1) {
// 		/* search for to, cc or bcc headers */
// 		if (headers_len > 0 && headers != NULL) {
// 			if (strncasecmp(headers, "to:", sizeof("to:") - 1) == 0 || suhosin_strcasestr(headers, "\nto:")) {
// 				suhosin_log(S_MAIL, "mail() - To: headers aren't allowed in the headers parameter.");
// 				if (!SUHOSIN7_G(simulation)) {
// 					RETVAL_FALSE;
// 					return (1);
// 				}
// 			}
// 			
// 			if (strncasecmp(headers, "cc:", sizeof("cc:") - 1) == 0 || suhosin_strcasestr(headers, "\ncc:")) {
// 				suhosin_log(S_MAIL, "mail() - CC: headers aren't allowed in the headers parameter.");
// 				if (!SUHOSIN7_G(simulation)) {
// 					RETVAL_FALSE;
// 					return (1);
// 				}
// 			}
// 
// 			if (strncasecmp(headers, "bcc:", sizeof("bcc:") - 1) == 0 || suhosin_strcasestr(headers, "\nbcc:")) {
// 				suhosin_log(S_MAIL, "mail() - BCC: headers aren't allowed in the headers parameter.");
// 				if (!SUHOSIN7_G(simulation)) {
// 					RETVAL_FALSE;
// 					return (1);
// 				}
// 			}
// 		}
// 	}
// 
// 	return (0);
// }

// #define SQLSTATE_SQL        0
// #define SQLSTATE_IDENTIFIER 1
// #define SQLSTATE_STRING     2
// #define SQLSTATE_COMMENT    3
// #define SQLSTATE_MLCOMMENT  4
// 
// int ih_querycheck(IH_HANDLER_PARAMS)
// {
// 	void **p = zend_vm_stack_top() - 1;
// 	unsigned long arg_count;
// 	zval **arg;
// 	char *query, *s, *e;
// 	zval *backup;
// 	int len;
// 	char quote;
// 	int state = SQLSTATE_SQL;
// 	int cnt_union = 0, cnt_select = 0, cnt_comment = 0, cnt_opencomment = 0;
// 	int mysql_extension = 0;
// 
// 	
// 	SDEBUG("function: %s", ih->name);
// 	arg_count = (unsigned long) *p;
// 
// 	if (ht < (long) ih->arg1) {
// 		return (0);
// 	}
//     
// 	if ((long) ih->arg2) {
//     	    mysql_extension = 1;
// 	}
// 	
// 	arg = (zval **) p - (arg_count - (long) ih->arg1 + 1); /* count from 0 */
// 
// 	backup = *arg;
// 	if (Z_TYPE_P(backup) != IS_STRING) {
// 		return (0);
// 	}
// 	len = Z_STRLEN_P(backup);
// 	query = Z_STRVAL_P(backup);
// 	SDEBUG("SQL |%s|", query);
// 	
// 	s = query;
// 	e = s+len;
// 	
// 	while (s < e) {
// 	    switch (state)
// 	    {
//     		case SQLSTATE_SQL:
//     		    switch (s[0])
//     		    {
//         		case '`':
//         		    state = SQLSTATE_IDENTIFIER;
//         		    quote = '`';
//         		    break;
//         		case '\'':
//         		case '"':
//         		    state = SQLSTATE_STRING;
//         		    quote = *s;
//         		    break;
//         		case '/':
//         		    if (s[1]=='*') {
//                         if (mysql_extension == 1 && s[2] == '!') {
//                             s += 2;
//                             break;
//                         }
//             			s++;
//             			state = SQLSTATE_MLCOMMENT;
//         			    cnt_comment++;
//         		    }
//         		    break;
//     			case '-':
//         		    if (s[1]=='-') {
//         			s++;
//         			state = SQLSTATE_COMMENT;
//         			cnt_comment++;
//         		    }
//         		    break;
//     			case '#':
//         		    state = SQLSTATE_COMMENT;
//         		    cnt_comment++;
//         		    break;
//         		case 'u':
//     			case 'U':
//         		    if (strncasecmp("union", s, 5)==0) {
//             			s += 4;
//         			cnt_union++;
//         		    }
//         		    break;
//     			case 's':
//     			case 'S':
//         		    if (strncasecmp("select", s, 6)==0) {
//             			s += 5;
//         			cnt_select++;
//         		    }
//         		    break;
//     		    }
//     		    break;
//     		case SQLSTATE_STRING:
// 		case SQLSTATE_IDENTIFIER:
//     		    if (s[0] == quote) {
//         		if (s[1] == quote) {
//         		    s++;
//     			} else {
//         		    state = SQLSTATE_SQL;
//     			}
//     		    }
//     		    if (s[0] == '\\') {
//     			s++;
//     		    }
//     		    break;
// 		case SQLSTATE_COMMENT:
//     		    while (s[0] && s[0] != '\n') {
//     			s++;        
//     		    }
//     		    state = SQLSTATE_SQL;
//     		    break;
//     		case SQLSTATE_MLCOMMENT:
//     		    while (s[0] && (s[0] != '*' || s[1] != '/')) {
//     			s++;
//     		    }
//     		    if (s[0]) {
//     			state = SQLSTATE_SQL;
//     		    }
//     		    break;
// 	    }
// 	    s++;
// 	}
// 	if (state == SQLSTATE_MLCOMMENT) {
// 	    cnt_opencomment = 1;
// 	}
// 	
// 	if (cnt_opencomment && SUHOSIN7_G(sql_opencomment)>0) {
// 	    suhosin_log(S_SQL, "Open comment in SQL query: '%*s'", len, query);
// 	    if (SUHOSIN7_G(sql_opencomment)>1) {
// 		suhosin_bailout();
// 	    }
// 	}
// 	
// 	if (cnt_comment && SUHOSIN7_G(sql_comment)>0) {
// 	    suhosin_log(S_SQL, "Comment in SQL query: '%*s'", len, query);
// 	    if (SUHOSIN7_G(sql_comment)>1) {
// 		suhosin_bailout();
// 	    }
// 	}
// 
// 	if (cnt_union && SUHOSIN7_G(sql_union)>0) {
// 	    suhosin_log(S_SQL, "UNION in SQL query: '%*s'", len, query);
// 	    if (SUHOSIN7_G(sql_union)>1) {
// 		suhosin_bailout();
// 	    }
// 	}
// 
// 	if (cnt_select>1 && SUHOSIN7_G(sql_mselect)>0) {
// 	    suhosin_log(S_SQL, "Multiple SELECT in SQL query: '%*s'", len, query);
// 	    if (SUHOSIN7_G(sql_mselect)>1) {
// 		suhosin_bailout();
// 	    }
// 	}
//     
// 	return (0);
// }
// 
// 
// int ih_fixusername(IH_HANDLER_PARAMS)
// {
// 	void **p = zend_vm_stack_top() - 1;
// 	unsigned long arg_count;
// 	zval **arg;
// 	char *prefix, *postfix, *user, *user_match, *cp;
// 	zval *backup, *my_user;
// 	int prefix_len, postfix_len, len;
// 	
// 	SDEBUG("function (fixusername): %s", ih->name);
// 	
// 	prefix = SUHOSIN7_G(sql_user_prefix);
// 	postfix = SUHOSIN7_G(sql_user_postfix);
// 	user_match = SUHOSIN7_G(sql_user_match);
// 	
// 	arg_count = (unsigned long) *p;
// 
// 	if (ht < (long) ih->arg1) {
// 		return (0);
// 	}
// 	
// 	arg = (zval **) p - (arg_count - (long) ih->arg1 + 1); /* count from 0 */
// 
// 	backup = *arg;
// 	if (Z_TYPE_P(backup) != IS_STRING) {
// 		user = "";
// 		len = 0;
// 	} else {
// 		len = Z_STRLEN_P(backup);
// 		user = Z_STRVAL_P(backup);
// 	}
// 
// 	cp = user;
// 	while (cp < user+len) {
// 		if (*cp < 32) {
// 			suhosin_log(S_SQL, "SQL username contains invalid characters");
// 			if (!SUHOSIN7_G(simulation)) {
// 				RETVAL_FALSE;
// 				return (1);
// 			}
// 			break;
// 		}
// 		cp++;
// 	}
// 
// 	if ((prefix != NULL && prefix[0]) || (postfix != NULL && postfix[0])) {
// 		if (prefix == NULL) {
// 			prefix = "";
// 		}
// 		if (postfix == NULL) {
// 			postfix = "";
// 		}
// 		prefix_len = strlen(prefix);
// 		postfix_len = strlen(postfix);
// 		
// 		MAKE_STD_ZVAL(my_user);
// 		my_user->type = IS_STRING;
// 		my_user->value.str.len = spprintf(&my_user->value.str.val, 0, "%s%s%s", prefix, user, postfix);
// 	
// 		/* XXX: memory_leak? */
// 		*arg = my_user;	
// 		
// 		len = Z_STRLEN_P(my_user);
// 		user = Z_STRVAL_P(my_user);
// 	}
// 	
// 	if (user_match && user_match[0]) {
// #ifdef HAVE_FNMATCH
// 		if (fnmatch(user_match, user, 0) != 0) {
// 			suhosin_log(S_SQL, "SQL username ('%s') does not match suhosin.sql.user_match ('%s')", user, user_match);
// 			if (!SUHOSIN7_G(simulation)) {
// 				RETVAL_FALSE;
// 				return (1);
// 			}
// 		}
// #else
// #warning no support for fnmatch() - setting suhosin.sql.user_match will always fail.
// 		suhosin_log(S_SQL, "suhosin.sql.user_match specified, but system does not support fnmatch()");
// 		if (!SUHOSIN7_G(simulation)) {
// 			RETVAL_FALSE;
// 			return (1);
// 		}
// #endif
// 	}
// 	
// 	SDEBUG("function: %s - user: %s", ih->name, user);
// 
// 	return (0);
// }
// 
// 
