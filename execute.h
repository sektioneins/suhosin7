#pragma once

#define S7_IH_HANDLER_PARAMS_REST INTERNAL_FUNCTION_PARAMETERS
#define S7_IH_HANDLER_PARAMS suhosin_internal_function_handler *ih, S7_IH_HANDLER_PARAMS_REST
#define S7_IH_HANDLER_PARAM_PASSTHRU ih, INTERNAL_FUNCTION_PARAM_PASSTHRU

#define S7_IH_FN(fname) suhosin_ih_ ## fname
#define S7_IH_FUNCTION(fname) int S7_IH_FN(fname)(S7_IH_HANDLER_PARAMS)
#define S7_IH_ENTRY(php_fname, fname, arg1, arg2, arg3) { php_fname, S7_IH_FN(fname), (void*)(arg1), (void*)(arg2), (void*)(arg3) },
#define S7_IH_ENTRY0(php_fname, fname) S7_IH_ENTRY(php_fname, fname, NULL, NULL, NULL)
#define S7_IH_ENTRY0i(fname) S7_IH_ENTRY0(#fname, fname)

typedef struct _suhosin_internal_function_handler {
	char *name;
	int (*handler)(struct _suhosin_internal_function_handler *ih, S7_IH_HANDLER_PARAMS_REST);
	void *arg1;
	void *arg2;
	void *arg3;
} suhosin_internal_function_handler;

// execute_ih.c
S7_IH_FUNCTION(preg_replace);
S7_IH_FUNCTION(symlink);
S7_IH_FUNCTION(function_exists);

// execute_rnd.c
S7_IH_FUNCTION(srand);
S7_IH_FUNCTION(mt_srand);
S7_IH_FUNCTION(mt_rand);
S7_IH_FUNCTION(rand);
S7_IH_FUNCTION(getrandmax);
