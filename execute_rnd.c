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

/* MT RAND FUNCTIONS */


/*
	The following php_mt_...() functions are based on a C++ class MTRand by
	Richard J. Wagner. For more information see the web page at
	http://www-personal.engin.umich.edu/~wagnerr/MersenneTwister.html

	Mersenne Twister random number generator -- a C++ class MTRand
	Based on code by Makoto Matsumoto, Takuji Nishimura, and Shawn Cokus
	Richard J. Wagner  v1.0  15 May 2003  rjwagner@writeme.com

	The Mersenne Twister is an algorithm for generating random numbers.  It
	was designed with consideration of the flaws in various other generators.
	The period, 2^19937-1, and the order of equidistribution, 623 dimensions,
	are far greater.  The generator is also fast; it avoids multiplication and
	division, and it benefits from caches and pipelines.  For more information
	see the inventors' web page at http://www.math.keio.ac.jp/~matumoto/emt.html

	Reference
	M. Matsumoto and T. Nishimura, "Mersenne Twister: A 623-Dimensionally
	Equidistributed Uniform Pseudo-Random Number Generator", ACM Transactions on
	Modeling and Computer Simulation, Vol. 8, No. 1, January 1998, pp 3-30.

	Copyright (C) 1997 - 2002, Makoto Matsumoto and Takuji Nishimura,
	Copyright (C) 2000 - 2003, Richard J. Wagner
	All rights reserved.

	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions
	are met:

	1. Redistributions of source code must retain the above copyright
	   notice, this list of conditions and the following disclaimer.

	2. Redistributions in binary form must reproduce the above copyright
	   notice, this list of conditions and the following disclaimer in the
	   documentation and/or other materials provided with the distribution.

	3. The names of its contributors may not be used to endorse or promote
	   products derived from this software without specific prior written
	   permission.

	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
	"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
	LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
	A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
	CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
	EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
	PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
	PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
	LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
	NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
	SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

	The original code included the following notice:

	When you use this, send an email to: matumoto@math.keio.ac.jp
	with an appropriate reference to your work.

	It would be nice to CC: rjwagner@writeme.com and Cokus@math.washington.edu
	when you write.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_suhosin7.h"
#include "ext/hash/php_hash.h"
#include "ext/hash/php_hash_sha.h"
#include "ext/standard/php_lcg.h"
#include "ext/standard/php_rand.h"
#include "execute.h"

#include <fcntl.h>


#define N             624                 /* length of state vector */
#define M             (397)                /* a period parameter */
#define hiBit(u)      ((u) & 0x80000000U)  /* mask all but highest   bit of u */
#define loBit(u)      ((u) & 0x00000001U)  /* mask all but lowest    bit of u */
#define loBits(u)     ((u) & 0x7FFFFFFFU)  /* mask     the highest   bit of u */
#define mixBits(u, v) (hiBit(u)|loBits(v)) /* move hi bit of u to hi bit of v */

#define twist(m,u,v)  (m ^ (mixBits(u,v)>>1) ^ ((php_uint32)(-(php_int32)(loBit(v))) & 0x9908b0dfU))

/* {{{ php_mt_initialize
 */
static inline void suhosin_mt_initialize(php_uint32 seed, php_uint32 *state)
{
	/* Initialize generator state with seed
	   See Knuth TAOCP Vol 2, 3rd Ed, p.106 for multiplier.
	   In previous versions, most significant bits (MSBs) of the seed affect
	   only MSBs of the state array.  Modified 9 Jan 2002 by Makoto Matsumoto. */

	register php_uint32 *s = state;
	register php_uint32 *r = state;
	register int i = 1;

	*s++ = seed & 0xffffffffU;
	for( ; i < N; ++i ) {
		*s++ = ( 1812433253U * ( *r ^ (*r >> 30) ) + i ) & 0xffffffffU;
		r++;
	}
}
/* }}} */

static inline void suhosin_mt_init_by_array(php_uint32 *key, int keylen, php_uint32 *state)
{
	int i, j, k;
	suhosin_mt_initialize(19650218U, state);
	i = 1; j = 0;
	k = (N > keylen ? N : keylen);
	for (; k; k--) {
		state[i] = (state[i] ^ ((state[i-1] ^ (state[i-1] >> 30)) * 1664525U)) + key[j] + j;
		i++; j = (j+1) % keylen;
		if (i >= N) { state[0] = state[N-1]; i=1; }
	}
	for (k=N-1; k; k--) {
		state[i] = (state[i] ^ ((state[i-1] ^ (state[i-1] >> 30)) * 1566083941U)) - i;
		i++;
		if (i >= N) { state[0] = state[N-1]; i=1; }
	}
	state[0] = 0x80000000U;
}
/* }}} */


/* {{{ suhosin_mt_reload
 */
static inline void suhosin_mt_reload(php_uint32 *state, php_uint32 **next, int *left)
{
	/* Generate N new values in state
	   Made clearer and faster by Matthew Bellew (matthew.bellew@home.com) */

	register php_uint32 *p = state;
	register int i;

	for (i = N - M; i--; ++p)
		*p = twist(p[M], p[0], p[1]);
	for (i = M; --i; ++p)
		*p = twist(p[M-N], p[0], p[1]);
	*p = twist(p[M-N], p[0], state[0]);
	*left = N;
	*next = state;
}
/* }}} */

/* {{{ suhosin_mt_srand
 */
static void suhosin_mt_srand(php_uint32 seed)
{
	/* Seed the generator with a simple uint32 */
	suhosin_mt_initialize(seed, SUHOSIN7_G(mt_state));
	suhosin_mt_reload(SUHOSIN7_G(mt_state), &SUHOSIN7_G(mt_next), &SUHOSIN7_G(mt_left));

	/* Seed only once */
	SUHOSIN7_G(mt_is_seeded) = 1;
}
/* }}} */

/* {{{ suhosin_mt_rand
 */
static php_uint32 suhosin_mt_rand()
{
	/* Pull a 32-bit integer from the generator state
	   Every other access function simply transforms the numbers extracted here */

	register php_uint32 s1;

	if (SUHOSIN7_G(mt_left) == 0) {
		suhosin_mt_reload(SUHOSIN7_G(mt_state), &SUHOSIN7_G(mt_next), &SUHOSIN7_G(mt_left));
	}
	--SUHOSIN7_G(mt_left);

	s1 = *SUHOSIN7_G(mt_next)++;
	s1 ^= (s1 >> 11);
	s1 ^= (s1 <<  7) & 0x9d2c5680U;
	s1 ^= (s1 << 15) & 0xefc60000U;
	return ( s1 ^ (s1 >> 18) );
}
/* }}} */

/* {{{ SUHOSIN7_Gen_entropy
 */
static void SUHOSIN7_Gen_entropy(php_uint32 *entropybuf)
{
	php_uint32 seedbuf[20];
	/* On a modern OS code, stack and heap base are randomized */
	unsigned long code_value  = (unsigned long)SUHOSIN7_Gen_entropy;
	unsigned long stack_value = (unsigned long)&code_value;
	unsigned long heap_value  = (unsigned long)SUHOSIN7_G(r_state);
	PHP_SHA256_CTX   context;
	int fd;

	code_value ^= code_value >> 32;
	stack_value ^= stack_value >> 32;
	heap_value ^= heap_value >> 32;

	seedbuf[0] = code_value;
	seedbuf[1] = stack_value;
	seedbuf[2] = heap_value;
	seedbuf[3] = time(0);
#ifdef PHP_WIN32
	seedbuf[4] = GetCurrentProcessId();
#else
	seedbuf[4] = getpid();
#endif
	seedbuf[5] = (php_uint32) 0x7fffffff * php_combined_lcg();

#ifndef PHP_WIN32
# if HAVE_DEV_URANDOM
#  ifdef VIRTUAL_DIR
	fd = VCWD_OPEN("/dev/urandom", O_RDONLY);
#  else
	fd = open("/dev/urandom", O_RDONLY);
#  endif
	if (fd >= 0) {
		/* ignore error case - if urandom doesn't give us any/enough random bytes */
		read(fd, &seedbuf[6], 8 * sizeof(php_uint32));
		close(fd);
	}
# endif
#else
	/* we have to live with the possibility that this call fails */
	php_win32_get_random_bytes((unsigned char*)&seedbuf[6], 8 * sizeof(php_uint32));
#endif

	PHP_SHA256Init(&context);
	/* to our friends from Debian: yes this will add unitialized stack values to the entropy DO NOT REMOVE */
	PHP_SHA256Update(&context, (void *) seedbuf, sizeof(seedbuf));
	if (SUHOSIN7_G(seedingkey) != NULL && *SUHOSIN7_G(seedingkey) != 0) {
		PHP_SHA256Update(&context, (unsigned char*)SUHOSIN7_G(seedingkey), strlen(SUHOSIN7_G(seedingkey)));
	}
	PHP_SHA256Final((void *)entropybuf, &context);
}
/* }}} */


/* {{{ suhosin_srand_auto
 */
static void suhosin_srand_auto()
{
	php_uint32 seed[8];
	SUHOSIN7_Gen_entropy(&seed[0]);

	suhosin_mt_init_by_array(seed, 8, SUHOSIN7_G(r_state));
	suhosin_mt_reload(SUHOSIN7_G(r_state), &SUHOSIN7_G(r_next), &SUHOSIN7_G(r_left));

	/* Seed only once */
	SUHOSIN7_G(r_is_seeded) = 1;
}
/* }}} */

/* {{{ suhosin_mt_srand_auto
 */
static void suhosin_mt_srand_auto()
{
	php_uint32 seed[8];
	SUHOSIN7_Gen_entropy(&seed[0]);

	suhosin_mt_init_by_array(seed, 8, SUHOSIN7_G(mt_state));
	suhosin_mt_reload(SUHOSIN7_G(mt_state), &SUHOSIN7_G(mt_next), &SUHOSIN7_G(mt_left));

	/* Seed only once */
	SUHOSIN7_G(mt_is_seeded) = 1;
}
/* }}} */


/* {{{ suhosin_srand
 */
static void suhosin_srand(php_uint32 seed)
{
	/* Seed the generator with a simple uint32 */
	suhosin_mt_initialize(seed+0x12345, SUHOSIN7_G(r_state));
	suhosin_mt_reload(SUHOSIN7_G(r_state), &SUHOSIN7_G(r_next), &SUHOSIN7_G(r_left));

	/* Seed only once */
	SUHOSIN7_G(r_is_seeded) = 1;
}
/* }}} */

/* {{{ suhosin_mt_rand
 */
static php_uint32 suhosin_rand()
{
	/* Pull a 32-bit integer from the generator state
	   Every other access function simply transforms the numbers extracted here */

	register php_uint32 s1;

	if (SUHOSIN7_G(r_left) == 0) {
		suhosin_mt_reload(SUHOSIN7_G(r_state), &SUHOSIN7_G(r_next), &SUHOSIN7_G(r_left));
	}
	--SUHOSIN7_G(r_left);

	s1 = *SUHOSIN7_G(r_next)++;
	s1 ^= (s1 >> 11);
	s1 ^= (s1 <<  7) & 0x9d2c5680U;
	s1 ^= (s1 << 15) & 0xefc60000U;
	return ( s1 ^ (s1 >> 18) );
}
/* }}} */

S7_IH_FUNCTION(srand)
{
	int argc = ZEND_NUM_ARGS();
	long seed;

	if (SUHOSIN7_G(srand_ignore)) {
		SUHOSIN7_G(r_is_seeded) = 0;
		return 1;
	}

	if (zend_parse_parameters(argc, "|l", &seed) == FAILURE) {
		return 1;
	}

	if (argc) {
		suhosin_srand(seed);
	} else {
		suhosin_srand_auto();
	}
	return (1);
}

S7_IH_FUNCTION(mt_srand)
{
	int argc = ZEND_NUM_ARGS();
	long seed;

	if (SUHOSIN7_G(mt_srand_ignore)) {
		SUHOSIN7_G(mt_is_seeded) = 0;
		return 1;
	}

	if (zend_parse_parameters(argc, "|l", &seed) == FAILURE) {
		return 1;
	}

	if (argc) {
		suhosin_mt_srand(seed);
	} else {
		suhosin_mt_srand_auto();
	}
	return 1;
}

S7_IH_FUNCTION(mt_rand)
{
	int argc = ZEND_NUM_ARGS();
	long min;
	long max;
	long number;

	if (argc != 0 && zend_parse_parameters(argc, "ll", &min, &max) == FAILURE) {
	    return (1);
	}

	if (!SUHOSIN7_G(mt_is_seeded)) {
		suhosin_mt_srand_auto();
	}

	number = (long) (suhosin_mt_rand() >> 1);
	if (argc == 2) {
		RAND_RANGE(number, min, max, PHP_MT_RAND_MAX);
	}

	RETVAL_LONG(number);
	return (1);
}

S7_IH_FUNCTION(rand)
{
	int argc = ZEND_NUM_ARGS();
	long min;
	long max;
	long number;

	if (argc != 0 && zend_parse_parameters(argc, "ll", &min, &max) == FAILURE) {
	    return (1);
	}

	if (!SUHOSIN7_G(r_is_seeded)) {
		suhosin_srand_auto();
	}

	number = (long) (suhosin_rand() >> 1);
	if (argc == 2) {
		RAND_RANGE(number, min, max, PHP_MT_RAND_MAX);
	}

	RETVAL_LONG(number);
	return (1);
}

S7_IH_FUNCTION(getrandmax)
{
	if (zend_parse_parameters_none() == FAILURE) {
		return(0);
	}
	RETVAL_LONG(PHP_MT_RAND_MAX);
	return (1);
}
