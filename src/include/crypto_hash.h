/**
 * crypto-hash
 * Copyright (C) 2015 David Jolly
 * ----------------------
 *
 * crypto-hash is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * crypto-hash is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef CRYPTO_HASH_H_
#define CRYPTO_HASH_H_

#include <stdint.h>

#ifndef _WIN32
#ifndef __in
#define __in
#endif // __in
#ifndef __inout
#define __inout
#endif // __inout
#endif // _WIN32

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

typedef enum _chasherr_t {
	HASH_ERR_NONE = 0,
	HASH_ERR_INVALID_ARG,
	HASH_ERR_ALLOC,
} chasherr_t;

#define HASH_ERR_MAX HASH_ERR_ALLOC
#define HASH_SUCCESS(_ERR_) ((_ERR_) == HASH_ERR_NONE)
#define HASH_FAILURE(_ERR_) (!HASH_SUCCESS(_ERR_))

#define CRYPTO_DIGEST_MD5_LEN 0x10
typedef struct _crypto_digest_md5 {
	uint8_t data[CRYPTO_DIGEST_MD5_LEN];
} crypto_digest_md5;

chasherr_t crypto_hash_md5(
	__in const uint8_t *data,
	__in size_t length,
	__inout crypto_digest_md5 *digest
	);

#define CRYPTO_DIGEST_SHA256_LEN 0x20
typedef struct _crypto_digest_sha256 {
	uint8_t data[CRYPTO_DIGEST_SHA256_LEN];
} crypto_digest_sha256;
	
chasherr_t crypto_hash_sha256(
	__in const uint8_t *data,
	__in size_t length,
	__inout crypto_digest_sha256 *digest
	);
	
#define CRYPTO_DIGEST_SHA512_LEN 0x40
typedef struct _cryptop_digest_sha512 {
	uint8_t data[CRYPTO_DIGEST_SHA512_LEN];
} cryptop_digest_sha512;
	
chasherr_t crypto_hash_sha512(
	__in const uint8_t *data,
	__in size_t length,
	__inout cryptop_digest_sha512 *digest
	);
	
const char *crypto_hash_version(void);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // CRYPTO_HASH_H_
