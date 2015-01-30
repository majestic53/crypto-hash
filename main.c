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

#include <stdio.h>
#include <string.h>
#include "src/include/crypto_hash.h"

#define HEADER_DEF "INPUT"
#define HEADER_MD5 "MD5"
#define HEADER_SHA256 "SHA256"
#define HEADER_SHA512 "SHA512"

void 
print_digest(
	__in const char *header,
	__in const char *input,
	__in const void *digest,
	__in size_t length
	)
{
	size_t iter = 0;

	fprintf(stdout, "%s(\"%s\") =\n", header ? header : HEADER_DEF, input);

	for(; iter < length; ++iter) {
		fprintf(stdout, "%02x", ((uint8_t *) digest)[iter]);
	}
	
	fprintf(stdout, "\n");
}

int 
main(
	__in int argc,
	__in const char **argv
	) 
{
	crypto_digest_md5 digest_md5;
	chasherr_t result = HASH_ERR_NONE;
	crypto_digest_sha256 digest_sha256;
	cryptop_digest_sha512 digest_sha512;

	fprintf(stdout, "Crypto-Hash Ver.%s\n", crypto_hash_version());

	if(argc < 2) {
		fprintf(stderr, "Usage: %s [MESSAGE]\n", argv[0]);
		goto exit;
	}

	result = crypto_hash_md5((uint8_t *) argv[1], strlen(argv[1]), &digest_md5);
	if(HASH_FAILURE(result)) {
		fprintf(stderr, "md5_hash failed with status 0x08%x\n", result);
		goto exit;
	}

	print_digest(HEADER_MD5, argv[1], &digest_md5, sizeof(crypto_digest_md5));

	result = crypto_hash_sha256((uint8_t *) argv[1], strlen(argv[1]), &digest_sha256);
	if(HASH_FAILURE(result)) {
		fprintf(stderr, "sha256_hash failed with status 0x08%x\n", result);
		goto exit;
	}

	print_digest(HEADER_SHA256, argv[1], &digest_sha256, sizeof(crypto_digest_sha256));

	result = crypto_hash_sha512((uint8_t *) argv[1], strlen(argv[1]), &digest_sha512);
	if(HASH_FAILURE(result)) {
		fprintf(stderr, "sha512_hash failed with status 0x08%x\n", result);
		goto exit;
	}

	print_digest(HEADER_SHA512, argv[1], &digest_sha512, sizeof(cryptop_digest_sha512));

exit:
	return result;
}
