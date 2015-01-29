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

#include <stdlib.h>
#include <string.h>
#include "../include/crypto_hash.h"

#define BITS_PER_BYTE 0x8

#define VERSION_MAJ 1
#define VERSION_MIN 0
#define VERSION_REV 1
#define VERSION_WEEK 1505

#define _STRING_CAT(_STR_) # _STR_
#define STRING_CAT(_STR_) _STRING_CAT(_STR_)

#define ROTATE_LEFT(_TYPE_, _VALUE_, _BITS_) \
	(((_VALUE_) << (_BITS_)) | ((_VALUE_) >> ((sizeof(_TYPE_) * BITS_PER_BYTE) - (_BITS_))))
#define ROTATE_RIGHT(_TYPE_, _VALUE_, _BITS_) \
	(((_VALUE_) >> (_BITS_)) | ((_VALUE_) << ((sizeof(_TYPE_) * BITS_PER_BYTE) - (_BITS_))))

uint32_t swap_endian_32(
	__in uint32_t value
	)
{
	uint32_t output = 0;
	size_t byte_iter = 0;

	for(; byte_iter < sizeof(uint32_t); ++byte_iter) {
		((uint8_t *) &output)[((sizeof(uint32_t) - 1) - byte_iter)] 
				= (uint8_t) ((value >> (byte_iter * BITS_PER_BYTE)) & UINT8_MAX);
	}

	return output;
}

uint64_t swap_endian_64(
	__in uint64_t value
	)
{
	uint64_t output = 0;
	size_t byte_iter = 0;

	for(; byte_iter < sizeof(uint64_t); ++byte_iter) {
		((uint8_t *) &output)[((sizeof(uint64_t) - 1) - byte_iter)] 
				= (uint8_t) ((value >> (byte_iter * BITS_PER_BYTE)) & UINT8_MAX);
	}

	return output;
}

#define MD5_BLOCK_PAD 0x80
#define MD5_BLOCK_PAD_LEN 0x9

#define MD5_INIT_A0 0x67452301
#define MD5_INIT_B0 0xefcdab89
#define MD5_INIT_C0 0x98badcfe
#define MD5_INIT_D0 0x10325476

static const uint8_t MD5_SHIFT_TABLE[] = {
	7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 
	5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 
	4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 
	6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 
	};

static const uint32_t MD5_SINE_TABLE[] = {
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501, 
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8, 
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1, 
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391, 
	};

#define MD5_BLOCK_LEN 0x40
typedef struct _md5_block {
	uint8_t data[MD5_BLOCK_LEN];
} md5_block;

#define MD5_CHUNK_LEN 0x10
typedef struct _md5_chunk {
	uint32_t data[MD5_CHUNK_LEN];
} md5_chunk;

chasherr_t 
crypto_hash_md5(
	__in const uint8_t *data,
	__in size_t length,
	__inout crypto_digest_md5 *digest
	)
{
	uint64_t bit_len;
	md5_block *block = NULL;
	md5_chunk *chunk = NULL;
	chasherr_t result = HASH_ERR_NONE;
	uint32_t a, a0, b, b0, c, c0, d, d0, d_tmp, f, g;
	size_t block_count, block_iter = 0, byte_count, byte_iter, ch_iter = 0;

	if(!digest) {
		result = HASH_ERR_INVARG;
		goto exit;
	}

	block_count = (length / MD5_BLOCK_LEN) + 1;

	byte_count = sizeof(md5_block) * block_count;
	if((byte_count - length) < MD5_BLOCK_PAD_LEN) {
		++block_count;
		byte_count += sizeof(md5_block);
	}

	block = (md5_block *) malloc(byte_count);
	if(!block) {
		result = HASH_ERR_ALLOC;
		goto exit;
	}

	memset(block, 0, byte_count);
	memset(digest, 0, sizeof(crypto_digest_md5));

	for(; ch_iter < length; ++ch_iter) {
		block[ch_iter / MD5_BLOCK_LEN].data[ch_iter % MD5_BLOCK_LEN] = data[ch_iter];
	}

	block[ch_iter / MD5_BLOCK_LEN].data[ch_iter % MD5_BLOCK_LEN] |= MD5_BLOCK_PAD;

	bit_len = (length * BITS_PER_BYTE) % UINT64_MAX;
	memcpy(&block[block_count - 1].data[MD5_BLOCK_LEN - sizeof(uint64_t)], &bit_len, sizeof(uint64_t));

	a0 = MD5_INIT_A0;
	b0 = MD5_INIT_B0;
	c0 = MD5_INIT_C0;
	d0 = MD5_INIT_D0;

	for(; block_iter < block_count; ++block_iter) {
		chunk = (md5_chunk *) &block[block_iter];
		a = a0;
		b = b0;
		c = c0;
		d = d0;
		
		for(byte_iter = 0; byte_iter < MD5_BLOCK_LEN; ++byte_iter) {

			if(byte_iter <= 15) {
				f = (b & c) | ((~b) & d);
				g = byte_iter;
			} else if((byte_iter > 15) && (byte_iter <= 31)) {
				f = (d & b) | (c & (~d));
				g = ((5 * byte_iter) + 1) % 0x10;
			} else if((byte_iter > 31) && (byte_iter <= 47)) {
				f = b ^ c ^ d;
				g = ((3 * byte_iter) + 5) % 0x10;
			} else {
				f = c ^ (b | (~d));
				g = (7 * byte_iter) % 0x10;
			}

			d_tmp = d;
			d = c;
			c = b;
			b += ROTATE_LEFT(uint32_t, (a + f + MD5_SINE_TABLE[byte_iter] + chunk->data[g]), 
					MD5_SHIFT_TABLE[byte_iter]);
			a = d_tmp;
		}

		a0 += a;
		b0 += b;
		c0 += c;
		d0 += d;
	}

	memcpy(&digest->data[CRYPTO_DIGEST_MD5_LEN - sizeof(uint32_t)], &d0, sizeof(uint32_t));
	memcpy(&digest->data[CRYPTO_DIGEST_MD5_LEN - (2 * sizeof(uint32_t))], &c0, sizeof(uint32_t));
	memcpy(&digest->data[CRYPTO_DIGEST_MD5_LEN - (3 * sizeof(uint32_t))], &b0, sizeof(uint32_t));
	memcpy(&digest->data[CRYPTO_DIGEST_MD5_LEN - (4 * sizeof(uint32_t))], &a0, sizeof(uint32_t));

exit:

	if(block) {
		free(block);
		block = NULL;
	}

	return result;
}

#define SHA256_BLOCK_PAD 0x80
#define SHA256_BLOCK_PAD_LEN 0x9

#define SHA256_INIT_A0 0x6a09e667
#define SHA256_INIT_B0 0xbb67ae85
#define SHA256_INIT_C0 0x3c6ef372
#define SHA256_INIT_D0 0xa54ff53a
#define SHA256_INIT_E0 0x510e527f
#define SHA256_INIT_F0 0x9b05688c
#define SHA256_INIT_G0 0x1f83d9ab
#define SHA256_INIT_H0 0x5be0cd19

static const uint32_t SHA256_ROUND_CONST_TABLE[] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
	};

#define SHA256_BLOCK_LEN 0x40
typedef struct _sha256_block {
	uint8_t data[SHA256_BLOCK_LEN];
} sha256_block;

#define SHA256_CHUNK_LEN 0x10
typedef struct _sha256_chunk {
	uint32_t data[SHA256_CHUNK_LEN];
} sha256_chunk;

#define SHA256_MESSAGE_SCHEDULER_LEN 0x40
typedef struct _sha256_message_schedule {
	uint32_t data[SHA256_MESSAGE_SCHEDULER_LEN];
} sha256_message_schedule;

chasherr_t 
crypto_hash_sha256(
	__in const uint8_t *data,
	__in size_t length,
	__inout crypto_digest_sha256 *digest
	)
{
	uint64_t bit_len;
	sha256_block *block = NULL;
	sha256_chunk *chunk = NULL;
	chasherr_t result = HASH_ERR_NONE;
	sha256_message_schedule msg_schedule;
	size_t block_count, block_iter = 0, byte_count, ch_iter = 0, chunk_iter, word_iter;
	uint32_t a, a0, b, b0, c, c0, ch, d, d0, e, e0, f, f0, g, g0, h, h0, maj, s0, s1, tmp0, tmp1;

	if(!digest) {
		result = HASH_ERR_INVARG;
		goto exit;
	}

	block_count = (length / SHA256_BLOCK_LEN) + 1;

	byte_count = sizeof(sha256_block) * block_count;
	if((byte_count - length) < SHA256_BLOCK_PAD_LEN) {
		++block_count;
		byte_count += sizeof(md5_block);
	}

	block = (sha256_block *) malloc(byte_count);
	if(!block) {
		result = HASH_ERR_ALLOC;
		goto exit;
	}

	memset(block, 0, byte_count);
	memset(digest, 0, sizeof(crypto_digest_sha256));

	for(; ch_iter < length; ++ch_iter) {
		block[ch_iter / SHA256_BLOCK_LEN].data[ch_iter % SHA256_BLOCK_LEN] = data[ch_iter];
	}

	block[ch_iter / SHA256_BLOCK_LEN].data[ch_iter % SHA256_BLOCK_LEN] |= SHA256_BLOCK_PAD;

	bit_len = swap_endian_64((length * BITS_PER_BYTE) % UINT64_MAX);
	memcpy(&block[block_count - 1].data[SHA256_BLOCK_LEN - sizeof(uint64_t)], 
		&bit_len, sizeof(uint64_t));

	a0 = SHA256_INIT_A0;
	b0 = SHA256_INIT_B0;
	c0 = SHA256_INIT_C0;
	d0 = SHA256_INIT_D0;
	e0 = SHA256_INIT_E0;
	f0 = SHA256_INIT_F0;
	g0 = SHA256_INIT_G0;
	h0 = SHA256_INIT_H0;

	for(; block_iter < block_count; ++block_iter) {
		chunk = (sha256_chunk *) &block[block_iter];
		memset(&msg_schedule, 0, sizeof(sha256_message_schedule));

		for(chunk_iter = 0; chunk_iter < SHA256_CHUNK_LEN; ++chunk_iter) {
			msg_schedule.data[chunk_iter] = swap_endian_32(chunk->data[chunk_iter]);
		}

		for(word_iter = SHA256_CHUNK_LEN; word_iter < SHA256_MESSAGE_SCHEDULER_LEN; ++word_iter) {
			s0 = ROTATE_RIGHT(uint32_t, msg_schedule.data[word_iter - 15], 7) 
					^ ROTATE_RIGHT(uint32_t, msg_schedule.data[word_iter - 15], 18) 
					^ (msg_schedule.data[word_iter - 15] >> 3);
			s1 = ROTATE_RIGHT(uint32_t, msg_schedule.data[word_iter - 2], 17) 
					^ ROTATE_RIGHT(uint32_t, msg_schedule.data[word_iter - 2], 19)  
					^ (msg_schedule.data[word_iter - 2] >> 10);
			msg_schedule.data[word_iter] = msg_schedule.data[word_iter - 16] + s0 
					+ msg_schedule.data[word_iter - 7] + s1;
		}

		a = a0;
		b = b0;
		c = c0;
		d = d0;
		e = e0;
		f = f0;
		g = g0;
		h = h0;

		for(word_iter = 0; word_iter < SHA256_MESSAGE_SCHEDULER_LEN; ++word_iter) {
			s1 = ROTATE_RIGHT(uint32_t, e, 6) ^ ROTATE_RIGHT(uint32_t, e, 11) 
					^ ROTATE_RIGHT(uint32_t, e, 25);
			ch = (e & f) ^ ((~e) & g);
			tmp0 = h + s1 + ch + SHA256_ROUND_CONST_TABLE[word_iter] 
					+ msg_schedule.data[word_iter];
			s0 = ROTATE_RIGHT(uint32_t, a, 2) ^ ROTATE_RIGHT(uint32_t, a, 13) 
					^ ROTATE_RIGHT(uint32_t, a, 22);
			maj = (a & b) ^ (a & c) ^ (b & c);
			tmp1 = s0 + maj;
			h = g;
			g = f;
			f = e;
			e = d + tmp0;
			d = c;
			c = b;
			b = a;
			a = tmp0 + tmp1;
		}

		a0 += a;
		b0 += b;
		c0 += c;
		d0 += d;
		e0 += e;
		f0 += f;
		g0 += g;
		h0 += h;
	}

	h0 = swap_endian_32(h0);
	g0 = swap_endian_32(g0);
	f0 = swap_endian_32(f0);
	e0 = swap_endian_32(e0);
	d0 = swap_endian_32(d0);
	c0 = swap_endian_32(c0);
	b0 = swap_endian_32(b0);
	a0 = swap_endian_32(a0);
	memcpy(&digest->data[CRYPTO_DIGEST_SHA256_LEN - sizeof(uint32_t)], &h0, sizeof(uint32_t));
	memcpy(&digest->data[CRYPTO_DIGEST_SHA256_LEN - (2 * sizeof(uint32_t))], &g0, sizeof(uint32_t));
	memcpy(&digest->data[CRYPTO_DIGEST_SHA256_LEN - (3 * sizeof(uint32_t))], &f0, sizeof(uint32_t));
	memcpy(&digest->data[CRYPTO_DIGEST_SHA256_LEN - (4 * sizeof(uint32_t))], &e0, sizeof(uint32_t));
	memcpy(&digest->data[CRYPTO_DIGEST_SHA256_LEN - (5 * sizeof(uint32_t))], &d0, sizeof(uint32_t));
	memcpy(&digest->data[CRYPTO_DIGEST_SHA256_LEN - (6 * sizeof(uint32_t))], &c0, sizeof(uint32_t));
	memcpy(&digest->data[CRYPTO_DIGEST_SHA256_LEN - (7 * sizeof(uint32_t))], &b0, sizeof(uint32_t));
	memcpy(&digest->data[CRYPTO_DIGEST_SHA256_LEN - (8 * sizeof(uint32_t))], &a0, sizeof(uint32_t));

exit:

	if(block) {
		free(block);
		block = NULL;
	}

	return result;
}

#define SHA512_BLOCK_PAD 0x80
#define SHA512_BLOCK_PAD_LEN 0x11

#define SHA512_INIT_A0 0x6a09e667f3bcc908
#define SHA512_INIT_B0 0xbb67ae8584caa73b
#define SHA512_INIT_C0 0x3c6ef372fe94f82b
#define SHA512_INIT_D0 0xa54ff53a5f1d36f1
#define SHA512_INIT_E0 0x510e527fade682d1
#define SHA512_INIT_F0 0x9b05688c2b3e6c1f
#define SHA512_INIT_G0 0x1f83d9abfb41bd6b
#define SHA512_INIT_H0 0x5be0cd19137e2179

static const uint64_t SHA512_ROUND_CONST_TABLE[] = {
	0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 
	0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe, 
	0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 
	0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 
	0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab, 
	0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 
	0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 
	0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 
	0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218, 
	0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 
	0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 
	0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec, 
	0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c, 
	0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 
	0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 
	0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
	};

#define SHA512_BLOCK_LEN 0x80
typedef struct _sha512_block {
	uint8_t data[SHA512_BLOCK_LEN];
} sha512_block;

#define SHA512_CHUNK_LEN 0x10
typedef struct _sha512_chunk {
	uint64_t data[SHA512_CHUNK_LEN];
} sha512_chunk;

#define SHA512_MESSAGE_SCHEDULER_LEN 0x50
typedef struct _sha512_message_schedule {
	uint64_t data[SHA512_MESSAGE_SCHEDULER_LEN];
} sha512_message_schedule;

chasherr_t 
crypto_hash_sha512(
	__in const uint8_t *data,
	__in size_t length,
	__inout cryptop_digest_sha512 *digest
	)
{
	uint64_t bit_len[2];
	sha512_block *block = NULL;
	sha512_chunk *chunk = NULL;
	chasherr_t result = HASH_ERR_NONE;
	sha512_message_schedule msg_schedule;
	size_t block_count, block_iter = 0, byte_count, ch_iter = 0, chunk_iter, word_iter;
	uint64_t a, a0, b, b0, c, c0, ch, d, d0, e, e0, f, f0, g, g0, h, h0, maj, s0, s1, tmp0, tmp1;

	if(!digest) {
		result = HASH_ERR_INVARG;
		goto exit;
	}

	block_count = (length / SHA512_BLOCK_LEN) + 1;

	byte_count = sizeof(sha512_block) * block_count;
	if((byte_count - length) < SHA512_BLOCK_PAD_LEN) {
		++block_count;
		byte_count += sizeof(md5_block);
	}

	block = (sha512_block *) malloc(byte_count);
	if(!block) {
		result = HASH_ERR_ALLOC;
		goto exit;
	}

	memset(block, 0, byte_count);
	memset(digest, 0, sizeof(cryptop_digest_sha512));

	for(; ch_iter < length; ++ch_iter) {
		block[ch_iter / SHA512_BLOCK_LEN].data[ch_iter % SHA512_BLOCK_LEN] = data[ch_iter];
	}

	block[ch_iter / SHA512_BLOCK_LEN].data[ch_iter % SHA512_BLOCK_LEN] |= SHA512_BLOCK_PAD;

	bit_len[1] = swap_endian_64((length * BITS_PER_BYTE) % UINT64_MAX);
	bit_len[0] = 0;
	memcpy(&block[block_count - 1].data[SHA512_BLOCK_LEN - (sizeof(uint64_t) * 2)], 
		&bit_len, (sizeof(uint64_t) * 2));

	a0 = SHA512_INIT_A0;
	b0 = SHA512_INIT_B0;
	c0 = SHA512_INIT_C0;
	d0 = SHA512_INIT_D0;
	e0 = SHA512_INIT_E0;
	f0 = SHA512_INIT_F0;
	g0 = SHA512_INIT_G0;
	h0 = SHA512_INIT_H0;

	for(; block_iter < block_count; ++block_iter) {
		chunk = (sha512_chunk *) &block[block_iter];
		memset(&msg_schedule, 0, sizeof(sha512_message_schedule));

		for(chunk_iter = 0; chunk_iter < SHA512_CHUNK_LEN; ++chunk_iter) {
			msg_schedule.data[chunk_iter] = swap_endian_64(chunk->data[chunk_iter]);
		}

		for(word_iter = SHA512_CHUNK_LEN; word_iter < SHA512_MESSAGE_SCHEDULER_LEN; ++word_iter) {
			s0 = ROTATE_RIGHT(uint64_t, msg_schedule.data[word_iter - 15], 1) 
					^ ROTATE_RIGHT(uint64_t, msg_schedule.data[word_iter - 15], 8) 
					^ (msg_schedule.data[word_iter - 15] >> 7);
			s1 = ROTATE_RIGHT(uint64_t, msg_schedule.data[word_iter - 2], 19) 
					^ ROTATE_RIGHT(uint64_t, msg_schedule.data[word_iter - 2], 61)  
					^ (msg_schedule.data[word_iter - 2] >> 6);
			msg_schedule.data[word_iter] = msg_schedule.data[word_iter - 16] + s0 
					+ msg_schedule.data[word_iter - 7] + s1;
		}

		a = a0;
		b = b0;
		c = c0;
		d = d0;
		e = e0;
		f = f0;
		g = g0;
		h = h0;

		for(word_iter = 0; word_iter < SHA512_MESSAGE_SCHEDULER_LEN; ++word_iter) {
			s1 = ROTATE_RIGHT(uint64_t, e, 14) ^ ROTATE_RIGHT(uint64_t, e, 18) 
					^ ROTATE_RIGHT(uint64_t, e, 41);
			ch = (e & f) ^ ((~e) & g);
			tmp0 = h + s1 + ch + SHA512_ROUND_CONST_TABLE[word_iter] 
					+ msg_schedule.data[word_iter];
			s0 = ROTATE_RIGHT(uint64_t, a, 28) ^ ROTATE_RIGHT(uint64_t, a, 34) 
					^ ROTATE_RIGHT(uint64_t, a, 39);
			maj = (a & b) ^ (a & c) ^ (b & c);
			tmp1 = s0 + maj;
			h = g;
			g = f;
			f = e;
			e = d + tmp0;
			d = c;
			c = b;
			b = a;
			a = tmp0 + tmp1;
		}

		a0 += a;
		b0 += b;
		c0 += c;
		d0 += d;
		e0 += e;
		f0 += f;
		g0 += g;
		h0 += h;
	}

	h0 = swap_endian_64(h0);
	g0 = swap_endian_64(g0);
	f0 = swap_endian_64(f0);
	e0 = swap_endian_64(e0);
	d0 = swap_endian_64(d0);
	c0 = swap_endian_64(c0);
	b0 = swap_endian_64(b0);
	a0 = swap_endian_64(a0);
	memcpy(&digest->data[CRYPTO_DIGEST_SHA512_LEN - sizeof(uint64_t)], &h0, sizeof(uint64_t));
	memcpy(&digest->data[CRYPTO_DIGEST_SHA512_LEN - (2 * sizeof(uint64_t))], &g0, sizeof(uint64_t));
	memcpy(&digest->data[CRYPTO_DIGEST_SHA512_LEN - (3 * sizeof(uint64_t))], &f0, sizeof(uint64_t));
	memcpy(&digest->data[CRYPTO_DIGEST_SHA512_LEN - (4 * sizeof(uint64_t))], &e0, sizeof(uint64_t));
	memcpy(&digest->data[CRYPTO_DIGEST_SHA512_LEN - (5 * sizeof(uint64_t))], &d0, sizeof(uint64_t));
	memcpy(&digest->data[CRYPTO_DIGEST_SHA512_LEN - (6 * sizeof(uint64_t))], &c0, sizeof(uint64_t));
	memcpy(&digest->data[CRYPTO_DIGEST_SHA512_LEN - (7 * sizeof(uint64_t))], &b0, sizeof(uint64_t));
	memcpy(&digest->data[CRYPTO_DIGEST_SHA512_LEN - (8 * sizeof(uint64_t))], &a0, sizeof(uint64_t));

exit:

	if(block) {
		free(block);
		block = NULL;
	}

	return result;
}

const char *
crypto_hash_version(void) 
{
	return STRING_CAT(VERSION_MAJ) "." STRING_CAT(VERSION_MIN) "." STRING_CAT(VERSION_WEEK) 
			"." STRING_CAT(VERSION_REV);
}
