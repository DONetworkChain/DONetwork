/**
 * Copyright (c) 2000-2001 Aaron D. Gifford
 * Copyright (c) 2013-2014 Pavol Rusnak
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTOR(S) ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTOR(S) BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef __CA_SHA2_H__
#define __CA_SHA2_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

#define SHA256_BLOCK_LENGTH		64
#define SHA256_DIGEST_LENGTH		32
#define SHA256_DIGEST_STRING_LENGTH	(SHA256_DIGEST_LENGTH * 2 + 1)
#define SHA512_BLOCK_LENGTH		128
#define SHA512_DIGEST_LENGTH		64
#define SHA512_DIGEST_STRING_LENGTH	(SHA512_DIGEST_LENGTH * 2 + 1)

typedef struct _SHA256_CTX {
	uint32_t	state[8];
	uint64_t	bitcount;
	uint8_t	buffer[SHA256_BLOCK_LENGTH];
} SHA256_CTX;
typedef struct _SHA512_CTX {
	uint64_t	state[8];
	uint64_t	bitcount[2];
	uint8_t	buffer[SHA512_BLOCK_LENGTH];
} SHA512_CTX;
/**
 * @brief
*/
void sha256_Init(SHA256_CTX *);
/**
 * @brief
 * 
 * @param       SHA256_CTX*:
 * @param       size_t:
*/
void sha256_Update(SHA256_CTX*, const void*, size_t);
/**
 * @brief
 * 
 * @param       uint8_t[SHA256_DIGEST_LENGTH]:
 * @param       SHA256_CTX*:
*/
void sha256_Final(uint8_t[SHA256_DIGEST_LENGTH], SHA256_CTX*);
/**
 * @brief
 * 
 * @param       SHA256_CTX*:
 * @param       char[SHA256_DIGEST_STRING_LENGTH]:
 * @return		char*
*/
char* sha256_End(SHA256_CTX*, char[SHA256_DIGEST_STRING_LENGTH]);
/**
 * @brief
 * 
 * @param       const void*:
 * @param       size_t:
 * @param       uint8_t[SHA256_DIGEST_LENGTH]:
*/
void sha256_Raw(const void*, size_t, uint8_t[SHA256_DIGEST_LENGTH]);
/**
 * @brief
 * 
 * @param       const void*:
 * @param       size_t:
 * @param       char[SHA256_DIGEST_STRING_LENGTH]:
 * @return		char*
*/
char* sha256_Data(const void*, size_t, char[SHA256_DIGEST_STRING_LENGTH]);
/**
 * @brief
 * 
 * @param       SHA512_CTX*:
*/
void sha512_Init(SHA512_CTX*);
/**
 * @brief
 * 
 * @param       SHA512_CTX*:
 * @param       const void*:
 * @param       size_t:
*/
void sha512_Update(SHA512_CTX*, const void*, size_t);
/**
 * @brief
 * 
 * @param       uint8_t[SHA512_DIGEST_LENGTH]:
 * @param       SHA512_CTX*:
*/
void sha512_Final(uint8_t[SHA512_DIGEST_LENGTH], SHA512_CTX*);
/**
 * @brief
 * 
 * @param       SHA512_CTX*:
 * @param       char[SHA512_DIGEST_STRING_LENGTH]:
 * @return		char*
*/
char* sha512_End(SHA512_CTX*, char[SHA512_DIGEST_STRING_LENGTH]);
/**
 * @brief
 * 
 * @param       const void*:
 * @param       size_t:
 * @param		uint8_t[SHA512_DIGEST_LENGTH]
*/
void sha512_Raw(const void*, size_t, uint8_t[SHA512_DIGEST_LENGTH]);
/**
 * @brief
 * 
 * @param       const void*:
 * @param       size_t:
 * @param       char[SHA512_DIGEST_STRING_LENGTH]:
 * @return		char*
*/
char* sha512_Data(const void*, size_t, char[SHA512_DIGEST_STRING_LENGTH]);

#ifdef __cplusplus
}
#endif

#endif
