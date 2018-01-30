/*
 * Esquilo Secure Tunneling Protocol Daemon (ESTP)
 * 
 * Copyright 2014-2018 Esquilo Corporation - https://esquilo.io/
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

#define CIPHER_AES_IV_LEN       16
#define CIPHER_MAX_IV_LEN       CIPHER_AES_IV_LEN

#define CIPHER_AES_BLOCK_LEN    16
#define CIPHER_MAX_BLOCK_LEN    CIPHER_AES_BLOCK_LEN

#define CIPHER_AES128_KEY_LEN   16
#define CIPHER_AES256_KEY_LEN   32
#define CIPHER_MAX_KEY_LEN      CIPHER_AES256_KEY_LEN

#define CIPHER_SHA1_HASH_LEN    20
#define CIPHER_SHA256_HASH_LEN  32
#define CIPHER_MAX_HASH_LEN     CIPHER_SHA256_HASH_LEN

#define CIPHER_TYPE_AES128_SHA1      0
#define CIPHER_TYPE_AES256_SHA256    1

typedef struct cipher_keys_s {
    union {
        struct aes128_sha1_s {
            uint8_t cipher[CIPHER_AES128_KEY_LEN];
            uint8_t mac[CIPHER_SHA1_HASH_LEN];
        } aes128_sha1;
        struct aes256_sha256_s {
            uint8_t cipher[CIPHER_AES256_KEY_LEN];
            uint8_t mac[CIPHER_SHA256_HASH_LEN];
        } aes256_sha256;
    };
} cipher_keys_t;

typedef struct cipher_s cipher_t;

cipher_t*
cipher_alloc(uint8_t type, cipher_keys_t* keys);

bool
cipher_encrypt(cipher_t* cipher, uint8_t* iv, void* buffer, size_t len);

bool
cipher_decrypt(cipher_t* cipher, uint8_t* iv, void* buffer, size_t len);

bool
cipher_mac_verify(cipher_t* cipher, uint8_t* mac, void* buffer, size_t len);

bool
cipher_mac_calc(cipher_t* cipher, uint8_t* mac, void* buffer, size_t len);

size_t
cipher_keys_size(uint8_t type);

size_t
cipher_iv_size(uint8_t type);

size_t
cipher_block_size(uint8_t type);

size_t
cipher_mac_size(uint8_t type);

uint8_t
cipher_get_type(cipher_t* cipher);

void
cipher_free(cipher_t* cipher);

