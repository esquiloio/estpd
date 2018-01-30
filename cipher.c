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
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/err.h>

#include "cipher.h"
#include "log.h"

struct cipher_s
{
    uint8_t         type;
    EVP_CIPHER_CTX  encrypt_ctx;
    EVP_CIPHER_CTX  decrypt_ctx;
    HMAC_CTX        mac_ctx;
};

cipher_t*
cipher_alloc(uint8_t type, cipher_keys_t* keys)
{
    cipher_t*           cipher;
    size_t              keys_size;
    const EVP_CIPHER*   cipher_type;
    uint8_t*            cipher_key;
    const EVP_MD*       mac_type;
    uint8_t*            mac_key;
    int                 mac_len;

    keys_size = cipher_keys_size(type);
    if (!keys_size)
        return NULL;

    switch (type) {
        case CIPHER_TYPE_AES128_SHA1:
            cipher_type = EVP_aes_128_cbc();
            cipher_key = keys->aes128_sha1.cipher;

            mac_type = EVP_sha1();
            mac_key = keys->aes128_sha1.mac;
            mac_len = sizeof(keys->aes128_sha1.mac);

            break;

        case CIPHER_TYPE_AES256_SHA256:
            cipher_type = EVP_aes_256_cbc();
            cipher_key = keys->aes256_sha256.cipher;

            mac_type = EVP_sha256();
            mac_key = keys->aes256_sha256.mac;
            mac_len = sizeof(keys->aes256_sha256.mac);

            break;

        default:
            return NULL;
    }

    cipher = calloc(sizeof(*cipher), 1);
    if (!cipher) {
        free(cipher);
        return NULL;
    }

    if (EVP_EncryptInit_ex(&cipher->encrypt_ctx, cipher_type, NULL, cipher_key, NULL) != 1) {
        LOGSSL("cipher alloc");
        cipher_free(cipher);
        return NULL;
    }

    EVP_CIPHER_CTX_set_padding(&cipher->encrypt_ctx, 0);

    if (EVP_DecryptInit_ex(&cipher->decrypt_ctx, cipher_type, NULL, cipher_key, NULL) != 1) {
        LOGSSL("cipher alloc");
        cipher_free(cipher);
        return NULL;
    }

    EVP_CIPHER_CTX_set_padding(&cipher->decrypt_ctx, 0);

    if (HMAC_Init_ex(&cipher->mac_ctx, mac_key, mac_len, mac_type, NULL) != 1) {
        LOGSSL("cipher alloc");
        cipher_free(cipher);
        return NULL;
    }

    cipher->type = type;

    LOGBLOB("alloc cipher key", cipher_key, cipher_get_key_len(type));
    LOGBLOB("alloc mac key", mac_key, mac_len);

    return cipher;
}

bool
cipher_encrypt(cipher_t* cipher, uint8_t* iv, void* buffer, size_t len)
{
    int out_len;

    LOGBLOB("encrypt iv", iv, cipher_iv_size(cipher->type));
    LOGBLOB("encrypt plaintext", buffer, len);

    if (EVP_EncryptInit_ex(&cipher->encrypt_ctx, NULL, NULL, NULL, iv) != 1 ||
        EVP_EncryptUpdate(&cipher->encrypt_ctx, buffer, &out_len, buffer, len) != 1 ||
        EVP_EncryptFinal_ex(&cipher->encrypt_ctx, buffer + out_len, &out_len) != 1) {

        LOGSSL("cipher encrypt");
        return false;
    }

    LOGBLOB("encrypt ciphertext", buffer, len);

    return true;
}

bool
cipher_decrypt(cipher_t* cipher, uint8_t* iv, void* buffer, size_t len)
{
    int out_len;

    LOGBLOB("decrypt iv", iv, cipher_iv_size(cipher->type));
    LOGBLOB("decrypt ciphertext", buffer, len);

    if (EVP_DecryptInit_ex(&cipher->decrypt_ctx, NULL, NULL, NULL, iv) != 1 ||
        EVP_DecryptUpdate(&cipher->decrypt_ctx, buffer, &out_len, buffer, len) != 1 ||
        EVP_DecryptFinal_ex(&cipher->decrypt_ctx, buffer + out_len, &out_len) != 1) {

        LOGSSL("cipher decrypt");
        return false;
    }

    LOGBLOB("decrypt plaintext", buffer, len);

    return true;
}

bool
cipher_mac_verify(cipher_t* cipher, uint8_t* mac, void* buffer, size_t len)
{
    uint8_t         out_mac[CIPHER_MAX_HASH_LEN];
    unsigned int    out_len;

    LOGBLOB("verify mac", mac, cipher_mac_size(cipher->type));
    LOGBLOB("verify text", buffer, len);

    if (HMAC_Init_ex(&cipher->mac_ctx, NULL, 0, NULL, NULL) != 1 ||
        HMAC_Update(&cipher->mac_ctx, buffer, len) != 1 ||
        HMAC_Final(&cipher->mac_ctx, out_mac, &out_len) != 1) {

        LOGSSL("mac verify");
        return false;
    }

    LOGBLOB("verify result", out_mac, out_len);

    return (memcmp(mac, out_mac, out_len) == 0);
}

bool
cipher_mac_calc(cipher_t* cipher, uint8_t* mac, void* buffer, size_t len)
{
    unsigned int    out_len;

    LOGBLOB("calc text", buffer, len);

    if (HMAC_Init_ex(&cipher->mac_ctx, NULL, 0, NULL, NULL) != 1 ||
        HMAC_Update(&cipher->mac_ctx, buffer, len) != 1 ||
        HMAC_Final(&cipher->mac_ctx, mac, &out_len) != 1) {

        LOGSSL("mac calc");
        return false;
    }

    LOGBLOB("calc mac", mac, cipher_mac_size(cipher->type));

    return true;
}

size_t
cipher_keys_size(uint8_t type)
{
    switch (type) {
        case CIPHER_TYPE_AES128_SHA1:
            return sizeof(struct aes128_sha1_s);
        case CIPHER_TYPE_AES256_SHA256:
            return sizeof(struct aes256_sha256_s);
        default:
            return 0;
    }
}

size_t
cipher_iv_size(uint8_t type)
{
    return CIPHER_AES_IV_LEN;
}

size_t
cipher_block_size(uint8_t type)
{
    return CIPHER_AES_BLOCK_LEN;
}

size_t
cipher_mac_size(uint8_t type)
{
    switch (type) {
        case CIPHER_TYPE_AES128_SHA1:
            return CIPHER_SHA1_HASH_LEN;
        case CIPHER_TYPE_AES256_SHA256:
            return CIPHER_SHA256_HASH_LEN;
        default:
            return 0;
    }
}

uint8_t
cipher_get_type(cipher_t* cipher)
{
    return (cipher->type);
}

void
cipher_free(cipher_t* cipher)
{
    EVP_CIPHER_CTX_cleanup(&cipher->encrypt_ctx);
    EVP_CIPHER_CTX_cleanup(&cipher->decrypt_ctx);
    HMAC_CTX_cleanup(&cipher->mac_ctx);
    free(cipher);
}

