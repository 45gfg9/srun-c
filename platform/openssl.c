/* Copyright © 2023-2025 45gfg9 <45gfg9@45gfg9.net>
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the LICENSE file for more details.
 */

#include "compat.h"
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

inline size_t sha1_digest(const uint8_t *data, size_t len, uint8_t digest[static 20]) {
  SHA1(data, len, digest);
  return 20;
}

inline size_t hmac_md5_digest(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len,
                              uint8_t digest[static 16]) {
  unsigned int md_len = 16;
  HMAC(EVP_md5(), key, (int)key_len, data, data_len, digest, &md_len);
  if (md_len != 16) {
    errno = EINVAL; // Invalid length
    return 0;
  }
  return 16;
}
