#include "compat.h"

#include <mbedtls/md.h>

inline size_t sha1_digest(const uint8_t *data, size_t len, uint8_t digest[static 20]) {
  mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), data, len, digest);
  return 20;
}

inline size_t hmac_md5_digest(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len,
                              uint8_t digest[static 16]) {
  mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_MD5), key, key_len, data, data_len, digest);
  return 16;
}
