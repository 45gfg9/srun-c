/* Copyright © 2023-2025 45gfg9 <45gfg9@45gfg9.net>
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the LICENSE file for more details.
 */

// see asprintf(3)
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif

// see strdup(3)
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 600
#endif

#include "srun.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <time.h>

#include "platform/compat.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>

#define srun_digest_update(hashctx, data, len) EVP_DigestUpdate((hashctx), (data), (len))

#define PATH_GET_CHAL "/cgi-bin/get_challenge"
#define PATH_PORTAL "/cgi-bin/srun_portal"
#define PATH_USER_INFO "/cgi-bin/rad_user_info"

#define CHALL_N "200"
#define CHALL_TYPE "1"

/**
 * @brief Encodes a message into a 32-bit integer array.
 * Original name "s"
 *
 * @param msg The message to encode.
 * @param msglen The length of the message.
 * @param dst The destination array to hold the encoded message.
 * @param append_len If non-zero, appends the length of the message to the end of the encoded array.
 * @returns The number of 32-bit integers written to the destination array.
 */
static size_t s_encode(const uint8_t *msg, size_t msglen, uint32_t *dst, int append_len) {
  // zero pad input
  size_t buflen = ((msglen + 3) / 4) * 4;
  uint8_t *buf = calloc(buflen, 1);
  memcpy(buf, msg, msglen);

  size_t i;
  for (i = 0; i < msglen; i += 4) {
    dst[i / 4] = (buf[i + 3] << 24) | (buf[i + 2] << 16) | (buf[i + 1] << 8) | buf[i];
  }
  free(buf);

  if (append_len) {
    dst[i / 4] = msglen;
  }
  return i / 4 + !!append_len;
}

/**
 * @brief Decodes a message from a 32-bit integer array.
 * Original name "l"
 *
 * @param msg The encoded message as a 32-bit integer array.
 * @param msglen The length of the encoded message (number of 32-bit integers).
 * @param dst The destination buffer to hold the decoded message.
 * @param dstlen The length of the destination buffer.
 * @param include_len If non-zero, checks the last element of the message for the actual length.
 * @returns The number of bytes written to the destination buffer, or 0 if an error occurred.
 */
static size_t s_decode(const uint32_t *msg, size_t msglen, uint8_t *dst, size_t dstlen, int include_len) {
  size_t retlen = msglen * 4;

  if (include_len) {
    // the actual length is stored in the last element of the message
    retlen = msg[msglen - 1];

    // check if the length is valid
    uint32_t expected_len = (msglen - 1) * 4;
    if (retlen < expected_len - 3 || retlen > expected_len) {
      // if the length recorded in the last element does not match
      // the actual length of the message, return 0
      return 0;
    }
  }

  if (retlen > dstlen) {
    // dst is not large enough
    return 0;
  }

  for (size_t i = 0; i < retlen; i++) {
    dst[i] = msg[i / 4] >> (i % 4 * 8);
  }

  return retlen;
}

// original name "xEncode"
static size_t x_encode(const uint8_t *src, size_t srclen, const uint8_t *key, size_t keylen, uint8_t *dst,
                       size_t dstlen) {
  if (srclen == 0) {
    return 0;
  }

  if (keylen > 16) {
    // only at most 16 bytes of key are used
    keylen = 16;
  }

  uint32_t n = (srclen + 3) / 4 + 1;
  uint32_t *encoded_msg = malloc(n * sizeof(uint32_t));
  uint32_t encoded_key[4] = {0};

  s_encode(src, srclen, encoded_msg, 1);
  s_encode(key, keylen, encoded_key, 0);

  for (uint32_t d = 0, q = 6 + 52 / n; q; q--) {
    uint32_t z = encoded_msg[n - 1];
    d += 0x9e3779b9;
    for (uint32_t p = 0; p < n; p++) {
      uint32_t y = encoded_msg[(p + 1) % n];
      encoded_msg[p] += (z >> 5 ^ y << 2) + ((y >> 3 ^ z << 4) ^ (d ^ y)) + (encoded_key[(p ^ d >> 2) & 3] ^ z);
      z = encoded_msg[p];
    }
  }

  size_t retlen = s_decode(encoded_msg, n, dst, dstlen, 0);

  free(encoded_msg);

  return retlen;
}

/**
 * @brief Encodes a message into Base64 format.
 *
 * @param alphabet The Base64 alphabet to use for encoding.
 * @param padchar The character to use for padding (usually '=').
 * @param src The source message to encode.
 * @param srclen The length of the source message.
 * @param dst The destination buffer to hold the encoded message.
 * @param dstlen The length of the destination buffer.
 * @returns The number of bytes written to the destination buffer, including the trailing '\0'.
 */
size_t b64_encode(const char alphabet[static 64], char padchar, const uint8_t *src, size_t srclen, char *dst,
                  size_t dstlen) {
  // check if the destination buffer is large enough
  size_t retlen = ((srclen + 2) / 3) * 4 + 1;
  if (dstlen < retlen) {
    return 0;
  }

  // zero pad input
  size_t buflen = ((srclen + 2) / 3) * 3;
  uint8_t *buf = calloc(buflen, 1);
  memcpy(buf, src, srclen);

  // encode
  for (size_t i = 0; i < buflen; i += 3) {
    uint32_t n = (buf[i] << 16) | (buf[i + 1] << 8) | buf[i + 2];
    for (int j = 0; j < 4; j++) {
      dst[(i / 3) * 4 + j] = alphabet[(n >> (18 - j * 6)) & 0x3f];
    }
  }
  free(buf);

  // add padding characters if necessary
  size_t mod = srclen % 3;
  if (mod == 1) {
    dst[retlen - 3] = padchar;
    dst[retlen - 2] = padchar;
  } else if (mod == 2) {
    dst[retlen - 2] = padchar;
  }

  dst[retlen - 1] = '\0';

  return retlen;
}

char *url_encode(const char *str) {
  if (!str)
    return NULL;

  // allocate enough memory: worst case every char is encoded as %XX (3x)
  size_t len = strlen(str);
  char *enc = malloc(len * 3 + 1); // +1 for null terminator

  char *penc = enc;

  for (; *str; str++) {
    unsigned char c = (unsigned char)*str;
    if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
      *penc++ = c;
    } else {
      sprintf(penc, "%%%02X", c);
      penc += 3;
    }
  }
  *penc = '\0';
  return enc;
}

srun_handle srun_create(void) {
  // allocate a new context
  srun_handle handle = calloc(1, sizeof(struct srun_context));
  srun_setopt(handle, SRUNOPT_CLIENT_IP, "0.0.0.0");
  return handle;
}

void srun_cleanup(srun_handle handle) {
  if (handle->password) {
    memset(handle->password, 0, strlen(handle->password));
  }
  free(handle->username);
  free(handle->password);
  free(handle->client_ip);
  free(handle->auth_server);
  free(handle);
}

void srun_setopt(srun_handle handle, srun_option option, ...) {
  va_list args;
  va_start(args, option);

  const char *src_str;

  // TODO: more robust realloc handling
  switch (option) {
    case SRUNOPT_AUTH_SERVER:
      src_str = va_arg(args, char *);
      handle->auth_server = realloc(handle->auth_server, strlen(src_str) + 1);
      strcpy(handle->auth_server, src_str);
      break;
    case SRUNOPT_USERNAME:
      src_str = va_arg(args, char *);
      handle->username = realloc(handle->username, strlen(src_str) + 1);
      strcpy(handle->username, src_str);
      break;
    case SRUNOPT_PASSWORD:
      src_str = va_arg(args, char *);
      handle->password = realloc(handle->password, strlen(src_str) + 1);
      strcpy(handle->password, src_str);
      break;
    case SRUNOPT_CLIENT_IP:
      src_str = va_arg(args, char *);
      handle->client_ip = realloc(handle->client_ip, strlen(src_str) + 1);
      strcpy(handle->client_ip, src_str);
      break;
    case SRUNOPT_QUIET:
      handle->quiet = va_arg(args, int);
      break;
  }

  va_end(args);
}

int srun_login(srun_handle handle) {
  if (!(handle->auth_server && handle->username && handle->password)) {
    return SRUNE_INVALID_CTX;
  }

  // 1. construct challenge request URL
  // callback parameter serves no purpose
  unsigned long long req_time = (unsigned long long)time(NULL);
  const char *const chal_fmtstr = "%s" PATH_GET_CHAL "?callback=jQuery98"
                                  "&username=%s&ip=%s&_=%llu000";
  char *challenge_url;
  asprintf(&challenge_url, chal_fmtstr, handle->auth_server, handle->username, handle->client_ip, req_time);

  // 2. perform challenge request and get response
  char *resp_buf = request_get(challenge_url);
  free(challenge_url);

  // TODO error handling
  char *json_start = strchr(resp_buf, '{');
  char *json_end = strrchr(resp_buf, '}');
  memmove(resp_buf, json_start, json_end - json_start + 1);
  resp_buf[json_end - json_start + 1] = '\0';

  fprintf(stderr, "Challenge response: %s\n", resp_buf);

  // 3. parse challenge response
  struct chal_response chall;
  if (parse_chal_response(&chall, resp_buf) != 0) {
    abort(); // FIXME
  }
  size_t chall_length = strlen(chall.challenge);

  free(resp_buf);

  // 4. construct challenge response

  // 4.1. HMAC-MD5 of the user password
  char md5_buf[33];
  unsigned int md_len = sizeof md5_buf / 2;

  HMAC(EVP_md5(), chall.challenge, (int)chall_length, (const uint8_t *)handle->password, strlen(handle->password),
       (uint8_t *)md5_buf + md_len, &md_len);
  for (unsigned int i = 0; i < md_len; i++) {
    snprintf(md5_buf + 2 * i, 3, "%02hhx", (uint8_t)md5_buf[md_len + i]);
  }

  // FIXME
  handle->client_ip = strdup(chall.client_ip);

  // 4.2. info field
  char *info_str = create_info_field(handle);

  // 4.3. x_encode the info field
  uint8_t x_encoded_info[128];
  size_t x_encoded_info_len = x_encode((uint8_t *)info_str, strlen(info_str), (const uint8_t *)chall.challenge,
                                       strlen(chall.challenge), x_encoded_info, sizeof x_encoded_info);
  free(info_str);

  // 4.4. Base64 encode the x_encoded_info for updated info field
  char b64_encoded_info[256] = "{SRBX1}";
  size_t b64_len = b64_encode("LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA", '=', x_encoded_info,
                              x_encoded_info_len, b64_encoded_info + 7, sizeof b64_encoded_info - 7)
                   - 1; // exclude the trailing '\0'

  // 4.5. the SHA-1 checksum
  EVP_MD_CTX *hashctx = EVP_MD_CTX_new();
  EVP_MD_CTX_reset(hashctx);
  EVP_DigestInit(hashctx, EVP_sha1());

  EVP_DigestUpdate(hashctx, chall.challenge, chall_length);
  EVP_DigestUpdate(hashctx, handle->username, strlen(handle->username));
  EVP_DigestUpdate(hashctx, chall.challenge, chall_length);
  EVP_DigestUpdate(hashctx, md5_buf, 32);
  EVP_DigestUpdate(hashctx, chall.challenge, chall_length);
  EVP_DigestUpdate(hashctx, "3", 1); // ac_id
  EVP_DigestUpdate(hashctx, chall.challenge, chall_length);
  EVP_DigestUpdate(hashctx, handle->client_ip, strlen(handle->client_ip));
  EVP_DigestUpdate(hashctx, chall.challenge, chall_length);
  EVP_DigestUpdate(hashctx, CHALL_N, strlen(CHALL_N)); // n
  EVP_DigestUpdate(hashctx, chall.challenge, chall_length);
  EVP_DigestUpdate(hashctx, CHALL_TYPE, strlen(CHALL_TYPE)); // type
  EVP_DigestUpdate(hashctx, chall.challenge, chall_length);
  EVP_DigestUpdate(hashctx, b64_encoded_info, b64_len + 7); // info

  char sha1_buf[41];
  md_len = sizeof sha1_buf / 2;
  EVP_DigestFinal(hashctx, (uint8_t *)sha1_buf + md_len, &md_len);
  for (unsigned int i = 0; i < md_len; i++) {
    snprintf(sha1_buf + 2 * i, 3, "%02hhx", (uint8_t)sha1_buf[md_len + i]);
  }
  EVP_MD_CTX_free(hashctx);

  fprintf(stderr, "check_sum: %s\n", sha1_buf);
  fprintf(stderr, "b64_encoded_info: %zu %s\n", b64_len + 7, b64_encoded_info);

  // 5. construct portal request URL
  char *url_encoded_info = url_encode(b64_encoded_info);

  const char *const portal_fmtstr =
      "%s" PATH_PORTAL "?callback=jQuery98&action=login&n=200&type=1&os=Linux&name=Linux&double_stack=0"
      "&_=%llu000&username=%s&password=%%7BMD5%%7D%s&ac_id=%d&ip=%s&chksum=%s&info=%s";
  char *portal_url;
  asprintf(&portal_url, portal_fmtstr, handle->auth_server, req_time, handle->username, md5_buf, 3, handle->client_ip,
           sha1_buf, url_encoded_info);
  free(url_encoded_info);

  fprintf(stderr, "Portal request URL: %s\n", portal_url);

  // 6. perform portal request
  resp_buf = request_get(portal_url);
  free(portal_url);

  fprintf(stderr, "Portal response: %s\n", resp_buf);

  // TODO
  free(resp_buf);
  return -1;
}
