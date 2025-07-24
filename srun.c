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
#include <assert.h>

#include "platform/compat.h"

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
 * @param msg_len The length of the message.
 * @param dst The destination array to hold the encoded message.
 * @param append_len If non-zero, appends the length of the message to the end of the encoded array.
 * @returns The number of 32-bit integers written to the destination array.
 */
static size_t s_encode(const uint8_t *msg, size_t msg_len, uint32_t *dst, int append_len) {
  // zero pad input
  size_t buf_len = ((msg_len + 3) / 4) * 4;
  uint8_t *buf = calloc(buf_len, 1);
  memcpy(buf, msg, msg_len);

  size_t i;
  for (i = 0; i < msg_len; i += 4) {
    dst[i / 4] = (buf[i + 3] << 24) | (buf[i + 2] << 16) | (buf[i + 1] << 8) | buf[i];
  }
  free(buf);

  if (append_len) {
    dst[i / 4] = msg_len;
  }
  return i / 4 + !!append_len;
}

/**
 * @brief Decodes a message from a 32-bit integer array.
 * Original name "l"
 *
 * @param msg The encoded message as a 32-bit integer array.
 * @param msg_len The length of the encoded message (number of 32-bit integers).
 * @param dst The destination buffer to hold the decoded message.
 * @param dst_len The length of the destination buffer.
 * @param include_len If non-zero, checks the last element of the message for the actual length.
 * @returns The number of bytes written to the destination buffer, or 0 if an error occurred.
 */
static size_t s_decode(const uint32_t *msg, size_t msg_len, uint8_t *dst, size_t dst_len, int include_len) {
  size_t ret_len = msg_len * 4;

  if (include_len) {
    // the actual length is stored in the last element of the message
    ret_len = msg[msg_len - 1];

    // check if the length is valid
    uint32_t expected_len = (msg_len - 1) * 4;
    if (ret_len < expected_len - 3 || ret_len > expected_len) {
      // if the length recorded in the last element does not match
      // the actual length of the message, return 0
      return 0;
    }
  }

  if (ret_len > dst_len) {
    // dst is not large enough
    return 0;
  }

  for (size_t i = 0; i < ret_len; i++) {
    dst[i] = msg[i / 4] >> (i % 4 * 8);
  }

  return ret_len;
}

// original name "xEncode"
static size_t x_encode(const uint8_t *src, size_t src_len, const uint8_t *key, size_t key_len, uint8_t *dst,
                       size_t dst_len) {
  if (src_len == 0) {
    return 0;
  }

  if (key_len > 16) {
    // only at most 16 bytes of key are used
    key_len = 16;
  }

  uint32_t n = (src_len + 3) / 4 + 1;
  uint32_t *encoded_msg = malloc(n * sizeof(uint32_t));
  uint32_t encoded_key[4] = {0};

  if (!encoded_msg) {
    errno = ENOMEM;
    return 0; // memory allocation failed
  }

  s_encode(src, src_len, encoded_msg, 1);
  s_encode(key, key_len, encoded_key, 0);

  for (uint32_t d = 0, q = 6 + 52 / n; q; q--) {
    uint32_t z = encoded_msg[n - 1];
    d += 0x9e3779b9;
    for (uint32_t p = 0; p < n; p++) {
      uint32_t y = encoded_msg[(p + 1) % n];
      encoded_msg[p] += (z >> 5 ^ y << 2) + (y >> 3 ^ z << 4 ^ d ^ y) + (encoded_key[(p ^ d >> 2) & 3] ^ z);
      z = encoded_msg[p];
    }
  }

  size_t ret_len = s_decode(encoded_msg, n, dst, dst_len, 0);

  free(encoded_msg);

  return ret_len;
}

/**
 * @brief Encodes a message into Base64 format.
 *
 * @param alpha The Base64 alphabet to use for encoding.
 * @param pad_char The character to use for padding (usually '=').
 * @param src The source message to encode.
 * @param src_len The length of the source message.
 * @param dst The destination buffer to hold the encoded message.
 * @param dst_len The length of the destination buffer.
 * @returns The number of bytes written to the destination buffer, including the trailing '\0'.
 */
static size_t b64_encode(const char alpha[static 64], char pad_char, const uint8_t *src, size_t src_len, char *dst,
                         size_t dst_len) {
  // check if the destination buffer is large enough
  size_t ret_len = ((src_len + 2) / 3) * 4 + 1;
  if (dst_len < ret_len) {
    return 0;
  }

  // zero pad input
  size_t buf_len = ((src_len + 2) / 3) * 3;
  uint8_t *buf = calloc(buf_len, 1);
  if (!buf) {
    errno = ENOMEM;
    return 0; // memory allocation failed
  }
  memcpy(buf, src, src_len);

  // encode
  for (size_t i = 0; i < buf_len; i += 3) {
    uint32_t n = (buf[i] << 16) | (buf[i + 1] << 8) | buf[i + 2];
    for (int j = 0; j < 4; j++) {
      dst[(i / 3) * 4 + j] = alpha[(n >> (18 - j * 6)) & 0x3f];
    }
  }
  free(buf);

  // add padding characters if necessary
  size_t mod = src_len % 3;
  if (mod == 1) {
    dst[ret_len - 3] = pad_char;
    dst[ret_len - 2] = pad_char;
  } else if (mod == 2) {
    dst[ret_len - 2] = pad_char;
  }

  dst[ret_len - 1] = '\0';

  return ret_len;
}

static char *url_encode(const char *str) {
  if (!str) {
    errno = EINVAL;
    return NULL;
  }

  // allocate enough memory: worst case every char is encoded as %XX (3x)
  size_t len = strlen(str);
  char *enc = malloc(len * 3 + 1); // +1 for null terminator
  if (!enc) {
    errno = ENOMEM;
    return NULL; // memory allocation failed
  }

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

static int json_strip_callback(char *buf) {
  char *json_start = strchr(buf, '{');
  char *json_end = strrchr(buf, '}');
  if (json_start && json_end && json_end > json_start) {
    memmove(buf, json_start, json_end - json_start + 1);
    buf[json_end - json_start + 1] = '\0';
    return 0;
  } else {
    return -1; // Invalid JSON format
  }
}

int srun_login(srun_handle handle) {
  if (!(handle->auth_server && handle->username && handle->password)) {
    return SRUNE_INVALID_CTX;
  }
  handle->ac_id = 3; // FIXME

  // 1. construct challenge request URL
  // callback parameter serves no purpose
  const unsigned long long req_time = (unsigned long long)time(NULL);
  const char *const chall_fmtstr = "%s" PATH_GET_CHAL "?callback=jQuery98"
                                   "&username=%s&ip=%s&_=%llu000";
  char *chall_url;
  if (asprintf(&chall_url, chall_fmtstr, handle->auth_server, handle->username, handle->client_ip, req_time) == -1) {
    fprintf(stderr, "Failed to construct challenge request URL\n");
    goto nomem_fail;
  }

  // 2. perform challenge request and get response
  char *resp_buf = request_get(chall_url);
  free(chall_url);

  // 3. parse challenge response
  struct chall_response chall;

  if (json_strip_callback(resp_buf) != 0 || parse_chall_response(&chall, resp_buf) != 0) {
    fprintf(stderr, "Invalid challenge response: %s\n", resp_buf);
    free(resp_buf);
    return SRUNE_NETWORK;
  }
  free(resp_buf);

  const size_t chall_len = strlen(chall.challenge);

  // 4. construct challenge response

  // 4.1. HMAC-MD5 of the user password
  uint8_t hmac_md5_buf[16];
  char hmac_md5_hex[33];

  hmac_md5_digest((const uint8_t *)handle->password, strlen(handle->password), (const uint8_t *)chall.challenge,
                  chall_len, hmac_md5_buf);
  for (unsigned int i = 0; i < 16; i++) {
    snprintf(&hmac_md5_hex[2 * i], 3, "%02hhx", hmac_md5_buf[i]);
  }

  // FIXME
  handle->client_ip = strdup(chall.client_ip);

  // 4.2. info field
  char *const info_str = create_info_field(handle);
  const size_t info_str_len = strlen(info_str);

  // 4.3. x_encode the info field
  const size_t xenc_info_len = ((info_str_len + 3) / 4 + 1) * 4;
  uint8_t *xenc_info = malloc(xenc_info_len);
  if (!xenc_info) {
x_encode_fail:
    free(info_str);
    free(chall.challenge);
    free(chall.client_ip);
nomem_fail:
    errno = ENOMEM;
    return SRUNE_SYSTEM;
  }
  x_encode((uint8_t *)info_str, info_str_len, (const uint8_t *)chall.challenge, chall_len, xenc_info, xenc_info_len);
  free(info_str);

  // 4.4. Base64 encode the x_encoded_info for updated info field
  // char b64enc_info[256] = "{SRBX1}";
  const size_t b64enc_info_len = ((xenc_info_len + 2) / 3) * 4;
  char *const b64enc_info = malloc(8 + b64enc_info_len); // "{SRBX1}" + '\0'
  if (!b64enc_info) {
    free(xenc_info);
    goto x_encode_fail;
  }
  strcpy(b64enc_info, "{SRBX1}");
  b64_encode("LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA", '=', xenc_info, xenc_info_len,
             b64enc_info + 7, b64enc_info_len + 1);
  free(xenc_info);

  // 4.5. the SHA-1 checksum
  char ac_id_str[12];
  snprintf(ac_id_str, sizeof ac_id_str, "%d", handle->ac_id);

  size_t sha1_msglen = 32                          // hmac_md5_hex length
                       + strlen(handle->username)  // username length
                       + strlen(handle->client_ip) // client_ip length
                       + strlen(ac_id_str)         // ac_id length
                       + strlen(CHALL_N)           // n length
                       + strlen(CHALL_TYPE)        // type length
                       + b64enc_info_len + 7       // info length (b64enc_info + "{SRBX1}")
                       + 7 * chall_len;            // 7 occurrences of chall.challenge

  char *sha1_msgbuf = malloc(sha1_msglen + 1);
  if (!sha1_msgbuf) {
    free(b64enc_info);
    goto x_encode_fail;
  }
  snprintf(sha1_msgbuf, sha1_msglen + 1, "%s%s%s%s%s%s%s%s%s%s%s%s%s%s", chall.challenge, handle->username,
           chall.challenge, hmac_md5_hex, chall.challenge, ac_id_str, chall.challenge, handle->client_ip,
           chall.challenge, CHALL_N, chall.challenge, CHALL_TYPE, chall.challenge, b64enc_info);

  free(chall.challenge);
  free(chall.client_ip);
  chall.challenge = NULL;
  chall.client_ip = NULL;

  uint8_t sha1_buf[20];
  char sha1_hex[41];
  sha1_digest((const uint8_t *)sha1_msgbuf, sha1_msglen, sha1_buf);
  free(sha1_msgbuf);
  for (unsigned int i = 0; i < sizeof sha1_buf; i++) {
    snprintf(&sha1_hex[2 * i], 3, "%02hhx", sha1_buf[i]);
  }

  // 5. construct portal request URL
  char *url_encoded_info = url_encode(b64enc_info);
  free(b64enc_info);
  if (!url_encoded_info) {
    fprintf(stderr, "Failed to URL encode info field\n");
    goto nomem_fail;
  }

  const char *const portal_fmtstr = "%s" PATH_PORTAL "?callback=jQuery98&n=%s&type=%s&_=%llu000"
                                    "&username=%s&password=%%7BMD5%%7D%s&ac_id=%d&ip=%s&chksum=%s&info=%s"
                                    "&action=login&os=Linux&name=Linux&double_stack=0";
  char *portal_url;
  if (asprintf(&portal_url, portal_fmtstr, handle->auth_server, CHALL_N, CHALL_TYPE, req_time, handle->username,
               hmac_md5_hex, handle->ac_id, handle->client_ip, sha1_hex, url_encoded_info)
      == -1) {
    fprintf(stderr, "Failed to construct portal request URL\n");
    goto nomem_fail;
  }
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
