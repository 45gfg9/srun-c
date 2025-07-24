/* Copyright © 2023-2025 45gfg9 <45gfg9@45gfg9.net>
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the LICENSE file for more details.
 */

#ifndef __SRUN_PLATFORM_COMPAT_H__
#define __SRUN_PLATFORM_COMPAT_H__

#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include "../srun.h"

struct srun_context {
  char *username;
  char *password;
  char *client_ip;
  char *auth_server;

  int ac_id;

  int quiet;
};

struct chall_response {
  char *challenge;
  char *client_ip;
};

/**
 * Sends a GET request to the specified URL.
 *
 * @param url The URL to send the request to. It can be freed after use.
 * @returns The response body, or NULL on error, in which case errno is set
 * appropriately. The returned string must be freed by the caller.
 */
char *request_get(const char *url);

/**
 * Parses the JSON response from the challenge request.
 *
 * @param json The JSON response to parse. It can be freed after use.
 * @param response A struct to hold the parsed challenge information.
 * Members of the struct must be freed by the caller.
 * If an error occurs, the struct is not modified.
 * @returns 0 on success, or -1 on error, in which case errno is set appropriately.
 */
int parse_chall_response(struct chall_response *response, const char *json);

/**
 * Creates the info field for the portal request.
 *
 * @param handle The srun handle.
 * @param challenge The challenge string.
 * @param chall_length The length of the challenge string.
 * @returns A newly allocated string containing the info field, or NULL on error,
 * in which case errno is set appropriately.
 * The caller is responsible for freeing the returned string.
 */
char *create_info_field(srun_handle handle);

/**
 * Computes the SHA-1 digest of the given data.
 *
 * @param data The input data to hash.
 * @param len The length of the input data.
 * @param digest A buffer to hold the resulting SHA-1 digest (20 bytes).
 * @returns The length of the digest (20), or 0 on error, in which case errno is set appropriately.
 */
size_t sha1_digest(const uint8_t *data, size_t len, uint8_t digest[static 20]);

/**
 * Computes the HMAC-MD5 digest of the given data using the specified key.
 *
 * @param key The HMAC key.
 * @param key_len The length of the key.
 * @param data The input data to hash.
 * @param data_len The length of the input data.
 * @param digest A buffer to hold the resulting HMAC-MD5 digest (16 bytes).
 * @returns The length of the digest (16), or 0 on error, in which case errno is set appropriately.
 */
size_t hmac_md5_digest(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len,
                       uint8_t digest[static 16]);

#endif
