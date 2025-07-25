/* Copyright © 2023-2025 45gfg9 <45gfg9@45gfg9.net>
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the LICENSE file for more details.
 */

#ifndef __SRUN_PLATFORM_COMPAT_H__
#define __SRUN_PLATFORM_COMPAT_H__

#ifdef __cplusplus
extern "C" {
#endif

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

#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include "srun.h"

#ifndef srun_log
#define srun_log(target_lvl, handle_lvl, ...) \
  do {                                        \
    if ((handle_lvl) >= (target_lvl)) {       \
      fprintf(stderr, __VA_ARGS__);           \
    }                                         \
  } while (0)
#define srun_log_verbose(lvl, ...) srun_log(SRUN_VERBOSITY_VERBOSE, lvl, __VA_ARGS__)
#define srun_log_debug(lvl, ...) srun_log(SRUN_VERBOSITY_DEBUG, lvl, __VA_ARGS__)
#endif

struct srun_context {
  char *username;
  char *password;
  char *client_ip;
  char *auth_server;

  int ac_id;

  enum srun_verbosity verbosity;
};

struct chall_response {
  char *token;
  char *client_ip;
};

struct portal_response {
  char *ecode;
  char *error;
  char *error_msg;
};

static inline void free_chall_response(struct chall_response *resp) {
  if (resp) {
    free(resp->token);
    free(resp->client_ip);
    *resp = (struct chall_response) {};
  }
}

static inline void free_portal_response(struct portal_response *resp) {
  if (resp) {
    free(resp->ecode);
    free(resp->error);
    free(resp->error_msg);
    *resp = (struct portal_response) {};
  }
}

/**
 * Sends a GET request to the specified URL and retrieves the response body.
 *
 * @param url The URL to send the request to.
 * @returns The response body, or NULL and errno is set.
 * The returned string must be freed by the caller.
 */
char *request_get_body(const char *url);

/**
 * Sends a GET request to the specified URL and retrieves the Location header.
 *
 * @param url The URL to send the request to.
 * @returns The value of the Location header, or NULL if the header is not
 * present or an error occurs. The returned string must be freed by the caller.
 */
char *request_get_location(const char *url);

/**
 * Parses the JSON response from the challenge request.
 *
 * @param json The JSON response to parse. It can be freed after use.
 * @param response A struct to hold the parsed challenge information.
 * Members of the struct must be freed by the caller.
 * If an error occurs, the struct is not modified.
 * @returns 0 on success, or -1 and errno is set.
 */
int parse_chall_response(struct chall_response *response, const char *json);

/**
 * Parses the JSON response from the portal request.
 *
 * @param json The JSON response to parse. It can be freed after use.
 * @param response A struct to hold the parsed portal information.
 * Members of the struct must be freed by the caller.
 * If an error occurs, the struct is not modified.
 * @returns 0 on success, or -1 and errno is set.
 */
int parse_portal_response(struct portal_response *response, const char *json);

/**
 * Creates the info field for the portal request.
 *
 * @param handle The srun handle.
 * @param challenge The challenge string.
 * @param chall_length The length of the challenge string.
 * @returns A newly allocated string containing the info field, or NULL and errno is set.
 * The caller is responsible for freeing the returned string.
 */
char *create_info_field(const srun_handle handle);

/**
 * Computes the SHA-1 digest of the given data.
 *
 * @param data The input data to hash.
 * @param len The length of the input data.
 * @param digest A buffer to hold the resulting SHA-1 digest (20 bytes).
 * @returns The length of the digest (20), or 0 and errno is set.
 */
size_t sha1_digest(const uint8_t *data, size_t len, uint8_t digest[20]);

/**
 * Computes the HMAC-MD5 digest of the given data using the specified key.
 *
 * @param key The HMAC key.
 * @param key_len The length of the key.
 * @param data The input data to hash.
 * @param data_len The length of the input data.
 * @param digest A buffer to hold the resulting HMAC-MD5 digest (16 bytes).
 * @returns The length of the digest (16), or 0 and errno is set.
 */
size_t hmac_md5_digest(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t digest[16]);

#ifdef __cplusplus
}
#endif

#endif
