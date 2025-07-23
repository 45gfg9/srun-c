/* Copyright © 2023-2025 45gfg9 <45gfg9@45gfg9.net>
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the LICENSE file for more details.
 */

#ifndef __SRUN_PLATFORM_COMPAT_H__
#define __SRUN_PLATFORM_COMPAT_H__

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

struct chal_response {
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
int parse_chal_response(struct chal_response *response, const char *json);

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

#endif
