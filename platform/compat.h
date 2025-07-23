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

#endif
