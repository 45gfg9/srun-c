/* Copyright © 2023-2025 45gfg9 <45gfg9@45gfg9.net>
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the LICENSE file for more details.
 */

#ifndef __SRUN_H__
#define __SRUN_H__

#ifdef __cplusplus
extern "C" {
#endif

enum srun_verbosity {
  /**
   * @brief Suppress all output. Print only critical errors.
   */
  SRUN_VERBOSITY_SILENT,

  /**
   * @brief Default verbosity level. Print connection status.
   */
  SRUN_VERBOSITY_NORMAL,

  /**
   * @brief Increased verbosity level. Print detailed connection status.
   */
  SRUN_VERBOSITY_VERBOSE,

  /**
   * @brief Maximum verbosity level. Print all messages and library debug information.
   */
  SRUN_VERBOSITY_DEBUG,
};

typedef struct srun_context *srun_handle;

typedef enum srun_option {
  /**
   * Authentication server URL. Required.
   * Type: char *
   */
  SRUNOPT_AUTH_SERVER,

  /**
   * Username. Required for login.
   * Type: char *
   */
  SRUNOPT_USERNAME,

  /**
   * Password. Required for login.
   * Type: char *
   */
  SRUNOPT_PASSWORD,

  /**
   * Server certificate. PEM format. This field is NOT copied.
   * Required if the server uses HTTPS.
   * On ESP32, see also SRUNOPT_USE_ESP_CRT_BUNDLE.
   * Type: const char *
   */
  // SRUNOPT_SERVER_CERT,

  /**
   * Set to 1 to use ESP x509 certificate bundle.
   * This option is ignored, if SRUNOPT_SERVER_CERT is set.
   * Setting this option on non-ESP platforms will have no effect.
   * Type: int
   */
  // SRUNOPT_USE_ESP_CRT_BUNDLE,

  /**
   * Client IP. Optional for login.
   * Leave unset to use the default assigned IP.
   * Type: char *
   */
  SRUNOPT_CLIENT_IP,

  /**
   * Verbosity level. See enum srun_verbosity.
   * Default is SRUN_VERBOSITY_SILENT.
   * Type: int
   */
  SRUNOPT_VERBOSITY,
} srun_option;

/**
 * Success.
 */
#define SRUNE_OK 0

/**
 * Network error.
 */
#define SRUNE_NETWORK (-1)

/**
 * Invalid context (missing fields).
 */
#define SRUNE_INVALID_CTX (-2)

/**
 * System error. See errno.
 */
#define SRUNE_SYSTEM (-3)

/**
 * Create a new srun handle. This handle must be freed by `srun_cleanup`.
 *
 * @return A new srun handle
 */
srun_handle srun_create(void);

void srun_setopt(srun_handle handle, srun_option option, ...);
/**
 * Set option of srun handle.
 *
 * @param context srun context
 * @param option
 * @param value
 */
#define srun_setopt(handle, option, value) srun_setopt(handle, option, value)

/**
 * Perform login. The username, password and auth server must be set.
 *
 * @param handle srun handle
 * @return SRUNE_OK if logged in successfully or device already online;
 *         gateway error code or library defined error code otherwise
 */
int srun_login(srun_handle handle);

/**
 * Logout from this session.
 *
 * Auth server needs to be set; the certificate must be set too if the server uses HTTPS.
 * No other fields are required.
 *
 * @param handle srun handle
 * @return SRUNE_OK if logged out successfully;
 *         SRUNE_NETWORK if network error
 */
int srun_logout(srun_handle handle);

/**
 * Free all allocated resources held by this handle. You are encouraged to set handle to NULL after this call.
 *
 * @param context srun context
 */
void srun_cleanup(srun_handle context);

#ifdef __cplusplus
}
#endif

#endif
