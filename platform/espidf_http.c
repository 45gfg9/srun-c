/* Copyright © 2023-2025 45gfg9 <45gfg9@45gfg9.net>
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the LICENSE file for more details.
 */

#if ESP_PLATFORM || ESP32

#include "compat.h"

#include <string.h>
#include <stdlib.h>
#include <esp_http_client.h>
#include <esp_crt_bundle.h>

// TODO: rewrite using event handler

char *request_get_body(const_srun_handle handle, const char *url) {
  char *response = NULL;
  esp_http_client_config_t config = {
      .url = url,
      .method = HTTP_METHOD_GET,
      .cert_pem = handle->cacert_pem,
      .cert_len = 0, // auto detect
      .crt_bundle_attach = esp_crt_bundle_attach,
      .disable_auto_redirect = true,
  };

  esp_http_client_handle_t client = esp_http_client_init(&config);
  if (esp_http_client_open(client, 0) == ESP_OK) {
    int content_length = esp_http_client_fetch_headers(client);
    if (content_length > 0) {
      response = (char *)malloc(content_length + 1);
      if (response) {
        int read_len = esp_http_client_read_response(client, response, content_length);
        if (read_len >= 0) {
          response[read_len] = '\0';
        } else {
          free(response);
          response = NULL;
        }
      }
    }
  }

  esp_http_client_cleanup(client);
  return response;
}

char *request_get_location(const_srun_handle handle, const char *url) {
  char *response = NULL;
  esp_http_client_config_t config = {
      .url = url,
      .method = HTTP_METHOD_GET,
      .cert_pem = handle->cacert_pem,
      .cert_len = 0, // auto detect
      .crt_bundle_attach = esp_crt_bundle_attach,
      .disable_auto_redirect = true,
  };

  esp_http_client_handle_t client = esp_http_client_init(&config);
  if (esp_http_client_open(client, 0) == ESP_OK) {
    esp_http_client_fetch_headers(client);
    int status_code = esp_http_client_get_status_code(client);
    if (status_code >= 300 && status_code < 400) {
      char *location = NULL;
      if (esp_http_client_get_header(client, "Location", &location) == ESP_OK && location) {
        response = strdup(location);
      }
    }
  }

  esp_http_client_cleanup(client);
  return response;
}

#endif
