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

static void request(const_srun_handle handle, const char *url, http_event_handle_cb evt_handler, void *user_data) {
  esp_http_client_config_t config = {
      .url = url,
      .cert_pem = handle->cacert_pem,
      .cert_len = 0, // auto detect
      .method = HTTP_METHOD_GET,
      .disable_auto_redirect = true,
      .event_handler = evt_handler,
      .user_data = user_data,
      .use_global_ca_store = true,
      .crt_bundle_attach = esp_crt_bundle_attach,
  };

  esp_http_client_handle_t client = esp_http_client_init(&config);
  esp_http_client_perform(client);
  esp_http_client_cleanup(client);
}

struct get_body_response {
  int content_length;
  char *data;
};

esp_err_t request_get_body_event_handler(esp_http_client_event_t *evt) {
  struct get_body_response *response = evt->user_data;
  if (evt->event_id == HTTP_EVENT_ON_HEADER && !strcasecmp(evt->header_key, "Content-Length")) {
    response->content_length = (int)strtol(evt->header_value, NULL, 10);
  } else if (evt->event_id == HTTP_EVENT_ON_DATA) {
    if (response->data == NULL) {
      response->data = malloc(response->content_length + 1);
      if (response->data == NULL) {
        return ESP_FAIL;
      }
      response->data[0] = '\0';
    }
    strncat(response->data, evt->data, evt->data_len);
  }
  return ESP_OK;
}

char *request_get_body(const_srun_handle handle, const char *url) {
  struct get_body_response response = {};
  request(handle, url, request_get_body_event_handler, &response);
  return response.data;
}

static esp_err_t request_get_location_event_handler(esp_http_client_event_t *evt) {
  if (evt->event_id == HTTP_EVENT_ON_HEADER && !strcasecmp(evt->header_key, "Location")) {
    char **pserver = evt->user_data;
    if (*pserver) {
      free(*pserver);
    }
    *pserver = strdup(evt->header_value);
  }
  return ESP_OK;
}

char *request_get_location(const_srun_handle handle, const char *url) {
  char *server = NULL;
  request(handle, url, request_get_location_event_handler, &server);
  return server;
}

#endif
