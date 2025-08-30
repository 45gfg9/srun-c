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

  esp_err_t err = esp_http_client_perform(client);
  if (err != ESP_OK) {
    srun_log_error("HTTP GET request failed: %s", esp_err_to_name(err));
  }

  esp_http_client_cleanup(client);
}

esp_err_t request_get_body_event_handler(esp_http_client_event_t *evt) {
  char **pbody = evt->user_data;
  if (evt->event_id == HTTP_EVENT_ON_HEADER && !strcasecmp(evt->header_key, "Content-Length")) {
    size_t content_length = strtoul(evt->header_value, NULL, 10);
    // it's unlikely that server responds with multiple Content-Length,
    // but just in case.
    if (*pbody) {
      free(*pbody);
    }
    *pbody = malloc(content_length + 1);
    if (*pbody == NULL) {
      return ESP_FAIL;
    }
    (*pbody)[0] = '\0';
  } else if (evt->event_id == HTTP_EVENT_ON_DATA) {
    strncat(*pbody, evt->data, evt->data_len);
  }
  return ESP_OK;
}

char *request_get_body(const_srun_handle handle, const char *url) {
  char *body = NULL;
  request(handle, url, request_get_body_event_handler, &body);
  return body;
}

static esp_err_t request_get_location_event_handler(esp_http_client_event_t *evt) {
  if (evt->event_id == HTTP_EVENT_ON_HEADER && !strcasecmp(evt->header_key, "Location")) {
    char **plocation = evt->user_data;
    if (*plocation) {
      free(*plocation);
    }
    *plocation = strdup(evt->header_value);
  }
  return ESP_OK;
}

char *request_get_location(const_srun_handle handle, const char *url) {
  char *location = NULL;
  request(handle, url, request_get_location_event_handler, &location);
  return location;
}

#endif
