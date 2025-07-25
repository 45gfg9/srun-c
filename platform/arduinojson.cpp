/* Copyright © 2023-2025 45gfg9 <45gfg9@45gfg9.net>
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the LICENSE file for more details.
 */

#include "compat.h"

#include <ArduinoJson.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

int parse_chall_response(struct chall_response *response, const char *json) {
#if ARDUINOJSON_VERSION_MAJOR >= 7
  JsonDocument doc;
#else
  DynamicJsonDocument doc(512);
#endif

  DeserializationError error = deserializeJson(doc, json);
  if (error) {
    if (error.code() == DeserializationError::NoMemory) {
      errno = ENOMEM;
    } else {
      errno = EINVAL;
    }
    return -1;
  }

  const char *challenge = doc["challenge"];
  const char *client_ip = doc["client_ip"];

  if (!challenge || !client_ip) {
    errno = EINVAL; // Missing or invalid fields
    return -1;
  }

  struct chall_response r;
  r.token = strdup(challenge);
  r.client_ip = strdup(client_ip);

  if (!r.token || !r.client_ip) {
    free_chall_response(&r);
    return -1;
  }

  *response = r;
  return 0;
}

int parse_portal_response(struct portal_response *response, const char *json) {
#if ARDUINOJSON_VERSION_MAJOR >= 7
  JsonDocument doc;
#else
  DynamicJsonDocument doc(512);
#endif

  DeserializationError error = deserializeJson(doc, json);
  if (error) {
    if (error.code() == DeserializationError::NoMemory) {
      errno = ENOMEM;
    } else {
      errno = EINVAL;
    }
    return -1;
  }

  JsonVariant ecode = doc["ecode"];
  JsonVariant error_msg = doc["error_msg"];
  JsonVariant error_str = doc["error"];

  if (!(ecode.is<int>() || ecode.is<const char *>()) || !error_msg.is<const char *>()
      || !error_str.is<const char *>()) {
    errno = EINVAL; // Missing or invalid fields
    return -1;
  }

  struct portal_response r;
  if (ecode.is<const char *>()) {
    r.ecode = strdup(ecode.as<const char *>());
  } else if (asprintf(&r.ecode, "%d", ecode.as<int>()) == -1) {
    // some error occurred
    r.ecode = NULL;
  }
  r.error = strdup(error_str.as<const char *>());
  r.error_msg = strdup(error_msg.as<const char *>());

  if (!r.ecode || !r.error || !r.error_msg) {
    free_portal_response(&r);
    return -1;
  }

  *response = r;
  return 0;
}

char *create_info_field(const srun_handle handle) {
#if ARDUINOJSON_VERSION_MAJOR >= 7
  JsonDocument doc;
#else
  DynamicJsonDocument doc(256);
#endif
  doc["username"] = handle->username;
  doc["password"] = handle->password;
  doc["ip"] = handle->client_ip;
  doc["acid"] = handle->ac_id;
  doc["enc_ver"] = "srun_bx1";

  size_t capacity = measureJson(doc) + 1;
  char *info_str = new char[capacity];
  if (!info_str) {
    return NULL;
  }
  serializeJson(doc, info_str, capacity);
  return info_str;
}
