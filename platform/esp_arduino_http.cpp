/* Copyright © 2023-2025 45gfg9 <45gfg9@45gfg9.net>
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the LICENSE file for more details.
 */

#if ARDUINO && (ESP_PLATFORM || ESP32 || ESP8266)

#include "compat.h"

// Currently we just reuse ESP32 and ESP8266 code for as much as possible.
// If two APIs ever deviate too much, we do separate handling then.

#include <memory>

#if ESP8266
#include <WiFiClientSecure.h>
#include <ESP8266HTTPClient.h>
#else
#include <WiFiClient.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#endif

using client_req_func = char *(HTTPClient &client);

static char *request(const_srun_handle handle, const char *url, client_req_func *func) {
  std::unique_ptr<WiFiClient> pclient;
  HTTPClient http;

#if ESP8266
  X509List x509;
  if (strncmp(url, "https://", 8) == 0) {
    auto psecure = new WiFiClientSecure;
    pclient.reset(psecure);
    if (handle->cert_pem && handle->cert_pem[0]) {
      // cert MUST be configured for ESP8266 to work
      // if no cert is provided, the connection will fail
      // see ESP8266WiFi/src/WiFiClientSecureBearSSL.cpp
      x509.append(handle->cert_pem);
      psecure->setTrustAnchors(&x509);
    }
  } else {
    pclient.reset(new WiFiClient);
  }
#else
  // TODO: test & esp32_cert_bundle
  if (strncmp(url, "https://", 8) == 0) {
    auto psecure = new WiFiClientSecure;
    pclient.reset(psecure);
    if (handle->cacert_pem && handle->cacert_pem[0]) {
      psecure->setCACert(handle->cacert_pem);
    }
  } else {
    pclient.reset(new WiFiClient);
  }
#endif
  http.begin(*pclient, url);

  char *response = func(http);

  http.end();
  return response;
}

char *request_get_body(const_srun_handle handle, const char *url) {
  return request(handle, url, [](HTTPClient &http) -> char * {
    int httpCode = http.GET();
    if (httpCode > 0) {
      String payload = http.getString();
      return strdup(payload.c_str());
    }
    return nullptr;
  });
}

char *request_get_location(const_srun_handle handle, const char *url) {
  return request(handle, url, [](HTTPClient &http) -> char * {
    int httpCode = http.GET();
    if (httpCode >= 300 && httpCode < 400) {
      String location = http.getLocation();
      if (!location.isEmpty()) {
        return strdup(location.c_str());
      }
    }
    return nullptr;
  });
}

#endif
