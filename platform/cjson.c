#include "compat.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if ESP_PLATFORM
#include <cJSON.h>
#else
#include <cjson/cJSON.h>
#endif

int parse_chall_response(struct chall_response *response, const char *json) {
  cJSON *root = cJSON_Parse(json);
  if (!root) {
    errno = EINVAL; // Invalid JSON format
    return -1;
  }

  cJSON *challenge = cJSON_GetObjectItem(root, "challenge");
  cJSON *client_ip = cJSON_GetObjectItem(root, "client_ip");

  if (!cJSON_IsString(challenge) || !cJSON_IsString(client_ip)) {
    cJSON_Delete(root);
    errno = EINVAL; // Missing or invalid fields
    return -1;
  }

  response->token = strdup(challenge->valuestring);
  response->client_ip = strdup(client_ip->valuestring);

  cJSON_Delete(root);

  if (!response->token || !response->client_ip) {
    free_chall_response(response);
    return -1;
  }

  return 0;
}

int parse_portal_response(struct portal_response *response, const char *json) {
  cJSON *root = cJSON_Parse(json);
  if (!root) {
    errno = EINVAL; // Invalid JSON format
    return -1;
  }

  cJSON *ecode = cJSON_GetObjectItem(root, "ecode");
  cJSON *error = cJSON_GetObjectItem(root, "error");
  cJSON *error_msg = cJSON_GetObjectItem(root, "error_msg");

  if (!(cJSON_IsString(ecode) || cJSON_IsNumber(ecode)) || !cJSON_IsString(error) || !cJSON_IsString(error_msg)) {
    cJSON_Delete(root);
    errno = EINVAL; // Missing or invalid fields
    return -1;
  }

  response->error = strdup(error->valuestring);
  response->error_msg = strdup(error_msg->valuestring);
  if (cJSON_IsString(ecode)) {
    response->ecode = strdup(ecode->valuestring);
  } else {
    asprintf(&response->ecode, "%d", ecode->valueint);
  }

  cJSON_Delete(root);

  if (!response->error || !response->error_msg || !response->ecode) {
    free_portal_response(response);
    return -1;
  }

  return 0;
}

char *create_info_field(srun_handle handle) {
  cJSON *info = cJSON_CreateObject();
  if (!info) {
    errno = ENOMEM;
    return NULL;
  }

  cJSON_AddStringToObject(info, "username", handle->username);
  cJSON_AddStringToObject(info, "password", handle->password);
  cJSON_AddStringToObject(info, "ip", handle->client_ip);
  cJSON_AddNumberToObject(info, "acid", handle->ac_id);
  cJSON_AddStringToObject(info, "enc_ver", "srun_bx1");

  char *info_str = cJSON_PrintUnformatted(info);
  cJSON_Delete(info);

  if (!info_str) {
    errno = ENOMEM;
    return NULL;
  }

  char *ret = strdup(info_str);
  cJSON_free(info_str);
  return ret;
}
