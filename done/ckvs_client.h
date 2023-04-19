/**
 * @file ckvs_client.h
 * @brief client-side operations over network
 * @author E Bugnion, A. Clergeot
 */
#pragma once

#include <json-c/json.h>

/**
 * @brief Performs the 'stats' command by connecting to the remote server at url.
 *
 * @param url (const char*) the url of the remote CKVS server
 * @param optargc (int) the number of optional arguments that are provided (should be 0)
 * @param optargv (char**) the values of optional arguments that were provided
 * @return int, error code
 */
int ckvs_client_stats(const char *url, int optargc, char **optargv);

/**
 * @brief Performs the 'get' command by connecting to the remote server at url.
 *
 * @param url (const char*) the url of the remote CKVS server
 * @param optargc (int) the number of optional arguments that are provided (should be 2)
 * @param optargv (char**) the values of optional arguments that were provided
 * @return int, error code
 */
int ckvs_client_get(const char *url, int optargc, char **optargv);

/**
 * @brief Performs the 'set' command by connecting to the remote server at url.
 *
 * @param url (const char*) the url of the remote CKVS server
 * @param optargc (int) the number of optional arguments that are provided (should be 3)
 * @param optargv (char**) the values of optional arguments that were provided
 * @return int, error code
 */
int ckvs_client_set(const char *url, int optargc, char **optargv);

/**
 * @brief Performs the 'new' command by connecting to the remote server at url.
 *
 * @param url (const char*) the url of the remote CKVS server
 * @param optargc (int) the number of optional arguments that are provided (should be 2)
 * @param optargv (char**) the values of optional arguments that were provided
 * @return int, error code
 */
int ckvs_client_new(const char *url, int optargc, char **optargv);

/**
 * @brief Gets the json_object associated with a given object field
 * and checks if there are no errors. If it's the case, prints an error message and returns an error code.
 * Also puts the json_object obj
 *
 * @param obj json object to extract the value from
 * @param str key of field name
 * @param val a pointer where to store a reference to the json_object associated with the given field name.
 * @return int, error code
 */
int json_header_call_check(json_object* obj, const char* str, json_object** val);