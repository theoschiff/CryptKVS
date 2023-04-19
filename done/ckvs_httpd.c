/**
 * @file ckvs_httpd.c
 * @brief webserver
 *
 * @author Edouard Bugnion
 */

#include "ckvs.h"
#include "ckvs_io.h"
#include "ckvs_utils.h"
#include "error.h"
#include "ckvs_httpd.h"
#include <assert.h>
#include "mongoose.h"
#include <json-c/json.h>
#include <string.h>
#include <assert.h>
#include <curl/curl.h>
#include "util.h"
#include "ckvs_local.h"
#include "ckvs_client.h"
#include <stdbool.h>


// Handle interrupts, like Ctrl-C
static int s_signo;

#define HTTP_ERROR_CODE 500
#define HTTP_OK_CODE 200
#define HTTP_FOUND_CODE 302
#define HTTP_NOTFOUND_CODE 404
#define BUFFER_SIZE 1024

static void handle_stats_call(struct mg_connection *nc, struct CKVS *ckvs,
                              _unused struct mg_http_message *hm);

static void handle_get_call(struct mg_connection *nc, struct CKVS *ckvs,
                            _unused struct mg_http_message *hm);

static void handle_set_call(struct mg_connection *nc, struct CKVS *ckvs,
                            _unused struct mg_http_message *hm);

static char *get_urldecoded_argument(struct mg_http_message *hm, const char *arg);

/**
 * @brief Sends an http error message
 * @param nc the http connection
 * @param err the error code corresponding the error message
*/
void mg_error_msg(struct mg_connection *nc, int err) {
    //w
    assert(err >= 0 && err < ERR_NB_ERR);
    mg_http_reply(nc, HTTP_ERROR_CODE, NULL, "Error: %s", ERR_MESSAGES[err]);
}

/**
 * @brief Handles server events (eg HTTP requests).
 * For more check https://cesanta.com/docs/#event-handler-function
 */
static void ckvs_event_handler(struct mg_connection *nc, int ev, void *ev_data, void *fn_data) {
    struct mg_http_message *hm = (struct mg_http_message *) ev_data;
    struct CKVS *ckvs = (struct CKVS *) fn_data;

    if (ev != MG_EV_POLL)
        debug_printf("Event received %d", ev);

    switch (ev) {
        case MG_EV_POLL:
        case MG_EV_CLOSE:
        case MG_EV_READ:
        case MG_EV_WRITE:
        case MG_EV_HTTP_CHUNK:
            break;

        case MG_EV_ERROR:
            debug_printf("httpd mongoose error \n");
            break;
        case MG_EV_ACCEPT:
            // students: no need to implement SSL
            assert(ckvs->listening_addr);
            debug_printf("accepting connection at %s\n", ckvs->listening_addr);
            assert (mg_url_is_ssl(ckvs->listening_addr) == 0);
            break;

        case MG_EV_HTTP_MSG:
            if (mg_http_match_uri(hm, "/stats") == true) {
                handle_stats_call(nc, ckvs, hm);
                break;
            }
            if (mg_http_match_uri(hm, "/get") == true) {
                handle_get_call(nc, ckvs, hm);
                break;
            }
            if (mg_http_match_uri(hm, "/set") == true) {
                handle_set_call(nc, ckvs, hm);
                break;
            }
            mg_error_msg(nc, NOT_IMPLEMENTED);
            break;

        default:
            fprintf(stderr, "ckvs_event_handler %u\n", ev);
            assert(0);
    }
}

/**
 * @brief Handles signal sent to program, eg. Ctrl+C
 */
static void signal_handler(int signo) {
    s_signo = signo;
}

// ========================================================================
static void handle_stats_call(struct mg_connection *nc, struct CKVS *ckvs,
                              _unused struct mg_http_message *hm) {

    if (nc == NULL) {
        mg_error_msg(nc, ERR_IO);
        return;
    }
    if (ckvs == NULL) {
        mg_error_msg(nc, ERR_IO);
        return;
    }

    //Adding all of the different parts of the header to our main json object
    json_object *main_object = json_object_new_object();
    int verify = 0;
    verify += json_object_object_add(main_object, "header_string", json_object_new_string(ckvs->header.header_string));
    verify += json_object_object_add(main_object, "version", json_object_new_int((int32_t) ckvs->header.version));
    verify += json_object_object_add(main_object, "table_size", json_object_new_int((int32_t) ckvs->header.table_size));
    verify += json_object_object_add(main_object, "threshold_entries",
                                     json_object_new_int((int32_t) ckvs->header.threshold_entries));
    verify += json_object_object_add(main_object, "num_entries",
                                     json_object_new_int((int32_t) ckvs->header.num_entries));
    if (verify != 0) {
        json_object_put(main_object);
        mg_error_msg(nc, ERR_IO);
        return;
    }
    json_object *keys_array = json_object_new_array();
    json_object *key = NULL;
    char copy[CKVS_MAXKEYLEN + 1] = "";
    //We only add the valuable entries to an array of keys
    for (size_t i = 0; i < CKVS_FIXEDSIZE_TABLE; ++i) {
        if (verify_entry(ckvs->entries[i]) == 1) {
            strncpy(copy, ckvs->entries[i].key, CKVS_MAXKEYLEN);
            key = json_object_new_string(copy);
            verify += json_object_array_add(keys_array, key);
        }
    }
    if (verify != 0) {
        mg_error_msg(nc, ERR_IO);
        json_object_put(main_object);
        //pps_printf("ERROR: error while adding header object");
        return;
    }

    //We add our keys array to our main json object
    verify += json_object_object_add(main_object, "keys", keys_array);
    if (verify != 0) {
        mg_error_msg(nc, ERR_IO);
        pps_printf("ERROR: error while adding header object");
        json_object_put(main_object);
        return;
    }

    //Getting a json string from our main json object
    const char *header = json_object_to_json_string(main_object);
    //Sending the message to the client
    mg_http_reply(nc, HTTP_OK_CODE, "Content-Type: application/json\r\n", "%s\n", header);
    json_object_put(main_object);
}

// ======================================================================
static void handle_get_call(struct mg_connection *nc, struct CKVS *ckvs,
                            _unused struct mg_http_message *hm) {
    if (nc == NULL) {
        mg_error_msg(nc, ERR_IO);
        return;
    }
    if (ckvs == NULL) {
        mg_error_msg(nc, ERR_IO);
        return;
    }
    //Getting the key part from our connection url
    char *key = get_urldecoded_argument(hm, "key");
    if (key == NULL) {
        mg_error_msg(nc, ERR_INVALID_ARGUMENT);
        curl_free(key);
        return;
    }

    //Getting the auth key part from our connection url
    char auth_key_unenc[SHA256_PRINTED_STRLEN] = "";
    if (mg_http_get_var(&hm->query, "auth_key", auth_key_unenc, BUFFER_SIZE) <= 0) {
        mg_error_msg(nc, ERR_IO);
        curl_free(key);
        return;
    }

    int error = ERR_NONE;
    ckvs_entry_t *ckvsEntry = NULL;
    ckvs_sha_t sha_of_auth;
    memset(&sha_of_auth, 0, sizeof(ckvs_sha_t));

    //Encoding our auth key
    if ((error = SHA256_from_string(auth_key_unenc, &sha_of_auth)) == -1) {
        mg_error_msg(nc, error);
        curl_free(key);
        return;
    }

    //Looking for our entry in the ckvs entries list, and if it exists storing it in ckvsEntry
    error = ckvs_find_entry(ckvs, key, &sha_of_auth, &ckvsEntry);
    if (error != ERR_NONE) {
        mg_error_msg(nc, error);
        curl_free(key);
        return;
    }
    if (ckvsEntry == NULL) {
        mg_error_msg(nc, ERR_NO_VALUE);
        curl_free(key);
        return;
    }

    if (ckvsEntry->value_len == 0) {
        mg_error_msg(nc, ERR_NO_VALUE);
        curl_free(key);
        return;
    }

    json_object *main_object = json_object_new_object();
    char *c2_encoded_str = calloc(SHA256_PRINTED_STRLEN, sizeof(char));
    if (c2_encoded_str == NULL) {
        json_object_put(main_object);
        mg_error_msg(nc, ERR_IO);
        curl_free(key);
        return;
    }
    //Transforming our c2 into a string
    SHA256_to_string(&ckvsEntry->c2, c2_encoded_str);

    int verify = 0;
    verify += json_object_object_add(main_object, "c2", json_object_new_string(c2_encoded_str));

    if (verify != 0) {
        c2_encoded_str = NULL;
        mg_error_msg(nc, ERR_IO);
        curl_free(key);
        json_object_put(main_object);
        free(c2_encoded_str);
        c2_encoded_str = NULL;
        return;
    }
    if (ckvsEntry->value_len == 0) {
        mg_error_msg(nc, ERR_IO);
        curl_free(key);
        free(c2_encoded_str);
        c2_encoded_str = NULL;
        json_object_put(main_object);
        return;
    }

    //Placing ourselves correctly in the file provided by ckvs our offset : value_of
    error = fseek(ckvs->file, (long) ckvsEntry->value_off, SEEK_SET);
    if (error != 0) {
        mg_error_msg(nc, error);
        curl_free(key);
        free(c2_encoded_str);
        c2_encoded_str = NULL;
        json_object_put(main_object);
        return;
    }


    unsigned char *data = calloc(ckvsEntry->value_len + 1, sizeof(char));
    if (data == NULL) {
        mg_error_msg(nc, ERR_IO);
        curl_free(key);
        free(c2_encoded_str);
        c2_encoded_str = NULL;
        json_object_put(main_object);
        return;
    }

    //Reading the corresponding data from the file
    size_t ok = fread(data, ckvsEntry->value_len, 1, ckvs->file);
    if (ok != 1) {
        curl_free(key);
        free(data);
        data = NULL;
        free(c2_encoded_str);
        c2_encoded_str = NULL;
        mg_error_msg(nc, ERR_IO);
        json_object_put(main_object);
        return;
    }

    char *encrypted_data = calloc(2 * ckvsEntry->value_len + 1, sizeof(char));
    if (encrypted_data == NULL) {
        free(data);
        data = NULL;
        mg_error_msg(nc, ERR_IO);
        curl_free(key);
        free(c2_encoded_str);
        c2_encoded_str = NULL;
        json_object_put(main_object);
        return;
    }
    //Encoding the data in hex format
    hex_encode(data, ckvsEntry->value_len, encrypted_data);

    //Adding a json string version of our encrypted data to our main json object
    verify += json_object_object_add(main_object, "data", json_object_new_string(encrypted_data));

    if (verify != 0) {
        free(data);
        data = NULL;
        mg_error_msg(nc, ERR_IO);
        curl_free(key);
        free(c2_encoded_str);
        c2_encoded_str = NULL;
        free(encrypted_data);
        encrypted_data = NULL;
        json_object_put(main_object);
        return;
    }

    //Getting a string from our main json object
    const char *main_reply = json_object_to_json_string(main_object);

    if (main_reply == NULL) {
        mg_error_msg(nc, ERR_IO);
        curl_free(key);
        free(data);
        data = NULL;
        free(c2_encoded_str);
        c2_encoded_str = NULL;
        free(encrypted_data);
        encrypted_data = NULL;
        json_object_put(main_object);
        return;
    }

    //Sending the reply to the client
    mg_http_reply(nc, HTTP_OK_CODE, "Content-Type: application/json\r\n", "%s\n", main_reply);
    curl_free(key);
    key = NULL;
    free(data);
    data = NULL;
    free(c2_encoded_str);
    c2_encoded_str = NULL;
    free(encrypted_data);
    encrypted_data = NULL;
    json_object_put(main_object);
    main_object = NULL;
}
// ======================================================================
/**
 * @brief extracts the specified argument arg from the HTML request
 * @param mg_http_message the htt
 */
static char *get_urldecoded_argument(struct mg_http_message *hm, const char *arg) {
    char *key_value = calloc(BUFFER_SIZE, sizeof(char));
    if (key_value == NULL) {
        pps_printf("key_value is null");
        return NULL;
    }

    //extracting the key from our request and placing it into key_value
    if (mg_http_get_var(&hm->query, arg, key_value, BUFFER_SIZE) <= 0) {
        free(key_value);
        key_value = NULL;
        return NULL;
    }

    //Starting a libcurl easy session
    CURL *curl = curl_easy_init();
    if (curl == NULL) {
        pps_printf("Error: Something went wrong with the curl initialisation");
        free(key_value);
        key_value = NULL;
        return NULL;
    }
    int outlength = 0;
    //Creating a url with the right format
    char *plain_url = curl_easy_unescape(curl, key_value, 0, &outlength);
    if (plain_url == NULL) {
        pps_printf("Error: failed to convert the given url to a plain string");
        free(key_value);
        key_value = NULL;
        return NULL;
    }

    //Ending the lib curl easy handle
    curl_easy_cleanup(curl);
    free(key_value);
    key_value = NULL;
    return plain_url;
}

// ======================================================================
int ckvs_httpd_mainloop(const char *filename, int optargc, char **optargv) {
    if (optargc < 1)
        return ERR_NOT_ENOUGH_ARGUMENTS;
    else if (optargc > 1)
        return ERR_TOO_MANY_ARGUMENTS;

    /* Create server */

    signal(SIGINT, signal_handler); //adds interruption signals to the signal handler
    signal(SIGTERM, signal_handler);

    struct CKVS ckvs;
    int err = ckvs_open(filename, &ckvs);

    if (err != ERR_NONE) {
        return err;
    }

    ckvs.listening_addr = optargv[0];

    struct mg_mgr mgr;
    struct mg_connection *c;

    mg_mgr_init(&mgr);

    c = mg_http_listen(&mgr, ckvs.listening_addr, ckvs_event_handler, &ckvs);
    if (c == NULL) {
        debug_printf("Error starting server on address %s\n", ckvs.listening_addr);
        ckvs_close(&ckvs);
        return ERR_IO;
    }

    debug_printf("Starting CKVS server on %s for database %s\n", ckvs.listening_addr, filename);

    while (s_signo == 0) {
        mg_mgr_poll(&mgr, 1000); //infinite loop as long as no termination signal occurs
    }
    mg_mgr_free(&mgr);
    ckvs_close(&ckvs);
    debug_printf("Exiting HTTPD server\n");
    return ERR_NONE;
}

static void handle_set_call(struct mg_connection *nc, struct CKVS *ckvs,
                            _unused struct mg_http_message *hm) {

    if (nc == NULL) {
        mg_error_msg(nc, ERR_IO);
        return;
    }
    if (ckvs == NULL) {
        mg_error_msg(nc, ERR_IO);
        return;
    }

    //Extracting the key from our request and placing it into key_value
    char *key = get_urldecoded_argument(hm, "key");
    if (key == NULL) {
        mg_error_msg(nc, ERR_INVALID_ARGUMENT);
        curl_free(key);
        return;
    }

    //Getting the decoded auth key from the query
    char auth_key_unenc[SHA256_PRINTED_STRLEN] = "";
    if (mg_http_get_var(&hm->query, "auth_key", auth_key_unenc, BUFFER_SIZE) <= 0) {
        mg_error_msg(nc, ERR_IO);
        curl_free(key);
        return;
    }


    int error = ERR_NONE;
    ckvs_entry_t *ckvsEntry = NULL;
    ckvs_sha_t sha_of_auth;
    memset(&sha_of_auth, 0, sizeof(ckvs_sha_t));

    //Encoding our auth
    if ((error = SHA256_from_string(auth_key_unenc, &sha_of_auth)) == -1) {
        mg_error_msg(nc, error);
        curl_free(key);
        return;
    }

    //Finding the corresponding entry in our ckvs entries list using the sha of the auth key
    error = ckvs_find_entry(ckvs, key, &sha_of_auth, &ckvsEntry);
    curl_free(key);
    if (error != ERR_NONE) {
        mg_error_msg(nc, error);
        return;
    }
    if (ckvsEntry == NULL) {
        mg_error_msg(nc, ERR_NO_VALUE);
        return;
    }

    //Extracting the name from the query
    char name[MAXNAMLEN] = "";
    if (mg_http_get_var(&hm->query, "name", name, BUFFER_SIZE) <= 0) {
        mg_error_msg(nc, ERR_IO);
        return;
    }

    //Creating the path to the directory /tmp/<name>
    char *path_to_dir = calloc(strlen("/tmp") + strlen(name) + 2, sizeof(char));
    if (path_to_dir == NULL) {
        mg_error_msg(nc, ERR_IO);
        return;
    }

    //First we add the /tmp to the path and
    strcat(path_to_dir, "/tmp");
    if (hm->body.len != 0) {
        //Building the first block (actually the only block)
        error = mg_http_upload(nc, hm, path_to_dir);
        if (error < 0) {
            mg_error_msg(nc, ERR_IO);
        }
    } else {
        size_t data_size = 0;
        //will read the file at filename and will allocate buffer c2_and_data to dump content in
        char *c2_and_data = NULL;
        strcat(path_to_dir, "/");
        strcat(path_to_dir, name);
        error = read_value_file_content(path_to_dir, &c2_and_data, &data_size);
        if (error != ERR_NONE) {
            free(c2_and_data);
            free(path_to_dir);
            mg_error_msg(nc, ERR_IO);
            return;
        }

        free(path_to_dir);
        path_to_dir = NULL;
        //parse to separate c2 and data to which we'll apply several operations
        json_object *str_object = json_tokener_parse(c2_and_data);
        free(c2_and_data);
        c2_and_data = NULL;
        if (str_object == NULL) {
            json_object_put(str_object);
            mg_error_msg(nc, ERR_IO);
            pps_printf("ERROR: json parsing is incomplete, NULL was returned\n");
            return;
        }

        json_object *c2_obj = NULL;

        error = json_header_call_check(str_object, "c2", &c2_obj);
        if (error != ERR_NONE) {
            json_object_put(str_object);
            mg_error_msg(nc, error);
            return;
        }

        const char *c2 = json_object_get_string(c2_obj);
        if (c2 == NULL) {
            json_object_put(str_object);
            mg_error_msg(nc, ERR_IO);
        }

        //will hex-decode the c2
        ckvs_sha_t c2_decoded;
        memset(&c2_decoded, 0, sizeof(ckvs_sha_t));
        if ((error = SHA256_from_string(c2, &c2_decoded)) == -1) {
            json_object_put(str_object);
            mg_error_msg(nc, error);
            return;
        }
        json_object *data_obj = NULL;

        error = json_header_call_check(str_object, "data", &data_obj);
        if (error != ERR_NONE) {
            json_object_put(str_object);
            mg_error_msg(nc, error);
            return;
        }

        const char *data = json_object_get_string(data_obj);
        if (c2 == NULL) {
            json_object_put(str_object);
            mg_error_msg(nc, ERR_IO);
        }

        //allocates memory to decode the data
        unsigned char *decoded_data = calloc(strlen(data) / 2 + 1, sizeof(uint8_t));
        if (decoded_data == NULL) {
            json_object_put(str_object);
            mg_error_msg(nc, ERR_IO);
            return;
        }
        int size_decoded = hex_decode(data, decoded_data);
        if (size_decoded == -1) {
            json_object_put(str_object);
            free(decoded_data);
            decoded_data = NULL;
            mg_error_msg(nc, ERR_IO);
            return;
        }

        ckvsEntry->c2 = c2_decoded;
        ckvs_write_encrypted_value(ckvs, ckvsEntry, decoded_data, (uint64_t) size_decoded);
        mg_http_reply(nc, HTTP_OK_CODE, "Content-Type: application/json\r\n", "%s", "");
        json_object_put(str_object);
        free(decoded_data);
        decoded_data = NULL;
    }
    free(path_to_dir);
    path_to_dir = NULL;
}



