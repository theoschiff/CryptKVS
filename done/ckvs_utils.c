#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include "error.h"
#include "ckvs.h"
#include "util.h"

void print_header(const struct ckvs_header* header){
    if(NULL == header){
        pps_printf("Error : Null pointer given");
        return;
    }
    //  printing all elements of the header
    pps_printf("CKVS Header type       : %s\n", header->header_string);
    pps_printf("CKVS Header version    : %d\n", header->version);
    pps_printf("CKVS Header table_size : %d\n", header->table_size);
    pps_printf("CKVS Header threshold  : %d\n", header->threshold_entries);
    pps_printf("CKVS Header num_entries: %d\n", header->num_entries);
}

void print_entry(const struct ckvs_entry* entry){
    if(NULL == entry){
        pps_printf("Error : Null pointer given");
        return;
    }
    //Printing all elements of an entry
    pps_printf("    Key   : " STR_LENGTH_FMT(32) "\n", entry->key);
    pps_printf("    Value : off %lu len %lu\n", (entry->value_off), (entry->value_len));
    print_SHA("    Auth  ", &entry->auth_key);
    print_SHA("    C2    ", &entry->c2);
}

void print_SHA(const char *prefix, const struct ckvs_sha *sha){
    if ((NULL == sha) || (prefix == NULL)){
        return;
    }
    char buffer[SHA256_PRINTED_STRLEN];
    //Encoding our sha in hex format
    SHA256_to_string(sha, buffer);
    pps_printf("%-5s: %s\n", prefix, buffer);
}

void SHA256_to_string(const struct ckvs_sha *sha, char *buf){
    if((NULL == sha) ||(NULL == buf)){
        pps_printf("Error : Null pointer given");
        return;
    }
    hex_encode((const uint8_t *)sha->sha, SHA256_DIGEST_LENGTH, buf);
}

int SHA256_from_string(const char* in, struct ckvs_sha* sha){
    M_REQUIRE_NON_NULL(in);
    M_REQUIRE_NON_NULL(sha);
    return hex_decode(in,  sha->sha);
}

int hex_decode(const char* input, uint8_t* output){
    if (input == NULL || output == NULL){
        return -1;
    }
    size_t begin = 0;
    int num_octects = 0;
    char new[3] = "";
    size_t length = strlen(input);
    if(strlen(input)%2 != 0){
        char even_output[3] = "";
        even_output[0] = '0';
        even_output[1] = input[0];
        even_output[2] = '\0';
        unsigned long conversion =  strtoul(even_output, NULL, 16);
        if(conversion == ULONG_MAX){
            return -1;
        }
        output[0] = (uint8_t) conversion;
        num_octects += 1;
        begin = 1;
    }

    for(size_t i = 0 + begin; i < (length); i += 1){
        //strncpy(new, input+2*i, 2);
        new[0] = input[i];
        new[1] = input[i+1];
        new[2] = '\0';
        ++i;
        unsigned long conversion =  strtoul(new, NULL, 16);
        if(conversion == ULONG_MAX){
            return -1;
        }
        output[i/2] = (uint8_t) conversion;
        num_octects += 1;
    }
    return num_octects;
}

void hex_encode(const uint8_t *in, size_t len, char *buf){
    if((NULL == in) ||(NULL == buf)){
        pps_printf("Error : Null pointer given");
        return;
    }
    for (size_t i = 0, j = 0 ; i < len; ++i, j += 2){
        sprintf(buf + j,"%02x", in[i]);
    }
}

int ckvs_cmp_sha(const struct ckvs_sha *a, const struct ckvs_sha *b){
    return memcmp(a, b, SHA256_DIGEST_LENGTH);
}