#include <stdio.h>
#include "error.h"
#include "ckvs.h"
#include "util.h"

void print_header(const struct ckvs_header* header){
    if(NULL == header){
        pps_printf("Error : Null pointer given");
        return;
    }
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
