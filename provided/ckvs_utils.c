#include <stdio.h>
#include <error.h>
#include "ckvs.h"
#include <math.h>



// TODO peut-être pas nécessaire de déclarer l'entête ici puisqu'un a un header file

void print_header(const struct ckvs_header* header){
    pps_printf("CKVS Header type       : %s", header->header_string);
    pps_printf("CKVS Header version    : %d", header->version);
    pps_printf("CKVS Header table_size : %d", header->table_size);
    pps_printf("CKVS Header threshold  : %d", header->threshold_entries);
    pps_printf("CKVS Header num_entries: %d ", header->num_entries);
}

//TODO ici il faut compléter la méthode SHA pour pouvoir print Auth et C2
void print_entry(const struct ckvs_entry* entry){
    pps_printf("\tKey   : %s", entry->key);
    //TODO strange warning, check with assistant, %change %llu to %lu
    pps_printf("\tValue : off %llu len %llu", (entry->value_off), (entry->value_len));
    //TODO const or not, initialise it empty?? correct with * ?
    //const char buffer[SHA256_PRINTED_STRLEN];

    print_SHA("hello", entry->auth_key);
    print_SHA("hello" , entry->c2);
}

void hex_encode(const uint8_t *in, size_t len, char *buf){
    for (size_t i = 0; i < len; ++i){
        //TODO is this & correct? is the + i correct?? replaces &buf
        //we write in buf the changed value of in[i]
        sprintf(buf + i,"%02x", in[i]);
    }
}

void SHA256_to_string(const struct ckvs_sha *sha, char *buf){
    //TODO, as in week 1, used for safety reasons, should we keep it?
   /* if (sha == NULL){
        return;
    }
    for (size_t j = 0; j < SHA256_PRINTED_STRLEN; ++j){
        printf("%02x", *sha[j]);
    }*/
    hex_encode(sha, SHA256_PRINTED_STRLEN, buf);
}

void print_SHA(const char *prefix, const struct ckvs_sha *sha){
    char buffer[SHA256_PRINTED_STRLEN];
    SHA256_to_string(sha, buffer);
    pps_printf("%-5s: %s\n", prefix, buffer);
}

