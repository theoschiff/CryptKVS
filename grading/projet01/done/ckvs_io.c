#include <stdio.h>
#include <string.h>
#include "ckvs_io.h"
#include <math.h>
#include <stdlib.h>

#define EPSILON 1e-10

int power_of_two(int table_size);
int verify_header(const struct ckvs_header* header);
int is_equal(double double1, double double2);
static int ckvs_write_entry_to_disk(struct CKVS *ckvs, uint32_t idx);


int ckvs_open(const char *filename, struct CKVS *ckvs){
    M_REQUIRE_NON_NULL(filename);
    M_REQUIRE_NON_NULL(ckvs);

    ckvs->file = fopen(filename, "rb+");
    if(ckvs->file == NULL){
        ckvs_close(ckvs);
        return ERR_IO;
    }
    size_t read = 0;
    struct ckvs_header header;
    read += fread(&header.header_string, sizeof(header.header_string),1, ckvs->file);
    read += fread(&header.version, sizeof(header.version), 1, ckvs->file);
    read += fread(&header.table_size, sizeof(header.table_size), 1, ckvs->file);
    read += fread(&header.threshold_entries, sizeof(header.threshold_entries), 1, ckvs->file);
    read += fread(&header.num_entries, sizeof(header.num_entries), 1, ckvs->file);

    if(read != 5){
        ckvs_close(ckvs);
        return ERR_IO;
    }

    int header_ver = verify_header(&header);
    if((header_ver == -1)||(header_ver == -2)){
        ckvs_close(ckvs);
        return ERR_CORRUPT_STORE;
    }

    ckvs->header = header;

    for(int i = 0; i < CKVS_FIXEDSIZE_TABLE; ++i){
        read = fread(&ckvs->entries[i], sizeof(ckvs_entry_t), 1, ckvs->file);
        if(read != 1){
            ckvs_close(ckvs);
            return ERR_IO;
        }
    }
    return ERR_NONE;
}

void ckvs_close(struct CKVS *ckvs){
    if (ckvs == NULL){
        debug_printf("CKVS NULL");
        return;
    }
    if (ckvs->file !=NULL) {
        fclose(ckvs->file);
        ckvs->file = NULL;
    }
}

int ckvs_find_entry(struct CKVS *ckvs, const char *key, const struct ckvs_sha *auth_key, struct ckvs_entry **e_out){
    M_REQUIRE_NON_NULL(ckvs);
    M_REQUIRE_NON_NULL(key);
    M_REQUIRE_NON_NULL(auth_key);
    M_REQUIRE_NON_NULL(e_out);
    for(int i = 0; i < CKVS_FIXEDSIZE_TABLE; ++i){
        if (strncmp(ckvs->entries[i].key, key, CKVS_MAXKEYLEN) == 0){
            if(ckvs_cmp_sha(&ckvs->entries[i].auth_key, auth_key) != 0){
                return ERR_DUPLICATE_ID;
            }
            *e_out = &ckvs->entries[i];
            return ERR_NONE;
        }
    }
    return ERR_KEY_NOT_FOUND;
}

int read_value_file_content(const char* filename, char** buffer_ptr, size_t* buffer_size){
    M_REQUIRE_NON_NULL(filename);
    M_REQUIRE_NON_NULL(buffer_ptr);
    M_REQUIRE_NON_NULL(buffer_size);
    FILE* entree;
    entree = fopen(filename, "rb");
    if(entree == NULL){
        return ERR_IO;
    }
    if (fseek(entree, 0,SEEK_END) !=0){
        fclose(entree);
        return ERR_IO;
    }
    *buffer_size = (size_t) ftell(entree);
    rewind(entree);
    *buffer_ptr = calloc(*buffer_size + sizeof(char), sizeof(char));
    if(*buffer_ptr == NULL){
        free(*buffer_ptr); //correcteur : free inutile car calloc a échoué (pas de memoire allouée)
        *buffer_ptr = NULL; //correcteur : il faudrait aussi mettre buffer_size à 0 (ou travailler sur une copie puis l'assigner à la fin si tout de passe bien)
        fclose(entree);
        return ERR_IO;
    }
    size_t read = 0;
    read = fread(*buffer_ptr, *buffer_size, 1, entree);
    if (read != 1){
        free(*buffer_ptr);
        *buffer_ptr = NULL;
        fclose(entree);
        return ERR_IO;
    }
    fclose(entree);
    return ERR_NONE;
}


int ckvs_write_encrypted_value(struct CKVS *ckvs, struct ckvs_entry *e, const unsigned char *buf, uint64_t buflen){
    M_REQUIRE_NON_NULL(ckvs);
    M_REQUIRE_NON_NULL(e);
    M_REQUIRE_NON_NULL(buf);

    int error = fseek(ckvs->file, 0, SEEK_END);
    long offset = ftell(ckvs->file);
    uint64_t lenWritten = fwrite(buf, sizeof(char), buflen, ckvs->file);
    if (error != 0){
        ckvs_close(ckvs);
        return error;
    }
    if(lenWritten != buflen){
        ckvs_close(ckvs);
        return ERR_IO;
    }
    e->value_len = lenWritten;
    e->value_off = (uint64_t) offset;
    uint32_t idx = (uint32_t) (e-ckvs->entries);
    error = ckvs_write_entry_to_disk(ckvs, idx);
    if(error != ERR_NONE){
        ckvs_close(ckvs);
        return ERR_IO;
    }
    return ERR_NONE;
}

static int ckvs_write_entry_to_disk(struct CKVS *ckvs, uint32_t idx){
    M_REQUIRE_NON_NULL(ckvs);
    //rewind(ckvs->file);
    int position = (int)(sizeof(ckvs_header_t) + idx*sizeof(ckvs_entry_t));
    //
    if (fseek(ckvs->file, position, SEEK_SET) != 0){
        return ERR_IO;
    }

    if (fwrite(&ckvs->entries[idx], sizeof(ckvs_entry_t), 1, ckvs->file) != 1){
        return ERR_IO;
    }
    return ERR_NONE;
}
// correcteur : vous devriez suivre le pattern d'erreur normal. 0 = pas d'erreur, si erreur : >0 comme definit dans le projet. 
/**
 * @brief this function can be used to verify if a header follows the right characteristics
 * it checks the prefix, the version and the table_size
 * @param header
 * @return -1 if the string prefix is incorrect, the header is not of verison 1, or if the table size is not a power of 2
 * @return -2 if the size of the table is different to the fixed value CKVS_FIXEDSIZE_TABLE
 * @return 1 if the header is correct
 */
int verify_header(const struct ckvs_header* header){
    M_REQUIRE_NON_NULL(header);
    int string_comparison = 0;
    string_comparison = strncmp(CKVS_HEADERSTRING_PREFIX, header->header_string, strlen(CKVS_HEADERSTRING_PREFIX));
    if ((string_comparison != 0) || (header->version != 1) || (power_of_two((int) header->table_size) == 0)){
        return -1;
    }
    if(header->table_size != CKVS_FIXEDSIZE_TABLE){
        return -2;
    }
    return 1;
}

/**
 * @brief function that cheks if the size of a table is a power of 2
 * @param table_size
 * @return 1 if the table's size is of power 2
 * @return 0 otherwise
 */
int power_of_two(int table_size){
    if (is_equal(ceil(log2(table_size)),floor(log2(table_size)))){
        return 1;
    }
    pps_printf("table size is not a power of 2");
    return 0;
}

/**
 * Tests if two doubles are equal
 * @param double1
 * @param double2
 * @return 0 if false, and another int if true
 */
int is_equal(double double1, double double2){
    return fabs(double1 - double2) < EPSILON;
}
