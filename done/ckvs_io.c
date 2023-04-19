#include <stdio.h>
#include <string.h>
#include "ckvs_io.h"
#include "ckvs_crypto.h"
#include <math.h>
#include <stdlib.h>

#define EPSILON 1e-10

int power_of_two(int table_size);

int verify_header(const struct ckvs_header *header);

int is_equal(double double1, double double2);

static int ckvs_write_entry_to_disk(struct CKVS *ckvs, uint32_t idx);

static uint32_t ckvs_hashkey(struct CKVS *ckvs, const char *key);

static int ckvs_write_header_to_disk(const struct CKVS *ckvs);


int ckvs_open(const char *filename, struct CKVS *ckvs) {
    M_REQUIRE_NON_NULL(filename);
    M_REQUIRE_NON_NULL(ckvs);

    ckvs->entries = NULL;
    ckvs->file = fopen(filename, "rb+");
    if (ckvs->file == NULL) {
        ckvs_close(ckvs);
        return ERR_IO;
    }
    size_t read = 0;
    struct ckvs_header header;
    read = fread(&header, sizeof(ckvs_header_t), 1, ckvs->file);

    if (read != 1) {
        ckvs_close(ckvs);
        return ERR_IO;
    }

    int header_ver = verify_header(&header);
    if (header_ver == 1) {
        ckvs_close(ckvs);
        return ERR_CORRUPT_STORE;
    }

    ckvs->header = header;
    ckvs->entries = calloc(ckvs->header.table_size, sizeof(ckvs_entry_t));
    if (ckvs->entries == NULL) {
        ckvs_close(ckvs);
        return ERR_OUT_OF_MEMORY;
    }
    for (size_t i = 0; i < ckvs->header.table_size; ++i) {
        read = fread(&ckvs->entries[i], sizeof(ckvs_entry_t), 1, ckvs->file);
        if (read != 1) {
            ckvs_close(ckvs);
            return ERR_IO;
        }
    }
    return ERR_NONE;
}

void ckvs_close(struct CKVS *ckvs) {
    if (ckvs == NULL) {
        debug_printf("CKVS NULL");
        return;
    }
    if (ckvs->file != NULL) {
        fclose(ckvs->file);
        ckvs->file = NULL;
    }
    free(ckvs->entries);
    ckvs->entries = NULL;
}

int ckvs_find_entry(struct CKVS *ckvs, const char *key, const struct ckvs_sha *auth_key, struct ckvs_entry **e_out) {
    M_REQUIRE_NON_NULL(ckvs);
    M_REQUIRE_NON_NULL(key);
    M_REQUIRE_NON_NULL(auth_key);
    M_REQUIRE_NON_NULL(e_out);

    uint32_t hash = ckvs_hashkey(ckvs, key);
    for (size_t i = 0; i < ckvs->header.table_size; ++i) {
        uint32_t tmp = ((unsigned int) i + hash) % (ckvs->header.table_size);

        if (ckvs->entries[tmp].key[0] == '\0') {
            *e_out = &ckvs->entries[tmp];
            return ERR_KEY_NOT_FOUND;
        }
        if (strncmp(ckvs->entries[tmp].key, key, CKVS_MAXKEYLEN) == 0) {
            if (ckvs_cmp_sha(&ckvs->entries[tmp].auth_key, auth_key) != 0) {
                return ERR_DUPLICATE_ID;
            }
            *e_out = &ckvs->entries[tmp];
            return ERR_NONE;
        }
    }
    return ERR_KEY_NOT_FOUND;
}

int read_value_file_content(const char *filename, char **buffer_ptr, size_t *buffer_size) {
    M_REQUIRE_NON_NULL(filename);
    M_REQUIRE_NON_NULL(buffer_ptr);
    M_REQUIRE_NON_NULL(buffer_size);
    FILE *entree;
    entree = fopen(filename, "rb");
    if (entree == NULL) {
        return ERR_IO;
    }
    if (fseek(entree, 0, SEEK_END) != 0) {
        fclose(entree);
        return ERR_IO;
    }

    long verify_ftell = ftell(entree);
    if (verify_ftell == -1) {
        fclose(entree);
        return ERR_IO;
    }
    *buffer_size = (size_t) verify_ftell;
    rewind(entree);
    *buffer_ptr = calloc(*buffer_size + sizeof(char), sizeof(char));
    if (*buffer_ptr == NULL) {
        *buffer_size = 0;
        fclose(entree);
        return ERR_OUT_OF_MEMORY;
    }
    size_t read = 0;
    read = fread(*buffer_ptr, 1, *buffer_size, entree);
    if (read != *buffer_size) {
        *buffer_size = 0;
        free(*buffer_ptr);
        *buffer_ptr = NULL;
        fclose(entree);
        return ERR_IO;
    }
    fclose(entree);
    return ERR_NONE;
}


int ckvs_write_encrypted_value(struct CKVS *ckvs, struct ckvs_entry *e, const unsigned char *buf, uint64_t buflen) {
    M_REQUIRE_NON_NULL(ckvs);
    M_REQUIRE_NON_NULL(e);
    M_REQUIRE_NON_NULL(buf);

    int error = fseek(ckvs->file, 0, SEEK_END);
    long offset = ftell(ckvs->file);
    if (offset == -1) {
        e->value_len = 0;
        e->value_off = 0;
        ckvs_close(ckvs);
        return error;
    }
    uint64_t lenWritten = fwrite(buf, sizeof(char), buflen, ckvs->file);
    if (error != 0) {
        e->value_len = 0;
        e->value_off = 0;
        ckvs_close(ckvs);
        return error;
    }
    if (lenWritten != buflen) {
        e->value_len = 0;
        e->value_off = 0;
        ckvs_close(ckvs);
        return ERR_IO;
    }
    e->value_len = lenWritten;
    e->value_off = (uint64_t) offset;
    uint32_t idx = (uint32_t) (e - ckvs->entries);
    error = ckvs_write_entry_to_disk(ckvs, idx);
    if (error != ERR_NONE) {
        ckvs_close(ckvs);
        return ERR_IO;
    }
    return ERR_NONE;
}

static int ckvs_write_entry_to_disk(struct CKVS *ckvs, uint32_t idx) {
    M_REQUIRE_NON_NULL(ckvs);
    unsigned long position = sizeof(ckvs_header_t) + idx * sizeof(ckvs_entry_t);
    if (fseek(ckvs->file, (long) position, SEEK_SET) != 0) {
        return ERR_IO;
    }

    if (fwrite(&ckvs->entries[idx], sizeof(ckvs_entry_t), 1, ckvs->file) != 1) {
        return ERR_IO;
    }
    return ERR_NONE;
}

int ckvs_new_entry(struct CKVS *ckvs, const char *key, struct ckvs_sha *auth_key, struct ckvs_entry **e_out) {
    M_REQUIRE_NON_NULL(ckvs);
    M_REQUIRE_NON_NULL(key);
    M_REQUIRE_NON_NULL(auth_key);
    M_REQUIRE_NON_NULL(e_out);

    ckvs_entry_t ckvsEntry;
    memset(&ckvsEntry, 0, sizeof(ckvs_entry_t));
    int error = 0;
    if (ckvs_find_entry(ckvs, key, auth_key, e_out) != ERR_KEY_NOT_FOUND) {
        return ERR_DUPLICATE_ID;
    }

    if (ckvs->header.num_entries + 1 > ckvs->header.threshold_entries) {
        return ERR_MAX_FILES;
    }
    //increment num entries
    ++ckvs->header.num_entries;
    if (strlen(key) > CKVS_MAXKEYLEN) {
        return ERR_INVALID_ARGUMENT;
    }

    strncpy(ckvsEntry.key, key, strlen(key));
    if (strlen(key) < CKVS_MAXKEYLEN) {
        ckvsEntry.key[strlen(key)] = '\0';
    }
    //ckvsEntry.auth_key = *auth_key;
    memcpy(&ckvsEntry.auth_key, auth_key, SHA256_DIGEST_LENGTH);

    **e_out = ckvsEntry;

    if ((error = ckvs_write_entry_to_disk(ckvs, (uint32_t) (*e_out - ckvs->entries)) != ERR_NONE)) {
        return error;
    }
    if ((error = ckvs_write_header_to_disk(ckvs)) != ERR_NONE) {
        return error;
    }

    return ERR_NONE;
}

static int ckvs_write_header_to_disk(const struct CKVS *ckvs) {
    M_REQUIRE_NON_NULL(ckvs);

    if (fseek(ckvs->file, 0, SEEK_SET) != 0) {
        return ERR_IO;
    }
    if (fwrite(&ckvs->header, sizeof(ckvs_header_t), 1, ckvs->file) != 1) {
        return ERR_IO;
    }

    return ERR_NONE;
}

static uint32_t ckvs_hashkey(struct CKVS *ckvs, const char *key) {
    ckvs_memrecord_t mr;
    memset(&mr, 0, sizeof(ckvs_memrecord_t));

    SHA256((const unsigned char *) key, strnlen(key, CKVS_MAXKEYLEN), mr.stretched_key.sha);
    uint32_t hash = *((uint32_t *) mr.stretched_key.sha);
    uint32_t LSB = (ckvs->header.table_size - 1);
    hash = hash & LSB;
    return hash;
}

/**
 * @brief this function can be used to verify if a header follows the right characteristics
 * it checks the prefix, the version and the table_size
 * @param header
 * @return 1 if the string prefix is incorrect, the header is not of verison 1, or if the table size is not a power of 2
 * @return 0 if the header is correct
 */
int verify_header(const struct ckvs_header *header) {
    M_REQUIRE_NON_NULL(header);
    int string_comparison = 0;
    string_comparison = strncmp(CKVS_HEADERSTRING_PREFIX, header->header_string, strlen(CKVS_HEADERSTRING_PREFIX));
    if ((string_comparison != 0) || (header->version != 1) || (power_of_two((int) header->table_size) == 0)) {
        return 1;
    }
    return 0;
}

/**
 * @brief function that cheks if the size of a table is a power of 2
 * @param table_size
 * @return 1 if the table's size is of power 2
 * @return 0 otherwise
 */
int power_of_two(int table_size) {
    if ((table_size & (table_size - 1)) && (table_size != 1)) {
        pps_printf("table size is not a power of 2");
        return 0;
    }
    return 1;
}

/**
 * Tests if two doubles are equal
 * @param double1
 * @param double2
 * @return 0 if false, and another int if true
 */
int is_equal(double double1, double double2) {
    return fabs(double1 - double2) < EPSILON;
}
