
#include <stdio.h>
#include <error.h>
#include "ckvs.h"
#include <math.h>

int ckvs_local_stats(const char *filename);
int power_of_two(int table_size);
int verify_header(const struct ckvs_header* header);
int verify_entry(const ckvs_entry_t ckvsEntry);

int ckvs_local_stats(const char *filename){
    int erreur = 0;
    FILE *file = fopen(filename, "r");
    if(file == NULL){
        //TODO utiliser pps_printf ou fprintf
        fprintf(stderr, "Erreur : impossible de lire le fichier suivant : %s\n", filename);
        return ERR_IO;
    }
    while(!feof(file) && !ferror(file)){
        int read;
        struct ckvs_header header;
        read = fscanf(file, "%s %u %u %u %u", header.header_string,
                      &header.version, &header.table_size, &header.threshold_entries, &header.num_entries);
        if(read != 5){
            //TODO fprintf in stderr or in file?
            fprintf(stderr, "couldn't read the file correctly.");
            return ERR_IO;
        }
        //TODO had a warning and put &header instead
        int header_ver = verify_header(&header);
        if((header_ver == -1)||(header_ver == -2)){
            return ERR_CORRUPT_STORE;
        }
        print_header(&header);

        ckvs_entry_t ckvsEntry[CKVS_FIXEDSIZE_TABLE];
        for(int i = 0; i < CKVS_FIXEDSIZE_TABLE; ++i){
            read = fscanf(file, "%s %d %d %llu %llu" , ckvsEntry[i].key, ckvsEntry[i].value_off, ckvsEntry[i].value_len; ckvsEntry[i].auth_key, ckvsEntry[i].c2);
            if(read != 5){
                return ERR_IO;
            }
            //TODO verify errors
            if(verify_entry(ckvsEntry[i].key) == 1){
                print_entry(ckvsEntry[i]);
            }
        }
        return ERR_NONE;
    }

}

/**
 * @brief this function can be used to verify if a header follows the right characteristics
 * it checks the prefix, the version and the table_size
 * @param header
 * @return -1 if the string prefix is incorrect, the header is not of verison 1, or if the table size is not a power of 2
 * @return -2 if the size of the table is different to the fixed value CKVS_FIXEDSIZE_TABLE
 * @return 1 if the header is correct
 */
int verify_header(const struct ckvs_header* header){

    //Checks if the prefix is correct
    int string_comparison = 0;
    string_comparison = strncmp(CKVS_HEADERSTRING_PREFIX, header->header_string);
    if ((string_comparison != 0)||(header->version != 1) || (power_of_two(header->table_size))){
        return (-1);
    }
    if(header->table_size != CKVS_FIXEDSIZE_TABLE){
        return -2;
    }
    return 1;
}

/**
 * @brief function that verifies if a key of an entry is valid or not
 * @param ckvsEntry
 * @param number_entries
 * @return -1 if a key is empty
 * @return 1 if all keys are valid
 */
int verify_entry(const ckvs_entry_t ckvsEntry){
    if (strlen(ckvsEntry.key) != 0){
        return -1;
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
    /*if (ceil(log2(table_size))==floor(log2(table_size))){
        return 1;
    }*/
    for(int i = 1; i < INT32_MAX; i*=2){
        if(table_size == i){
            return 1;
        }
    }
    fprintf("table size is not a power of 2");
    return 0;
}
