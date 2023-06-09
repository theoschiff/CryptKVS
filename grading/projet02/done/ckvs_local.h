/**
 * @file ckvs_local.h
 * @brief ckvs_local -- operations on local databases
 *
 * @author E. Bugnion
 */

#pragma once

/* *************************************************** *
 * TODO WEEK 04                                        *
 * *************************************************** */

/**
 * @brief Opens the CKVS database at the given filename and executes the 'stats' command,
 * ie. prints information about the database.
 * DO NOT FORGET TO USE pps_printf to print the header/entries!!!
 *
 * @param filename (const char*) the path to the CKVS database to open
 * @param optargc (int) the number of arguments given to stats (should be 0)
 * @param optargv unused in this function but has to follow model
 * @return int, an error code
 */
int ckvs_local_stats(const char* filename, int optargc, char* optargv[]);

/* *************************************************** *
 * TODO WEEK 05                                        *
 * *************************************************** */
/**
 * @brief Opens the CKVS database at the given filename and executes the 'get' command,
 * ie. fetches, decrypts and prints the entry corresponding to the key and password.
 * DO NOT FORGET TO USE pps_printf to print to value!!!
 *
 * @param filename (const char*) the path to the CKVS database to open
 * @param optargc (int) the number of arguments given to stats (should be 2)
 * @param optargv (char* []) values of different arguments (key, password)
 * @return int, an error code
 */
int ckvs_local_get(const char* filename, int optargc, char* optargv[]);

/* *************************************************** *
 * TODO WEEK 06                                        *
 * *************************************************** */
/**
 * @brief Opens the CKVS database at the given filename and executes the 'set' command,
 * ie. fetches the entry corresponding to the key and password and
 * then sets the encrypted content of valuefilename as new content.
 *
 * @param filename (const char*) the path to the CKVS database to open
 * @param optargc (int) the number of arguments given to stats (should be 3)
 * @param optargv (char* []) values of different arguments (key, pwd, value_filename)
 * @return int, an error code
 */
int ckvs_local_set(const char* filename, int optargc, char* optargv[]);


/* *************************************************** *
 * TODO WEEK 07                                        *
 * *************************************************** */
/**
 * @brief Opens the CKVS database at the given filename and executes the 'new' command,
 * ie. creates a new entry with the given key and password.
 *
 * @param filename (const char*) the path to the CKVS database to open
 * @param optargc (int) the number of arguments given to stats (should be 2)
 * @param optargv (char* []) values of different arguments (key, password)
 * @return int, an error code
 */
int ckvs_local_new(const char* filename, int optargc, char* optargv[]);

/* *************************************************** *
 * TODO WEEK 09: Refactor ckvs_local_*** commands      *
 * *************************************************** */
