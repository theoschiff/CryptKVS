/*
 * cryptkvs -- main ; argument parsing and dispatch ; etc.
 */

#include <stdio.h>
#include "error.h"
#include "ckvs_local.h"
#include "ckvs_utils.h"
#include "ckvs_client.h"
#include "ckvs_httpd.h"

#define HTTP_WORD "http"

typedef int (*ckvs_command)(const char* filename, int optargc, char* optargv[]);

struct ckvs_command_mapping{
    const char* name;
    const char* utilisation;
    ckvs_command function_local;
    ckvs_command function_url;
};

struct ckvs_command_mapping commands[] =
        {{"stats", "- cryptkvs [<database>|<url>] stats \n", ckvs_local_stats, ckvs_client_stats},
        {"get", "- cryptkvs [<database>|<url>] get <key> <password> \n", ckvs_local_get, ckvs_client_get},
        {"set", "- cryptkvs [<database>|<url>] set <key> <password> <filename> \n", ckvs_local_set, ckvs_client_set},
        {"new", "- cryptkvs [<database>|<url>] new <key> <password> \n", ckvs_local_new, ckvs_client_new},
         {"httpd", "- cryptkvs <database> httpd <url> \n", ckvs_httpd_mainloop, NULL}};

static void usage(const char *execname, int err)
{
    if(execname == NULL){
        return;
    }
    if (err == ERR_INVALID_COMMAND) {
        pps_printf("Available commands:\n");
        for(size_t i = 0; i < sizeof(commands)/ sizeof(struct ckvs_command_mapping); ++i){
            pps_printf("%s %s", commands[i].name,  commands[i].utilisation);
        }
        pps_printf("\n");
    } else if (err >= 0 && err < ERR_NB_ERR) {
        pps_printf("%s exited with error: %s\n\n\n", execname, ERR_MESSAGES[err]);
    } else {
        pps_printf("%s exited with error: %d (out of range)\n\n\n", execname, err);
    }
}

/**
 * @brief Runs the command requested by the user in the command line, or returns ERR_INVALID_COMMAND if the command is not found.
 *
 * @param argc (int) the number of arguments in the command line
 * @param argv (char*[]) the arguments of the command line, as passed to main()
 */
int ckvs_do_one_cmd(int argc, char *argv[])
{
    if(argc < 3){
        return ERR_INVALID_COMMAND;
    }
    M_REQUIRE_NON_NULL(argv);
    const char* db_filename_url = argv[1];
    const char* cmd = argv[2];

    int optargc = argc - 3;
    char** optargv = argv + 3;

    for(size_t i = 0; i < sizeof(commands)/ sizeof(struct ckvs_command_mapping); ++i){
        if(strncmp(cmd, commands[i].name, strlen(commands[i].name)) == 0){
            if(strncmp(db_filename_url, "http", strlen(HTTP_WORD)) == 0) {
                return commands[i].function_url(db_filename_url, optargc, optargv);
            }else{
                return commands[i].function_local(db_filename_url, optargc, optargv);
            }
        }
    }
    return ERR_INVALID_COMMAND;
}


#ifndef FUZZ
/**
 * @brief main function, runs the requested command and prints the resulting error if any.
 * @param argc
 * @param argv
 * @return error or not
 */
int main(int argc, char *argv[])
{
    int ret = ckvs_do_one_cmd(argc, argv);
    if (ret != ERR_NONE) {
        usage(argv[0], ret);
    }
    return ret;
}
#endif
