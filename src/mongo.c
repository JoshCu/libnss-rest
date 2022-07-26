#include <nss.h>
#include <pwd.h>
#include <grp.h>
#include <syslog.h>
#include <string.h>
#include <stdlib.h>
#include <libconfig.h>
#include <errno.h>
#include <curl/curl.h>
#include <json-c/json.h>

#define CURL_VERBOSE 1
#define CONFIG_FILE "/etc/security/mongonss.conf"

// Structure to hold the response the curl command
struct curl_output
{
    char *memory;
    size_t size;
};

// Stores output of CURL command into string
static size_t writecallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    struct curl_output *mem = (struct curl_output *)userp;

    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (ptr == NULL)
    {
        syslog(LOG_ERR, "Not enough memory (realloc returned NULL)");
        return 0;
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

// Takes the query part of the url and returns the response data
// e.g. pass in user/name/jc1104039 
// DO NOT include a '/' prefix
char *handle_url(char *url_suffix)
{
    // Config loading
    config_t config;
    const char *api_url, *username, *password;
    // Initiate config parser
    config_init(&config);
    if(!config_read_file(&config, CONFIG_FILE)) {
        syslog(LOG_ERR, "%s:%d - %s", config_error_file(&config), config_error_line(&config), config_error_text(&config));
        goto cleanup;
    }

    if (!config_lookup_string(&config, "api_url", &api_url)) {
        syslog(LOG_ERR, "No 'api_url' setting in configuration file.");
        goto cleanup;
    }

    if (!config_lookup_string(&config, "username", &username)) {
        syslog(LOG_ERR, "No 'username' setting in configuration file.");
        goto cleanup;
    }

    if (!config_lookup_string(&config, "password", &password)) {
        syslog(LOG_ERR, "No 'password' setting in configuration file.");
        goto cleanup;
    }
    // Config loading done
    long response_code;
    // Create query url
    char url[1024] = "";
    strcat(url, api_url);
    strcat(url, url_suffix);
    
    syslog(LOG_INFO, "query url : %s", url);

    struct curl_output data;
    data.size = 0;
    data.memory = malloc(4096); // Reasonable size initial buffer

    if (NULL == data.memory)
    {
        syslog(LOG_ERR, "Failed to allocate memory.\n");
        goto cleanup;
    }

    data.memory[0] = '\0';
    CURLcode res;
    CURL *curl;
    curl = curl_easy_init();
    if (curl)
    {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writecallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &data);
        curl_easy_setopt(curl, CURLOPT_USERNAME, username);
        curl_easy_setopt(curl, CURLOPT_PASSWORD, password);
        res = curl_easy_perform(curl);
        syslog(LOG_INFO, "curl response : %d", res);
        // This response is not a http status code
        // It's just from the curl command library 
        // Https://github.com/curl/curl/blob/master/include/curl/curl.h
        if (res != CURLE_OK)
        {
            fprintf(stderr, "curl_easy_perform() failed: %s\n",
                    curl_easy_strerror(res));
        }
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
        syslog(LOG_INFO, "response code  : %d", response_code);
        if (response_code != 200){
            data.memory = NULL;
        }

        curl_easy_cleanup(curl);
    }
    closelog();
    config_destroy(&config);
    return data.memory;
cleanup:
    closelog();
    config_destroy(&config);
    // Curling the api returns string "null" when no user is found
    // We must also return string null to match behaviour when config is broken
    return NULL;

}

// Name : string representation of a user's name e.g. jc1104039
// Result : structure we fill out with the user's data
enum nss_status _nss_mongo_getpwnam_r(const char *name, struct passwd *result, char *buffer, size_t buflen, int *errnop)
{
    int retval;
    // Initiate logging
    setlogmask(LOG_UPTO(LOG_INFO));
    openlog("mongo_nss", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
    syslog(LOG_INFO, "getpwnam");
    syslog(LOG_INFO, "user_name : %s,", name);

    char url[1024] = "users/name/";
    strcat(url, name);

    char *data;
    syslog(LOG_INFO, "buflen: %d", buflen);
    data = handle_url(url);
    syslog(LOG_INFO, "response: %s", data);
    if (data != NULL)
    {
        // Delare json objects for each variable
        struct json_object *parsed_json;
        parsed_json = json_tokener_parse(data);
        struct json_object *_name;
        struct json_object *_passwd;
        struct json_object *_uid;
        struct json_object *_gid;
        struct json_object *_gecos;
        struct json_object *_dir;
        struct json_object *_shell;

        // Import values into json objects
        json_object_object_get_ex(parsed_json, "pw_name", &_name);
        json_object_object_get_ex(parsed_json, "pw_passwd", &_passwd);
        json_object_object_get_ex(parsed_json, "pw_uid", &_uid);
        json_object_object_get_ex(parsed_json, "pw_gid", &_gid);
        json_object_object_get_ex(parsed_json, "pw_gecos", &_gecos);
        json_object_object_get_ex(parsed_json, "pw_dir", &_dir);
        json_object_object_get_ex(parsed_json, "pw_shell", &_shell);

        strcpy(result->pw_name, json_object_get_string(_name));
        strcpy(result->pw_passwd ,json_object_get_string(_passwd));
        result->pw_uid = json_object_get_int(_uid);
        result->pw_gid = json_object_get_int(_gid);
        strcpy(result->pw_gecos,json_object_get_string(_gecos));
        strcpy(result->pw_dir,json_object_get_string(_dir));
        strcpy(result->pw_shell,json_object_get_string(_shell));

        retval = NSS_STATUS_SUCCESS;
        goto cleanup;
    }
    retval = NSS_STATUS_NOTFOUND;
cleanup:
    closelog();
    return retval;
}

// Name : uid representation of a user e.g. 2024922
// Result : structure we fill out with the user's data
enum nss_status _nss_mongo_getpwuid_r(__uid_t uid, struct passwd *result, char *buffer, size_t buflen, int *errnop)
{
    int retval;
    // Initiate logging
    setlogmask(LOG_UPTO(LOG_INFO));
    openlog("mongo_nss", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
    syslog(LOG_INFO, "getpwnuid");
    syslog(LOG_INFO, "user_id : %d,", uid);

    char struid[50];
    sprintf(struid, "%d", uid);
    char url[1024] = "users/id/";
    strcat(url, struid);

    char *data;

    data = handle_url(url);
    syslog(LOG_INFO, "response: %s", data);
    if (data != NULL)
    {
        // Delare json objects for each variable
        struct json_object *parsed_json;
        parsed_json = json_tokener_parse(data);
        struct json_object *_name;
        struct json_object *_passwd;
        struct json_object *_uid;
        struct json_object *_gid;
        struct json_object *_gecos;
        struct json_object *_dir;
        struct json_object *_shell;

        // Import values into json objects
        json_object_object_get_ex(parsed_json, "pw_name", &_name);
        json_object_object_get_ex(parsed_json, "pw_passwd", &_passwd);
        json_object_object_get_ex(parsed_json, "pw_uid", &_uid);
        json_object_object_get_ex(parsed_json, "pw_gid", &_gid);
        json_object_object_get_ex(parsed_json, "pw_gecos", &_gecos);
        json_object_object_get_ex(parsed_json, "pw_dir", &_dir);
        json_object_object_get_ex(parsed_json, "pw_shell", &_shell);

        strcpy(result->pw_name, json_object_get_string(_name));
        strcpy(result->pw_passwd ,json_object_get_string(_passwd));
        result->pw_uid = json_object_get_int(_uid);
        result->pw_gid = json_object_get_int(_gid);
        strcpy(result->pw_gecos,json_object_get_string(_gecos));
        strcpy(result->pw_dir,json_object_get_string(_dir));
        strcpy(result->pw_shell,json_object_get_string(_shell));

        retval = NSS_STATUS_SUCCESS;
        goto cleanup;
    }
    retval = NSS_STATUS_NOTFOUND;
cleanup:
    closelog();
    return retval;
}

// Name : string representation of a group's name e.g. RB1610093
// Result : structure we fill out with the groups's data
enum nss_status _nss_mongo_getgrnam_r(const char *name, struct group *result, char *buffer, size_t buflen, int *errnop)
{
    int retval;
    // Initiate logging
    setlogmask(LOG_UPTO(LOG_INFO));
    openlog("mongo_nss", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
    syslog(LOG_INFO, "getgrnam");
    syslog(LOG_INFO, "group_name : %s,", name);

    char url[1024] = "groups/name/";
    strcat(url, name);

    struct group fakeGroup;
    char *data;
    char **members = malloc(4096);

    data = handle_url(url);
    syslog(LOG_INFO, "response: %s", data);
    if (data != NULL)
    {
        // Delare json objects for each variable
        struct json_object *parsed_json;
        parsed_json = json_tokener_parse(data);
        struct json_object *_name;
        struct json_object *_passwd;
        struct json_object *_gid;
        struct json_object *_mems_array;

        // Import values into json object
        json_object_object_get_ex(parsed_json, "gr_mem", &_mems_array);

        // Get the number of members returned and create an array of that size
        int member_count = json_object_array_length(_mems_array);

        // Temporary json object to hold an entry at a given index in the array
        struct json_object * jvalue;

        // Loop over the json array to extract values into members array
        int i;
        for (i=0; i< member_count; i++){
            jvalue = json_object_array_get_idx(_mems_array, i);
            members[i] = malloc(strlen(json_object_get_string(jvalue)) + 1);
            strcpy(members[i],json_object_get_string(jvalue));
        }

        // Import values into json objects
        json_object_object_get_ex(parsed_json, "gr_name", &_name);
        json_object_object_get_ex(parsed_json, "gr_passwd", &_passwd);
        json_object_object_get_ex(parsed_json, "gr_gid", &_gid);

        result->gr_name = (void *)json_object_get_string(_name);
        result->gr_passwd = (void *)json_object_get_string(_passwd);
        result->gr_gid = json_object_get_int(_gid);
        result->gr_mem = members;

        retval = NSS_STATUS_SUCCESS;
        goto cleanup;
    }

    retval = NSS_STATUS_NOTFOUND;
cleanup:
    closelog();
    return retval;
}

// Name : gid representation of a group e.g. 1757409
// Result : structure we fill out with the groups's data
enum nss_status _nss_mongo_getgrgid_r(__gid_t gid, struct group *result, char *buffer, size_t buflen, int *errnop)
{
    int retval;
    // Initiate logging
    setlogmask(LOG_UPTO(LOG_INFO));
    openlog("mongo_nss", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
    syslog(LOG_INFO, "getgrgid");
    syslog(LOG_INFO, "group_id : %d,", gid);

    char struid[50];
    sprintf(struid, "%d", gid);
    char url[1024] = "groups/id/";
    strcat(url, struid);

    char *data;
    char **members = malloc(4096);

    data = handle_url(url);
    syslog(LOG_INFO, "response: %s", data);
    if (data != NULL)
    {
        // Delare json objects for each variable
        struct json_object *parsed_json;
        parsed_json = json_tokener_parse(data);
        struct json_object *_name;
        struct json_object *_passwd;
        struct json_object *_gid;
        struct json_object *_mems_array;

        // Import values into json object
        json_object_object_get_ex(parsed_json, "gr_mem", &_mems_array);

        // Get the number of members returned and create an array of that size
        int member_count = json_object_array_length(_mems_array);

        // Temporary json object to hold an entry at a given index in the array
        struct json_object * jvalue;

        // Loop over the json array to extract values into members array
        int i;
        for (i=0; i< member_count; i++){
            jvalue = json_object_array_get_idx(_mems_array, i);
            members[i] = malloc(strlen(json_object_get_string(jvalue)) + 1);
            strcpy(members[i],json_object_get_string(jvalue));
        }

        // Import values into json objects
        json_object_object_get_ex(parsed_json, "gr_name", &_name);
        json_object_object_get_ex(parsed_json, "gr_passwd", &_passwd);
        json_object_object_get_ex(parsed_json, "gr_gid", &_gid);

        result->gr_name = (void *)json_object_get_string(_name);
        result->gr_passwd = (void *)json_object_get_string(_passwd);
        result->gr_gid = json_object_get_int(_gid);
        result->gr_mem = members;

        retval = NSS_STATUS_SUCCESS;
        goto cleanup;
    }

    retval = NSS_STATUS_NOTFOUND;
cleanup:
    closelog();
    return retval;
}

// Haven't seen any detailled documentation about this function.
// Anyway it have to fill in groups for the specified user without
// adding his main group (group param).
// This functionality is handled by the api, more on this in README
// @param user : Username whose groups are wanted.
// @param group : Main group of user (should not be put in groupsp).
// @param start : Index from which groups filling must begin (initgroups_dyn
// is called for every backend). Can be updated
// @param size : Size of groups vector. Can be modified if function needs
// more space (should not exceed limit).
// @param groupsp : Pointer to the group vector. Can be realloc'ed if more
// space is needed.
// @param limit : Max size of groupsp (<= 0 if no limit).
// @param errnop : Pointer to errno (filled if an error occurs).
enum nss_status _nss_mongo_initgroups_dyn(const char *user, gid_t group, long int *start, long int *size,
                                          gid_t **groups, long int limit, int *errnop)
{
    int retval;
    // Initiate logging
    setlogmask(LOG_UPTO(LOG_INFO));
    openlog("mongo_nss", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
    syslog(LOG_INFO, "initgroups_dyn");
    syslog(LOG_INFO, "user_name : %s,", user);
    
    char url[1024] = "usergroups/";
    strcat(url, user);

    char *data;

    data = handle_url(url);
    syslog(LOG_INFO, "response: %s", data);
    if (strcmp(data, "null"))
    {
        // Delare json objects for each variable
        struct json_object *parsed_json;
        parsed_json = json_tokener_parse(data);
        struct json_object *_gids_array;

        // Import values into json object
        json_object_object_get_ex(parsed_json, "gids", &_gids_array);

        // Get the number of groups returned and create an array of that size
        int group_count = json_object_array_length(_gids_array);
        int gids[group_count];

        // Temporary json object to hold an entry at a given index in the array
        struct json_object * jvalue;

        // Loop over the json array to extract values into gids array
        int i;
        for (i=0; i< group_count; i++){
            jvalue = json_object_array_get_idx(_gids_array, i);
            gids[i] = json_object_get_int(jvalue);
        }

        // Add every gid from our local gids array into the passed in groups array
        int counter = 0;
        while (counter <= group_count - 1){
        syslog(LOG_DEBUG, "initgroups_dyn: adding group %d\n", gids[counter]);
        /* Too short, doubling size */
        if(*start == *size) {
            if(limit > 0) {
                if(*size < limit) {
                    *size = (limit < (*size * 2)) ? limit : (*size * 2);
                } else {
                    /* limit reached, tell caller to try with a bigger one */
                    syslog(LOG_ERR, "initgroups_dyn: limit was too low\n");
                    *errnop = ERANGE;
                    return NSS_STATUS_TRYAGAIN;
                }
            } else {
                (*size) = (*size) * 2;
            }
            // Trim the groups array allocated memory back down to size
            *groups = realloc(*groups, sizeof(**groups) * (*size));
        }
        (*groups)[*start] = gids[counter];
        (*start)++;
        counter++;
        }

        // Trim the groups array allocated memory back down to size
        *groups = realloc(*groups, sizeof(**groups) * (*start));
        *size = *start;
        retval = NSS_STATUS_SUCCESS;
        goto cleanup;
    }

    retval = NSS_STATUS_NOTFOUND;
cleanup:
    closelog();
    return retval;
}