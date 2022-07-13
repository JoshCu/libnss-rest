#include <nss.h>
#include <pwd.h>
#include <grp.h>
#include <syslog.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <curl/curl.h>
#include <json-c/json.h>

#define CURL_VERBOSE 0

struct curl_output
{
    char *memory;
    size_t size;
};

// stores output of CURL command into string
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

char *handle_url(char *url)
{
    CURL *curl;
    struct curl_output data;
    data.size = 0;
    data.memory = malloc(4096); /* reasonable size initial buffer */

    if (NULL == data.memory)
    {
        fprintf(stderr, "Failed to allocate memory.\n");
        return NULL;
    }

    data.memory[0] = '\0';
    CURLcode res;
    curl = curl_easy_init();
    if (curl)
    {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writecallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &data);
        curl_easy_setopt(curl, CURLOPT_USERNAME, "username");
        curl_easy_setopt(curl, CURLOPT_PASSWORD, "password");
        res = curl_easy_perform(curl);
        if (res != CURLE_OK)
        {
            fprintf(stderr, "curl_easy_perform() failed: %s\n",
                    curl_easy_strerror(res));
        }

        curl_easy_cleanup(curl);
    }
    return data.memory;
}

enum nss_status _nss_mongo_getpwnam_r(const char *name, struct passwd *result, char *buffer, size_t buflen, int *errnop)
{
    int retval;
    // initiate logging
    setlogmask(LOG_UPTO(LOG_INFO));
    openlog("mongo_nss", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
    syslog(LOG_INFO, "getpwnam");
    syslog(LOG_INFO, "user_name : %s,", name);

    char url[] = "https://host-172-16-103-228.nubes.stfc.ac.uk:81/isis/users/name/";
    strcat(url, name);

    struct passwd fakeUser;
    char *data;

    data = handle_url(url);
    syslog(LOG_INFO, "response: %s", data);
    if (data)
    {
        struct json_object *parsed_json;
        parsed_json = json_tokener_parse(data);
        struct json_object *_name;
        struct json_object *_passwd;
        struct json_object *_uid;
        struct json_object *_gid;
        struct json_object *_gecos;
        struct json_object *_dir;
        struct json_object *_shell;

        json_object_object_get_ex(parsed_json, "pw_name", &_name);
        json_object_object_get_ex(parsed_json, "pw_passwd", &_passwd);
        json_object_object_get_ex(parsed_json, "pw_uid", &_uid);
        json_object_object_get_ex(parsed_json, "pw_gid", &_gid);
        json_object_object_get_ex(parsed_json, "pw_gecos", &_gecos);
        json_object_object_get_ex(parsed_json, "pw_dir", &_dir);
        json_object_object_get_ex(parsed_json, "pw_shell", &_shell);

        fakeUser.pw_name = (void *)json_object_get_string(_name);
        fakeUser.pw_passwd = (void *)json_object_get_string(_passwd);
        fakeUser.pw_uid = json_object_get_int(_uid);
        fakeUser.pw_gid = json_object_get_int(_gid);
        fakeUser.pw_gecos = (void *)json_object_get_string(_gecos);
        fakeUser.pw_dir = (void *)json_object_get_string(_dir);
        fakeUser.pw_shell = (void *)json_object_get_string(_shell);
    }

    struct passwd *ptrfakeUser = &fakeUser;
    *result = *ptrfakeUser;
    retval = NSS_STATUS_SUCCESS;
    goto cleanup;

    retval = NSS_STATUS_NOTFOUND;
cleanup:
    closelog();

    return retval;
}

enum nss_status _nss_mongo_getpwuid_r(__uid_t uid, struct passwd *result, char *buffer, size_t buflen, int *errnop)
{
    int retval;
    // initiate logging
    setlogmask(LOG_UPTO(LOG_INFO));
    openlog("mongo_nss", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
    syslog(LOG_INFO, "getpwnuid");
    syslog(LOG_INFO, "user_id : %d,", uid);

    char struid[50];
    sprintf(struid, "%d", uid);
    char url[] = "https://host-172-16-103-228.nubes.stfc.ac.uk:81/isis/users/id/";
    strcat(url, struid);

    struct passwd fakeUser;
    char *data;

    data = handle_url(url);
    syslog(LOG_INFO, "response: %s", data);
    if (data)
    {
        struct json_object *parsed_json;
        parsed_json = json_tokener_parse(data);
        struct json_object *_name;
        struct json_object *_passwd;
        struct json_object *_uid;
        struct json_object *_gid;
        struct json_object *_gecos;
        struct json_object *_dir;
        struct json_object *_shell;

        json_object_object_get_ex(parsed_json, "pw_name", &_name);
        json_object_object_get_ex(parsed_json, "pw_passwd", &_passwd);
        json_object_object_get_ex(parsed_json, "pw_uid", &_uid);
        json_object_object_get_ex(parsed_json, "pw_gid", &_gid);
        json_object_object_get_ex(parsed_json, "pw_gecos", &_gecos);
        json_object_object_get_ex(parsed_json, "pw_dir", &_dir);
        json_object_object_get_ex(parsed_json, "pw_shell", &_shell);

        fakeUser.pw_name = (void *)json_object_get_string(_name);
        fakeUser.pw_passwd = (void *)json_object_get_string(_passwd);
        fakeUser.pw_uid = json_object_get_int(_uid);
        fakeUser.pw_gid = json_object_get_int(_gid);
        fakeUser.pw_gecos = (void *)json_object_get_string(_gecos);
        fakeUser.pw_dir = (void *)json_object_get_string(_dir);
        fakeUser.pw_shell = (void *)json_object_get_string(_shell);
    }
    struct passwd *ptrfakeUser = &fakeUser;
    *result = *ptrfakeUser;
    retval = NSS_STATUS_SUCCESS;
    goto cleanup;

    retval = NSS_STATUS_NOTFOUND;
cleanup:
    closelog();

    return retval;
}

enum nss_status _nss_mongo_getgrgid_r(__gid_t gid, struct group *result, char *buffer, size_t buflen, int *errnop)
{
    int retval;
    // initiate logging
    setlogmask(LOG_UPTO(LOG_INFO));
    openlog("mongo_nss", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
    syslog(LOG_INFO, "getgrgid");
    syslog(LOG_INFO, "group_id : %d,", gid);

    char struid[50];
    sprintf(struid, "%d", gid);
    char url[] = "https://host-172-16-103-228.nubes.stfc.ac.uk:81/isis/groups/id/";
    strcat(url, struid);

    struct group fakeGroup;
    char *data;

    data = handle_url(url);
    syslog(LOG_INFO, "response: %s", data);
    if (data)
    {
        struct json_object *parsed_json;
        parsed_json = json_tokener_parse(data);
        struct json_object *_name;
        struct json_object *_passwd;
        struct json_object *_gid;

        json_object_object_get_ex(parsed_json, "gr_name", &_name);
        json_object_object_get_ex(parsed_json, "gr_passwd", &_passwd);
        json_object_object_get_ex(parsed_json, "gr_gid", &_gid);

        fakeGroup.gr_name = (void *)json_object_get_string(_name);
        fakeGroup.gr_passwd = (void *)json_object_get_string(_passwd);
        fakeGroup.gr_gid = json_object_get_int(_gid);
    }

    struct group *ptrfakeGroup = &fakeGroup;
    *result = *ptrfakeGroup;
    retval = NSS_STATUS_SUCCESS;
    goto cleanup;

    retval = NSS_STATUS_NOTFOUND;
cleanup:
    closelog();

    return retval;
}

enum nss_status _nss_mongo_getgrnam_r(const char *name, struct group *result, char *buffer, size_t buflen, int *errnop)
{
    int retval;
    // initiate logging
    setlogmask(LOG_UPTO(LOG_INFO));
    openlog("mongo_nss", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
    syslog(LOG_INFO, "getgrnam");
    syslog(LOG_INFO, "group_name : %s,", name);

    char url[] = "https://host-172-16-103-228.nubes.stfc.ac.uk:81/isis/groups/name/";
    strcat(url, name);

    struct group fakeGroup;
    char *data;

    data = handle_url(url);
    syslog(LOG_INFO, "response: %s", data);
    if (data)
    {
        struct json_object *parsed_json;
        parsed_json = json_tokener_parse(data);
        struct json_object *_name;
        struct json_object *_passwd;
        struct json_object *_gid;

        json_object_object_get_ex(parsed_json, "gr_name", &_name);
        json_object_object_get_ex(parsed_json, "gr_passwd", &_passwd);
        json_object_object_get_ex(parsed_json, "gr_gid", &_gid);

        fakeGroup.gr_name = (void *)json_object_get_string(_name);
        fakeGroup.gr_passwd = (void *)json_object_get_string(_passwd);
        fakeGroup.gr_gid = json_object_get_int(_gid);
    }

    struct group *ptrfakeGroup = &fakeGroup;
    *result = *ptrfakeGroup;
    retval = NSS_STATUS_SUCCESS;
    goto cleanup;

    retval = NSS_STATUS_NOTFOUND;
cleanup:
    closelog();
    return retval;
}

// group is the gid to exclude from the list
enum nss_status _nss_mongo_initgroups_dyn(const char *user, gid_t group,
                                          long int *start, long int *size,
                                          gid_t **groups, long int limit,
                                          int *errnop)
{
    int retval = -1;
    // initiate logging
    setlogmask(LOG_UPTO(LOG_INFO));
    openlog("mongo_nss", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
    syslog(LOG_INFO, "initgroups_dyn");
    syslog(LOG_INFO, "user_name : %s,", user);
    
    char url[] = "https://host-172-16-103-228.nubes.stfc.ac.uk:81/isis/usergroups/";
    strcat(url, user);

    char *data;

    data = handle_url(url);
    syslog(LOG_INFO, "response: %s", data);
    if (data)
    {
        struct json_object *parsed_json;
        parsed_json = json_tokener_parse(data);
        struct json_object *_group_count;
        struct json_object *_gids_array;

        json_object_object_get_ex(parsed_json, "group_count", &_group_count);
        json_object_object_get_ex(parsed_json, "gids", &_gids_array);

        int group_count = json_object_get_int(_group_count);
        int gids[group_count];
        struct json_object * jvalue;
        int i = 0;
        for (i=0; i< group_count; i++){
            jvalue = json_object_array_get_idx(_gids_array, i);
            gids[i] = json_object_get_int(jvalue);
        }
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
            *groups = realloc(*groups, sizeof(**groups) * (*size));
        }
        (*groups)[*start] = gids[counter];
        (*start)++;
        counter++;
        }


        *groups = realloc(*groups, sizeof(**groups) * (*start));
        *size = *start;
    }

    closelog();
    retval = NSS_STATUS_SUCCESS;
    return retval;
}