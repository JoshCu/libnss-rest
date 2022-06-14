#include <nss.h>
#include <pwd.h>
#include <grp.h>
#include <syslog.h>
#include <string.h>
#include <stdlib.h>
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

    char url[] = "127.0.0.1:8000/user/name/";
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
    char url[] = "127.0.0.1:8000/user/id/";
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
    char url[] = "127.0.0.1:8000/group/id/";
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

    char url[] = "127.0.0.1:8000/group/name/";
    strcat(url, name);

    struct group fakeGroup;
    char *data;

    data = handle_url("127.0.0.1:8000/group/name/fakegroup");
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