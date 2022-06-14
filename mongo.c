#include <nss.h>
#include <pwd.h>
#include <grp.h>
#include <syslog.h>
#include <string.h>
#include <stdlib.h>
#include <curl/curl.h>
#include <json-c/json.h>

#define CURL_VERBOSE 0

#define GROUP_DETAILS                                   \
    syslog(LOG_INFO, "group_details");                  \
    fakeGroup.gr_name = "fakegroup"; /* Group name.  */ \
    fakeGroup.gr_passwd = "x";       /* Password.    */ \
    fakeGroup.gr_gid = 12345;        /* Group ID.    */ \
                                     // fakeGroup.gr_mem[0] = *ptrfakeUser; /* Member list. */

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
    /* trim leading and trailing characters ["useful:response:here"] */
    data.memory = data.memory + 2;
    data.memory[strlen(data.memory) - 2] = '\0';
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
    CURL *curl;
    char *data;
    char *values[7];
    CURLcode res;
    curl = curl_easy_init();
    if (curl)
    {
        data = handle_url(url);
        syslog(LOG_INFO, "response: %s", data);
        if (data)
        {
            int i = 0;
            int counter = 0;
            char *start = data;
            for (i = 0; data[i] != '\0'; i++)
            {
                if (data[i] == ':')
                {
                    data[i] = '\0';
                    // printf("%s\n", start);
                    values[counter] = start;
                    start = &data[i + 1];
                    counter++;
                }
            }
            fakeUser.pw_name = values[0];
            fakeUser.pw_passwd = values[1];
            fakeUser.pw_uid = (__uid_t)atoi(values[2]);
            fakeUser.pw_gid = (__gid_t)atoi(values[3]);
            fakeUser.pw_gecos = values[4];
            fakeUser.pw_dir = values[5];
            fakeUser.pw_shell = values[6];
        }
        /* example.com is redirected, so we tell libcurl to follow redirection */
        /* Perform the request, res will get the return code */
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
    CURL *curl;
    char *data;

    CURLcode res;
    char *values[7];
    curl = curl_easy_init();
    if (curl)
    {
        data = handle_url(url);
        syslog(LOG_INFO, "response: %s", data);
        if (data)
        {
            int i = 0;
            int counter = 0;
            char *start = data;
            for (i = 0; data[i] != '\0'; i++)
            {
                if (data[i] == ':')
                {
                    data[i] = '\0';
                    // printf("%s\n", start);
                    values[counter] = start;
                    start = &data[i + 1];
                    counter++;
                }
            }
            fakeUser.pw_name = values[0];
            fakeUser.pw_passwd = values[1];
            fakeUser.pw_uid = (__uid_t)atoi(values[2]);
            fakeUser.pw_gid = (__gid_t)atoi(values[3]);
            fakeUser.pw_gecos = values[4];
            fakeUser.pw_dir = values[5];
            fakeUser.pw_shell = values[6];
        }
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
    CURL *curl;
    char *data;
    CURLcode res;
    char *values[3];
    curl = curl_easy_init();
    if (curl)
    {
        data = handle_url(url);
        syslog(LOG_INFO, "response: %s", data);
        if (data)
        {
            int i = 0;
            int counter = 0;
            char *start = data;
            for (i = 0; data[i] != '\0'; i++)
            {
                if (data[i] == ':')
                {
                    data[i] = '\0';
                    // printf("%s\n", start);
                    values[counter] = start;
                    start = &data[i + 1];
                    counter++;
                }
            }
            fakeGroup.gr_name = values[0];
            fakeGroup.gr_passwd = values[1];
            fakeGroup.gr_gid = (__gid_t)atoi(values[2]);
        }
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
    char filter[1024];

    // initiate logging
    setlogmask(LOG_UPTO(LOG_INFO));
    openlog("mongo_nss", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
    syslog(LOG_INFO, "getgrnam");
    syslog(LOG_INFO, "group_name : %s,", name);

    char url[] = "127.0.0.1:8000/group/name/";
    strcat(url, name);

    struct group fakeGroup;
    CURL *curl;
    char *data;
    CURLcode res;
    char *values[3];
    curl = curl_easy_init();
    if (curl)
    {
        data = handle_url("127.0.0.1:8000/group/name/fakegroup");
        syslog(LOG_INFO, "response: %s", data);
        if (data)
        {
            int i = 0;
            int counter = 0;
            char *start = data;
            for (i = 0; data[i] != '\0'; i++)
            {
                if (data[i] == ':')
                {
                    data[i] = '\0';
                    // printf("%s\n", start);
                    values[counter] = start;
                    start = &data[i + 1];
                    counter++;
                }
            }
            fakeGroup.gr_name = values[0];
            fakeGroup.gr_passwd = values[1];
            fakeGroup.gr_gid = (__gid_t)atoi(values[2]);
        }
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