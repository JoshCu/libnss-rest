#include <nss.h>
#include <pwd.h>
#include <grp.h>
#include <syslog.h>
#include <string.h>
#include <stdlib.h>
#include <curl/curl.h>

#define CURL_VERBOSE 0

// #define USER_DETAILS                                         \
//     syslog(LOG_INFO, "user_details");                        \
//     fakeUser.pw_name = "fake";                               \
//     fakeUser.pw_passwd = "password";  /* Password.  */       \
//     fakeUser.pw_uid = (__uid_t)1234;  /* User ID.  */        \
//     fakeUser.pw_gid = (__gid_t)12345; /* Group ID.  */       \
//     fakeUser.pw_gecos = "fakeuser";   /* Real name.  */      \
//     fakeUser.pw_dir = "/home/fake";   /* Home directory.  */ \
//     fakeUser.pw_shell = "/bin/bash";

#define GROUP_DETAILS                                   \
    syslog(LOG_INFO, "group_details");                  \
    fakeGroup.gr_name = "fakegroup"; /* Group name.  */ \
    fakeGroup.gr_passwd = "x";       /* Password.    */ \
    fakeGroup.gr_gid = 12345;        /* Group ID.    */ \
                                     // fakeGroup.gr_mem[0] = *ptrfakeUser; /* Member list. */

#define GET_NEXT_VALUE               \
    tmp = data;                      \
    for (i = 0; data[i] != ':'; i++) \
        ;                            \
    data[i] = '\0';                  \
    data = data + i + 1;             \
    printf("%s\n", tmp);

struct url_data
{
    size_t size;
    char *data;
};

size_t write_data(void *ptr, size_t size, size_t nmemb, struct url_data *data)
{
    size_t index = data->size;
    size_t n = (size * nmemb);
    char *tmp;

    data->size += (size * nmemb);
    tmp = realloc(data->data, data->size + 1); /* +1 for '\0' */

    if (tmp)
    {
        data->data = tmp;
    }
    else
    {
        if (data->data)
        {
            free(data->data);
        }
        fprintf(stderr, "Failed to allocate memory.\n");
        return 0;
    }

    memcpy((data->data + index), ptr, n);
    data->data[data->size] = '\0';
    return size * nmemb;
}

char *handle_url(char *url)
{
    CURL *curl;

    struct url_data data;
    data.size = 0;
    data.data = malloc(500); /* reasonable size initial buffer */
    if (NULL == data.data)
    {
        fprintf(stderr, "Failed to allocate memory.\n");
        return NULL;
    }

    data.data[0] = '\0';

    CURLcode res;

    curl = curl_easy_init();
    if (curl)
    {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
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
    data.data = data.data + 2;
    data.data[strlen(data.data) - 2] = '\0';
    return data.data;
}

// POINTERS
enum nss_status _nss_mongo_getpwnam_r(const char *name, struct passwd *result, char *buffer, size_t buflen, int *errnop)
{
    int retval;
    // initiate logging
    setlogmask(LOG_UPTO(LOG_INFO));
    openlog("mongo_nss", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
    syslog(LOG_INFO, "getpwnam");
    syslog(LOG_INFO, "user_name : %s,", name);
    char hardName[5] = "fake";
    int value = strcmp(name, hardName);
    if (value == 0)
    {
        struct passwd fakeUser;
        CURL *curl;
        char *data;
        CURLcode res;
        curl = curl_easy_init();
        if (curl)
        {
            data = handle_url("127.0.0.1:8000/user/name/fake");
            syslog(LOG_INFO, "response: %s", data);
            if (data)
            {
                int i = 0;
                char *tmp;
                GET_NEXT_VALUE
                fakeUser.pw_name = tmp;
                GET_NEXT_VALUE
                fakeUser.pw_passwd = tmp;
                GET_NEXT_VALUE
                fakeUser.pw_uid = (__uid_t)atoi(tmp);
                GET_NEXT_VALUE
                fakeUser.pw_gid = (__gid_t)atoi(tmp);
                GET_NEXT_VALUE
                fakeUser.pw_gecos = tmp;
                GET_NEXT_VALUE
                fakeUser.pw_dir = tmp;
                GET_NEXT_VALUE
                fakeUser.pw_shell = tmp;
            }
            // free(data);
            /* example.com is redirected, so we tell libcurl to follow redirection */
            /* Perform the request, res will get the return code */
            res = curl_easy_perform(curl);
        }

        /* always cleanup */
        // free(*response_string);
        curl_easy_cleanup(curl);

        struct passwd *ptrfakeUser = &fakeUser;
        *result = *ptrfakeUser;
        retval = NSS_STATUS_SUCCESS;
        goto cleanup;
    }

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

    if (uid == 1234)
    {
        struct passwd fakeUser;
        CURL *curl;
        char *data;
        CURLcode res;
        curl = curl_easy_init();
        if (curl)
        {
            data = handle_url("127.0.0.1:8000/user/name/1234");
            syslog(LOG_INFO, "response: %s", data);
            if (data)
            {
                int i = 0;
                char *tmp;
                GET_NEXT_VALUE
                fakeUser.pw_name = tmp;
                GET_NEXT_VALUE
                fakeUser.pw_passwd = tmp;
                GET_NEXT_VALUE
                fakeUser.pw_uid = (__uid_t)atoi(tmp);
                GET_NEXT_VALUE
                fakeUser.pw_gid = (__gid_t)atoi(tmp);
                GET_NEXT_VALUE
                fakeUser.pw_gecos = tmp;
                GET_NEXT_VALUE
                fakeUser.pw_dir = tmp;
                GET_NEXT_VALUE
                fakeUser.pw_shell = tmp;
            }
            // free(data);
            /* example.com is redirected, so we tell libcurl to follow redirection */
            /* Perform the request, res will get the return code */
            res = curl_easy_perform(curl);
        }

        /* always cleanup */
        // free(*response_string);
        curl_easy_cleanup(curl);

        struct passwd *ptrfakeUser = &fakeUser;
        *result = *ptrfakeUser;
        retval = NSS_STATUS_SUCCESS;
        goto cleanup;
    }

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

    if (gid == 12345)
    {
        struct group fakeGroup;
        GROUP_DETAILS
        struct group *ptrfakeGroup = &fakeGroup;
        *result = *ptrfakeGroup;
        retval = NSS_STATUS_SUCCESS;
        goto cleanup;
    }

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
    int value = strcmp(name, "fakegroup");
    syslog(LOG_INFO, "compare_val : %d,", value);
    if (value == 0)
    {
        struct group fakeGroup;
        GROUP_DETAILS
        struct group *ptrfakeGroup = &fakeGroup;
        *result = *ptrfakeGroup;
        retval = NSS_STATUS_SUCCESS;
        goto cleanup;
    }

    retval = NSS_STATUS_NOTFOUND;
cleanup:
    closelog();
    return retval;
}