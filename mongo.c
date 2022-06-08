#include <nss.h>
#include <pwd.h>
#include <grp.h>
#include <syslog.h>
#include <string.h>
#include <stdlib.h>

#define USER_DETAILS                                         \
    fakeUser.pw_name = "fake";                               \
    fakeUser.pw_passwd = "password";  /* Password.  */       \
    fakeUser.pw_uid = (__uid_t)1234;  /* User ID.  */        \
    fakeUser.pw_gid = (__gid_t)12345; /* Group ID.  */       \
    fakeUser.pw_gecos = "fakeuser";   /* Real name.  */      \
    fakeUser.pw_dir = "/home/fake";   /* Home directory.  */ \
    fakeUser.pw_shell = "/bin/bash";

// POINTERS
enum nss_status _nss_mongo_getpwnam_r(const char *name, struct passwd *result, char *buffer, size_t buflen, int *errnop)
{
    int retval;
    char filter[1024];

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
        USER_DETAILS
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
    char filter[1024];

    // initiate logging
    setlogmask(LOG_UPTO(LOG_INFO));
    openlog("mongo_nss", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
    syslog(LOG_INFO, "getpwnuid");
    syslog(LOG_INFO, "user_id : %d,", uid);

    if (uid == 1234)
    {
        struct passwd fakeUser;
        USER_DETAILS
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

// enum nss_status _nss_mongo_getgrgid_r(__gid_t gid, struct group *result, char *buffer, size_t buflen, int *errnop)
// {
//     int retval;
//     char filter[1024];

//     // initiate logging
//     setlogmask(LOG_UPTO(LOG_INFO));
//     openlog("mongo_nss", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
//     syslog(LOG_INFO, "getgrgid");
//     syslog(LOG_INFO, "group_id : %d,", gid);

//     if (gid == 12345)
//     {
//         syslog(LOG_INFO, "making struct");
//         struct group fakeGroup;
//         fakeGroup.gr_name = "fakegroup"; /* Group name.  */
//         fakeGroup.gr_passwd = "x";       /* Password.    */
//         fakeGroup.gr_gid = 12345;        /* Group ID.    */
//         fakeGroup.gr_mem[0] = 1234;      /* Member list. */

//         struct group *ptrfakeGroup = &fakeGroup;
//         *result = *ptrfakeGroup;
//         retval = NSS_STATUS_SUCCESS;
//         goto cleanup;
//     }

//     retval = NSS_STATUS_NOTFOUND;
// cleanup:
//     closelog();

//     return retval;
// }

// enum nss_status _nss_mongo_getgrnam_r(const char *name, struct group *result, char *buffer, size_t buflen, int *errnop)
// {
//     int retval;
//     char filter[1024];

//     // initiate logging
//     setlogmask(LOG_UPTO(LOG_INFO));
//     openlog("mongo_nss", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
//     syslog(LOG_INFO, "getgrnam");
//     syslog(LOG_INFO, "group_name : %s,", name);
//     char hardName[9] = "fakegroup";
//     int value = strcmp(name, hardName);
//     if (value == 0)
//     {
//         syslog(LOG_INFO, "making struct");
//         struct group fakeGroup;
//         fakeGroup.gr_name = "fakegroup"; /* Group name.  */
//         fakeGroup.gr_passwd = "x";       /* Password.    */
//         fakeGroup.gr_gid = 12345;        /* Group ID.    */
//         // fakeGroup.gr_mem[0] = 1234;      /* Member list. */

//         struct group *ptrfakeGroup = &fakeGroup;
//         *result = *ptrfakeGroup;
//         retval = NSS_STATUS_SUCCESS;
//         goto cleanup;
//     }

//     retval = NSS_STATUS_NOTFOUND;
// cleanup:
//     closelog();

//     return retval;
// }