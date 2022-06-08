#include <nss.h>
#include <pwd.h>
#include <syslog.h>
#include <string.h>
#include <stdlib.h>

enum nss_status _nss_mongo_getpwnam_r(const char *name, struct passwd *p, char *buffer, size_t buflen, int *errnop)
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
        syslog(LOG_INFO, "making struct");
        struct passwd fakeUser;
        fakeUser.pw_name = "fake";       /* Username.  */
        fakeUser.pw_passwd = "password"; /* Password.  */
        fakeUser.pw_uid = (__uid_t)1234; /* User ID.  */
        fakeUser.pw_gid = (__gid_t)1234; /* Group ID.  */
        fakeUser.pw_gecos = "fakeuser";  /* Real name.  */
        fakeUser.pw_dir = "/home/fake";  /* Home directory.  */
        fakeUser.pw_shell = "/bin/bash";

        struct passwd *ptrfakeUser = &fakeUser;
        *p = *ptrfakeUser;
        retval = NSS_STATUS_SUCCESS;
        goto cleanup;
    }

    retval = NSS_STATUS_NOTFOUND;
cleanup:
    closelog();

    return retval;
}

enum nss_status _nss_mongo_getpwuid_r(__uid_t uid, struct passwd *p, char *buffer, size_t buflen, int *errnop)
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
        syslog(LOG_INFO, "making struct");
        struct passwd fakeUser;
        fakeUser.pw_name = "fake";       /* Username.  */
        fakeUser.pw_passwd = "password"; /* Password.  */
        fakeUser.pw_uid = (__uid_t)1234; /* User ID.  */
        fakeUser.pw_gid = (__gid_t)1234; /* Group ID.  */
        fakeUser.pw_gecos = "fakeuser";  /* Real name.  */
        fakeUser.pw_dir = "/home/fake";  /* Home directory.  */
        fakeUser.pw_shell = "/bin/bash";

        struct passwd *ptrfakeUser = &fakeUser;
        *p = *ptrfakeUser;
        retval = NSS_STATUS_SUCCESS;
        goto cleanup;
    }

    retval = NSS_STATUS_NOTFOUND;
cleanup:
    closelog();

    return retval;
}
