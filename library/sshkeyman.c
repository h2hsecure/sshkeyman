#define _GNU_SOURCE
#include <nss.h>
#include <pwd.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <stdio.h>

#define SOCKET_PATH "/var/lib/sshkeyman/daemon.sock"
#define BUF_SIZE 512

#define GETPWNAM "GETPWNAM"
#define GETPWUID "GETPWUID"

static enum nss_status query_daemon(
    const char *command,
    const char *usernameOrId,
    struct passwd *pwd,
    char *buffer,
    size_t buflen,
    int *errnop)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
    {
        *errnop = errno;
        return NSS_STATUS_UNAVAIL;
    }

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        close(fd);
        *errnop = errno;
        return NSS_STATUS_UNAVAIL;
    }

    char request[BUF_SIZE];
    snprintf(request, sizeof(request), "%s %s\n", command, usernameOrId);
    write(fd, request, strlen(request));

    char response[BUF_SIZE];
    ssize_t n = read(fd, response, sizeof(response) - 1);
    close(fd);

    if (n <= 0)
    {
        *errnop = EIO;
        return NSS_STATUS_UNAVAIL;
    }

    response[n] = '\0';

    if (strncmp(response, "NOTFOUND", 8) == 0)
    {
        return NSS_STATUS_NOTFOUND;
    }

    unsigned uid, gid;
    char username[128], home[128], shell[128];

    if (sscanf(response, "OK %127s %u %u %127s %127s", username, &uid, &gid, home, shell) != 5)
    {
        *errnop = EINVAL;
        return NSS_STATUS_UNAVAIL;
    }

    size_t needed =
        strlen(usernameOrId) + 1 +
        strlen(home) + 1 +
        strlen(shell) + 1;

    if (needed > buflen)
    {
        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    }

    char *p = buffer;

    pwd->pw_name = p;
    strcpy(p, username);
    p += strlen(p) + 1;

    pwd->pw_passwd = (char *)"x";
    pwd->pw_uid = uid;
    pwd->pw_gid = gid;

    pwd->pw_gecos = pwd->pw_name;

    pwd->pw_dir = p;
    strcpy(p, home);
    p += strlen(p) + 1;

    pwd->pw_shell = p;
    strcpy(p, shell);

    return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_sshkeyman_getpwnam_r(
    const char *name,
    struct passwd *pwd,
    char *buffer,
    size_t buflen,
    int *errnop)
{
    return query_daemon(GETPWNAM, name, pwd, buffer, buflen, errnop);
}

enum nss_status _nss_sshkeyman_getpwuid_r(
    uid_t uid,
    struct passwd *pwd,
    char *buffer,
    size_t buflen,
    int *errnop)
{
    char uidstr[32];
    snprintf(uidstr, sizeof(uidstr), "%u", uid);
    return query_daemon(GETPWUID, uidstr, pwd, buffer, buflen, errnop);
}