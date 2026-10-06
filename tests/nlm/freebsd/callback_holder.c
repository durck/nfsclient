/* Independent POSIX oracle, controlled only by files in a disposable directory. */
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int mark(const char *name) {
    int fd = open(name, O_WRONLY | O_CREAT | O_EXCL, 0666);
    if (fd < 0) return -1;
    return close(fd);
}
static int wait_for(const char *name) {
    for (int i = 0; i < 36000; i++) {
        if (access(name, F_OK) == 0) return 0;
        usleep(100000);
    }
    return -1;
}
int main(int argc, char **argv) {
    if (argc != 3 || chdir(argv[1]) != 0) return 2;
    int fd = open("file", O_RDWR | O_CREAT | O_EXCL, 0666);
    if (fd < 0 || fchmod(fd, 0666) || write(fd, "NLM fixture payload\n", 20) != 20) return 3;
    struct flock lock = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 8, .l_len = 8};
    if (wait_for("start") || fcntl(fd, F_SETLK, &lock) || mark("ready")) return 4;
    if (wait_for("release")) return 5;
    lock.l_type = F_UNLCK;
    if (fcntl(fd, F_SETLK, &lock)) return 6;
    lock.l_type = F_WRLCK;
    if (strcmp(argv[2], "grant") == 0) {
        if (wait_for("held")) return 7;
        errno = 0;
        if (fcntl(fd, F_SETLK, &lock) != -1 || (errno != EAGAIN && errno != EACCES)) return 8;
        if (mark("probed")) return 9;
    }
    if (wait_for("done") || fcntl(fd, F_SETLK, &lock) || mark("clean")) return 10;
    puts("PASS: native exclusion and cleanup");
    return close(fd);
}
