/* Independent native POSIX lock holder for the NLM TEST fixture. */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
    const char *names[] = {"locked-write", "locked-read", "locked-high", "free"};
    int fds[4];
    if (argc != 2 || chdir(argv[1]) != 0) return 2;
    for (int i = 0; i < 4; i++) {
        fds[i] = open(names[i], O_CREAT | O_EXCL | O_RDWR, 0666);
        if (fds[i] < 0 || fchmod(fds[i], 0666) != 0 ||
            write(fds[i], "NLM fixture payload\n", 20) != 20) {
            perror("create fixture"); return 3;
        }
        if (i < 3) {
            struct flock lock = {0};
            lock.l_type = i == 1 ? F_RDLCK : F_WRLCK;
            lock.l_whence = SEEK_SET;
            lock.l_start = i == 2 ? ((off_t)1 << 33) + 7 : i == 1 ? 16 : 8;
            lock.l_len = i == 2 ? 11 : i == 1 ? 0 : 8;
            if (fcntl(fds[i], F_SETLK, &lock) != 0) { perror("F_SETLK"); return 4; }
            printf("%s pid=%ld type=%s offset=%lld length=%lld\n", names[i],
                (long)getpid(), i == 1 ? "read" : "write",
                (long long)lock.l_start, (long long)lock.l_len);
        }
    }
    if (symlink("locked-write", "link") != 0) return 5;
    puts("READY"); fflush(stdout);
    for (;;) pause();
}
