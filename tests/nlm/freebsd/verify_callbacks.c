/* Run locally on the disposable FreeBSD server after the callback matrix. */
#include <sys/param.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    const char *platforms[] = {"windows-final", "linux-final"};
    const char *kinds[] = {"api", "cli"};
    const char *transports[] = {"tcp", "udp"};
    const char *phases[] = {"grant", "cancel"};
    int count = 0;
    if (argc != 2 || chdir(argv[1])) return 2;
    puts("[");
    for (int p = 0; p < 2; p++) for (int k = 0; k < 2; k++)
    for (int v = 2; v <= 3; v++) for (int tr = 0; tr < 2; tr++)
    for (int phase = 0; phase < (k == 0 ? 2 : 1); phase++) {
        char name[128], path[160], data[21] = {0};
        snprintf(name, sizeof(name), "%s-%s-%d-%s-%s", platforms[p], kinds[k], v, transports[tr], phases[phase]);
        snprintf(path, sizeof(path), "%s/clean", name);
        if (access(path, F_OK)) { perror(path); return 3; }
        if (phase == 0) {
            snprintf(path, sizeof(path), "%s/probed", name);
            if (access(path, F_OK)) { perror(path); return 4; }
        }
        snprintf(path, sizeof(path), "%s/file", name);
        int fd = open(path, O_RDWR);
        if (fd < 0 || read(fd, data, sizeof(data)) != 20 || memcmp(data, "NLM fixture payload\n", 20)) return 5;
        struct flock lock = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 8, .l_len = 8};
        if (fcntl(fd, F_SETLK, &lock)) return 6;
        fhandle_t fh = {0};
        if (getfh(path, &fh)) return 7;
        printf("%s{\"profile\":\"%s\",\"fh\":\"", count++ ? ",\n" : "", name);
        const unsigned char *bytes = (const unsigned char *)&fh;
        for (unsigned i = 0; i < sizeof(fh); i++) printf("%02x", bytes[i]);
        printf("\",\"native_bytes_and_unlock\":true}");
        if (close(fd)) return 8;
    }
    puts("\n]");
    return count == 24 ? 0 : 9;
}
