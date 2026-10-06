#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <inttypes.h>
#include <poll.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "lizardfs_c_api.h"
#include "lizardfs_error_codes.h"

/* Operate only on an existing, explicitly named disposable lab fixture. */
static const char *name;
struct peer { liz_t *client; liz_context_t *context; liz_fileinfo_t *file; };
static unsigned passed;
static int denial_mapping_ok = 1;

static int valid_name(const char *value)
{
    regex_t expression;
    int valid;
    if (strlen(value) > 200 || regcomp(&expression,
        "^pnfs-multi-(api|cli)-(windows|linux)-4[.][12]-[0-9]+$",
        REG_EXTENDED | REG_NOSUB) != 0)
        return 0;
    valid = regexec(&expression, value, 0, NULL, 0) == 0;
    regfree(&expression);
    return valid;
}

static double now(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + t.tv_nsec / 1e9;
}

static int set(struct peer *p, int type, int64_t start, int64_t len,
               int expect_denied, const char *label)
{
    liz_lock_info_t lock = {.l_type=type, .l_start=start, .l_len=len,
                            .l_pid=getpid()};
    double begin = now();
    int rc = liz_setlk(p->client, p->context, p->file, &lock, NULL, NULL);
    int error = liz_last_err(), posix = liz_error_conv(error);
    double elapsed = now() - begin;
    int errno_correct = !expect_denied ||
        (posix == EAGAIN || posix == EACCES || posix == EWOULDBLOCK);
    int correct = expect_denied
        ? rc == -1 && (errno_correct || error == LIZARDFS_ERROR_WAITING)
        : rc == 0;
    if (expect_denied && !errno_correct)
        denial_mapping_ok = 0;
    correct = correct && elapsed < 3.0;
    printf("{\"case\":\"%s\",\"kind\":\"setlk\",\"type\":%d,"
           "\"start\":%" PRId64 ",\"length\":%" PRId64 ",\"rc\":%d,"
           "\"native_error\":%d,\"posix_error\":%d,\"seconds\":%.6f,"
           "\"errno_translation_ok\":%s,\"ok\":%s}\n",
           label, type, start, len, rc, error, posix, elapsed,
           errno_correct ? "true" : "false", correct ? "true" : "false");
    fflush(stdout);
    if (!correct) {
        fprintf(stderr, "%s failed: %s\n", label, liz_error_string(error));
        return -1;
    }
    ++passed;
    return 0;
}

static int query(struct peer *p, int request_type, int64_t start, int64_t len,
                 int expected_type, int64_t expected_start, int64_t expected_len,
                 const char *label)
{
    liz_lock_info_t lock = {.l_type=request_type, .l_start=start, .l_len=len,
                            .l_pid=getpid()};
    int rc = liz_getlk(p->client, p->context, p->file, &lock);
    int error = liz_last_err();
    int correct = rc == 0 && lock.l_type == expected_type;
    if (expected_type != F_UNLCK)
        correct = correct && lock.l_start == expected_start &&
                  lock.l_len == expected_len;
    printf("{\"case\":\"%s\",\"kind\":\"getlk\",\"rc\":%d,"
           "\"native_error\":%d,\"type\":%d,\"start\":%" PRId64
           ",\"length\":%" PRId64 ",\"pid\":%d,\"ok\":%s}\n", label,
           rc, error, lock.l_type, lock.l_start, lock.l_len, lock.l_pid,
           correct ? "true" : "false");
    fflush(stdout);
    if (!correct)
        return -1;
    ++passed;
    return 0;
}

static int connect_peer(struct peer *p, const char *host, uint64_t owner,
                        liz_inode_t *inode)
{
    liz_init_params_t params;
    liz_entry_t entry;
    liz_set_default_init_params(&params, host, "9421", "pnfs-native-lock-probe");
    params.subfolder = "/";
    params.io_retries = 2;
    params.attr_cache_timeout = 0;
    params.entry_cache_timeout = 0;
    params.verbose = false;
    p->client = liz_init_with_params(&params);
    if (!p->client)
        return -1;
    p->context = liz_create_user_context(25001, 25000, getpid(), 0);
    if (!p->context || liz_lookup(p->client, p->context, 1, name, &entry) < 0)
        return -1;
    *inode = entry.ino;
    p->file = liz_open(p->client, p->context, entry.ino, O_RDWR);
    if (!p->file)
        return -1;
    liz_set_lock_owner(p->file, owner);
    return 0;
}

static void close_peer(struct peer *p)
{
    /* Release through the existing native release path, not a potentially
       broken POSIX-to-protocol F_UNLCK conversion in the red library. */
    if (p->file)
        liz_release(p->client, p->file);
    if (p->context)
        liz_destroy_context(p->context);
    if (p->client)
        liz_destroy(p->client);
}

#define CHECK(call) do { if ((call) < 0) goto out; } while (0)
static int hold_read(const char *host)
{
    struct peer a = {0};
    liz_inode_t inode = 0;
    struct pollfd input = {.fd=STDIN_FILENO, .events=POLLIN};
    int result = 1;
    if (connect_peer(&a, host, UINT64_C(0x504e465348), &inode) < 0 ||
        set(&a, F_RDLCK, 0, 0, 0, "native_hold_shared") < 0)
        goto done;
    printf("{\"ready\":true,\"mode\":\"hold-read\",\"inode\":%u,"
           "\"release\":\"send newline on stdin; timeout 120 seconds\"}\n", inode);
    fflush(stdout);
    if (poll(&input, 1, 120000) > 0 && (input.revents & POLLIN)) {
        (void)getchar();
        result = 0;
    } else {
        fprintf(stderr, "Native holder timed out or lost stdin; releasing\n");
    }
    if (set(&a, F_UNLCK, 0, 0, 0, "native_hold_released") < 0)
        result = 1;
done:
    close_peer(&a);
    return result;
}

int main(int argc, char **argv)
{
    struct peer a = {0}, b = {0};
    liz_inode_t ai = 0, bi = 0;
    liz_attr_reply_t before, after;
    int result = 1;
    if (argc == 4 && strcmp(argv[1], "--hold-read") == 0) {
        name = argv[3];
        if (!valid_name(name)) {
            fprintf(stderr, "Rejected filename outside the lab fixture pattern\n");
            return 2;
        }
        return hold_read(argv[2]);
    }
    if (argc != 3 || !valid_name(argv[2])) {
        fprintf(stderr, "Usage: %s [--hold-read] EXPLICIT_LAB_MASTER FIXTURE_NAME\n",
                argv[0]);
        return 2;
    }
    name = argv[2];
    CHECK(connect_peer(&a, argv[1], UINT64_C(0x504e465331), &ai));
    CHECK(connect_peer(&b, argv[1], UINT64_C(0x504e465332), &bi));
    if (ai != bi) goto out;
    CHECK(liz_getattr(a.client, a.context, ai, &before));
    CHECK(set(&a, F_RDLCK, 0, 0, 0, "a_shared_whole"));
    CHECK(set(&b, F_RDLCK, 0, 0, 0, "b_shared_whole"));
    CHECK(set(&a, F_UNLCK, 0, 0, 0, "a_unlock_preserves_b"));
    CHECK(set(&a, F_WRLCK, 0, 0, 1, "a_write_denied_by_b_shared"));
    CHECK(query(&a, F_WRLCK, 0, 0, F_RDLCK, 0, 0, "getlk_shared_posix_type"));
    CHECK(set(&b, F_UNLCK, 0, 0, 0, "b_unlock_shared"));
    CHECK(set(&a, F_WRLCK, 0, 0, 0, "a_exclusive_whole"));
    CHECK(set(&b, F_RDLCK, 0, 0, 1, "b_read_denied_by_a_exclusive"));
    CHECK(query(&b, F_RDLCK, 0, 0, F_WRLCK, 0, 0, "getlk_exclusive_posix_type"));
    CHECK(set(&a, F_UNLCK, 0, 0, 0, "a_unlock_exclusive"));
    CHECK(set(&b, F_WRLCK, 0, 0, 0, "b_reacquire_after_unlock"));
    CHECK(set(&b, F_UNLCK, 0, 0, 0, "b_unlock_reacquired"));
    CHECK(set(&a, F_WRLCK, 4096, 4096, 0, "a_finite_exclusive"));
    CHECK(set(&b, F_WRLCK, 8192, 4096, 0, "b_adjacent_finite_allowed"));
    CHECK(set(&b, F_WRLCK, 6144, 1, 1, "b_overlapping_finite_denied"));
    CHECK(query(&b, F_WRLCK, 6144, 1, F_WRLCK, 4096, 4096,
                "getlk_finite_conflict_range"));
    CHECK(set(&a, F_UNLCK, 4096, 4096, 0, "a_finite_unlock"));
    CHECK(set(&b, F_WRLCK, 6144, 1, 0, "b_finite_reacquire"));
    CHECK(set(&b, F_UNLCK, 0, 0, 0, "b_unlock_all_finite"));
    CHECK(query(&a, F_WRLCK, 0, 0, F_UNLCK, 0, 0, "getlk_unlocked_posix_type"));
    CHECK(liz_getattr(a.client, a.context, ai, &after));
    if (before.attr.st_size != after.attr.st_size ||
        before.attr.st_mtim.tv_sec != after.attr.st_mtim.tv_sec ||
        before.attr.st_mtim.tv_nsec != after.attr.st_mtim.tv_nsec) {
        fprintf(stderr, "File size/mtime changed during lock-only probe\n");
        goto out;
    }
    printf("{\"ok\":%s,\"lock_mechanics_ok\":true,\"errno_translation_ok\":%s,"
           "\"passed\":%u,\"connections\":2,\"lock_owners\":2,"
           "\"data_writes\":0,\"size_and_mtime_unchanged\":true}\n",
           denial_mapping_ok ? "true" : "false",
           denial_mapping_ok ? "true" : "false", passed);
    result = denial_mapping_ok ? 0 : 1;
out:
    if (result)
        fprintf(stderr, "Native lock probe failed after %u checks; native error %d: %s\n",
                passed, liz_last_err(), liz_error_string(liz_last_err()));
    close_peer(&b);
    close_peer(&a);
    return result;
}
