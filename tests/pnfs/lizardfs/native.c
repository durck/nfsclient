/* Native, mount-free oracle for the explicitly selected disposable LizardFS lab.
 * API: lizardfs/lizardfs b1e97f974fc3a4046edaf9fdc3962264d4cd24fa.
 * This utility never creates or repairs test files. --setup changes root only.
 */
#define _POSIX_C_SOURCE 200809L
#include <inttypes.h>
#include <openssl/evp.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lizardfs_c_api.h"

#define LAB_UID 25001
#define LAB_GID 25000
#define FILE_SIZE UINT64_C(134217745)
#define CHUNK_SIZE UINT64_C(67108864)
#define READ_SIZE (1024U * 1024U)
#define MAX_SERVERS 64
#define MAX_CHUNKS 64

static int api_error(const char *operation)
{
    fprintf(stderr, "%s: %s (LizardFS error %d)\n", operation,
            liz_error_string(liz_last_err()), liz_last_err());
    return -1;
}

static void json_string(FILE *out, const char *value)
{
    const unsigned char *p = (const unsigned char *)(value ? value : "");
    fputc('"', out);
    for (; *p; ++p) {
        if (*p == '"' || *p == '\\')
            fprintf(out, "\\%c", *p);
        else if (*p < 0x20 || *p >= 0x7f)
            fprintf(out, "\\u%04x", *p);
        else
            fputc(*p, out);
    }
    fputc('"', out);
}

/* The C API exposes addresses as host-order uint32_t, as used by its FSAL. */
static void json_ip(FILE *out, uint32_t address)
{
    fprintf(out, "\"%u.%u.%u.%u\"", address >> 24,
            (address >> 16) & 255, (address >> 8) & 255, address & 255);
}

static unsigned add_ip(uint32_t *ips, unsigned count, uint32_t ip)
{
    for (unsigned i = 0; i < count; ++i)
        if (ips[i] == ip)
            return count;
    ips[count] = ip;
    return count + 1;
}

static int valid_name(const char *name)
{
    regex_t expression;
    int result;
    if (strlen(name) > 200 ||
        regcomp(&expression,
                "^pnfs-multi-(api|cli)-(windows|linux)-4[.][12]-[0-9]+$",
                REG_EXTENDED | REG_NOSUB) != 0)
        return 0;
    result = regexec(&expression, name, 0, NULL, 0) == 0;
    regfree(&expression);
    return result;
}

static int selftest(void)
{
    const char *accepted[] = {
        "pnfs-multi-api-windows-4.1-1", "pnfs-multi-cli-linux-4.2-1234567890"
    };
    const char *rejected[] = {
        "../pnfs-multi-api-windows-4.1-1", "pnfs-multi-api-windows-4x1-1",
        "pnfs-multi-cli-linux-4.3-1", "pnfs-multi-cli-linux-4.2-",
        "pnfs-multi-cli-linux-4.2-1\n", "pnfs-multi-cli-linux-4.2-1/child",
        "pnfs-multi-api-windows-4.1-1;touch x", ""
    };
    for (unsigned i = 0; i < sizeof(accepted) / sizeof(*accepted); ++i)
        if (!valid_name(accepted[i]))
            return 1;
    for (unsigned i = 0; i < sizeof(rejected) / sizeof(*rejected); ++i)
        if (valid_name(rejected[i]))
            return 1;
    puts("{\"ok\":true,\"selftest\":\"filename boundary checks\"}");
    return 0;
}

static int servers_json(liz_t *client, FILE *out, int require_two)
{
    liz_chunkserver_info_t servers[MAX_SERVERS] = {0};
    uint32_t ips[MAX_SERVERS], count = 0;
    unsigned distinct = 0;
    if (liz_get_chunkservers_info(client, servers, MAX_SERVERS, &count) < 0)
        return api_error("get_chunkservers_info");
    if (count >= MAX_SERVERS) {
        fprintf(stderr, "Chunkserver inventory may be truncated\n");
        liz_destroy_chunkservers_info(servers);
        return -1;
    }
    fputs("\"chunkservers\":[", out);
    for (uint32_t i = 0; i < count; ++i) {
        int active = servers[i].version != UINT32_C(0x01000000);
        if (active)
            distinct = add_ip(ips, distinct, servers[i].ip);
        if (i)
            fputc(',', out);
        fputs("{\"ip\":", out);
        json_ip(out, servers[i].ip);
        fprintf(out, ",\"port\":%u,\"version\":%u,\"active\":%s,"
                "\"used_space\":%" PRIu64 ",\"total_space\":%" PRIu64
                ",\"label\":", servers[i].port,
                servers[i].version, active ? "true" : "false",
                servers[i].used_space, servers[i].total_space);
        json_string(out, servers[i].label);
        fputc('}', out);
    }
    fprintf(out, "],\"active_distinct_ips\":%u", distinct);
    liz_destroy_chunkservers_info(servers);
    if (require_two && distinct < 2) {
        fprintf(stderr, "Expected at least two active chunkserver IPs, got %u\n",
                distinct);
        return -1;
    }
    return 0;
}

static int setup(liz_t *client, liz_context_t *root, FILE *out)
{
    struct stat desired = {0};
    liz_attr_reply_t actual;
    char goal[LIZARDFS_MAX_GOAL_NAME] = {0};
    desired.st_uid = LAB_UID;
    desired.st_gid = LAB_GID;
    desired.st_mode = 01777;
    if (liz_setattr(client, root, LIZARDFS_INODE_ROOT, &desired,
                    LIZ_SET_ATTR_UID | LIZ_SET_ATTR_GID | LIZ_SET_ATTR_MODE,
                    &actual) < 0)
        return api_error("set root ownership/mode");
    if (liz_setgoal(client, root, LIZARDFS_INODE_ROOT, "1", 0) < 0)
        return api_error("set root goal");
    if (liz_getattr(client, root, LIZARDFS_INODE_ROOT, &actual) < 0 ||
        liz_getgoal(client, root, LIZARDFS_INODE_ROOT, goal) < 0)
        return api_error("verify root attributes/goal");
    if (!S_ISDIR(actual.attr.st_mode) || actual.attr.st_uid != LAB_UID ||
        actual.attr.st_gid != LAB_GID || (actual.attr.st_mode & 07777) != 01777 ||
        strcmp(goal, "1") != 0) {
        fprintf(stderr, "Root ownership/mode/goal verification failed\n");
        return -1;
    }
    fprintf(out, "{\"ok\":true,\"operation\":\"setup\",\"root_inode\":1,"
            "\"uid\":%u,\"gid\":%u,\"mode\":\"1777\",\"goal\":\"1\",",
            (unsigned)actual.attr.st_uid, (unsigned)actual.attr.st_gid);
    if (servers_json(client, out, 1) < 0)
        return -1;
    fputs("}\n", out);
    return 0;
}

static int expected_stat(const struct stat *st)
{
    return S_ISREG(st->st_mode) && st->st_size == (off_t)FILE_SIZE &&
           st->st_uid == LAB_UID && st->st_gid == LAB_GID &&
           (st->st_mode & 07777) == 0644;
}

static int verify_file(liz_t *client, liz_context_t *context, const char *name,
                       FILE *out)
{
    liz_entry_t entry;
    liz_attr_reply_t before, after;
    liz_fileinfo_t *file = NULL;
    liz_chunk_info_t chunks[MAX_CHUNKS] = {0};
    uint32_t chunk_count = 0, ips[MAX_CHUNKS];
    unsigned distinct = 0, digest_length = 0;
    unsigned char digest[EVP_MAX_MD_SIZE];
    char goal[LIZARDFS_MAX_GOAL_NAME] = {0};
    unsigned char *buffer = NULL;
    EVP_MD_CTX *hash = NULL;
    uint64_t offset = 0;
    int result = -1, have_chunks = 0;

    if (liz_lookup(client, context, LIZARDFS_INODE_ROOT, name, &entry) < 0 ||
        liz_getattr(client, context, entry.ino, &before) < 0 ||
        liz_getgoal(client, context, entry.ino, goal) < 0)
        return api_error("lookup/getattr/getgoal");
    if (!expected_stat(&before.attr) || strcmp(goal, "1") != 0) {
        fprintf(stderr, "%s: expected regular file, size=%" PRIu64
                ", uid=%d, gid=%d, mode=0644, goal=1; got size=%jd, "
                "uid=%u, gid=%u, mode=%04o, goal=%s\n", name, FILE_SIZE,
                LAB_UID, LAB_GID, (intmax_t)before.attr.st_size,
                (unsigned)before.attr.st_uid, (unsigned)before.attr.st_gid,
                before.attr.st_mode & 07777, goal);
        return -1;
    }
    file = liz_open(client, context, entry.ino, O_RDONLY);
    if (!file)
        return api_error("open for native verification");
    buffer = malloc(READ_SIZE);
    hash = EVP_MD_CTX_new();
    if (!buffer || !hash || EVP_DigestInit_ex(hash, EVP_sha256(), NULL) != 1) {
        fprintf(stderr, "Cannot allocate native read/hash state\n");
        goto done;
    }
    while (offset < FILE_SIZE) {
        size_t requested = FILE_SIZE - offset < READ_SIZE
                               ? (size_t)(FILE_SIZE - offset) : READ_SIZE;
        ssize_t got = liz_read(client, context, file, (off_t)offset,
                               requested, (char *)buffer);
        if (got < 0) {
            api_error("native read");
            goto done;
        }
        if (got == 0 || (size_t)got > requested) {
            fprintf(stderr, "%s: invalid read length %zd at offset %" PRIu64
                    "\n", name, got, offset);
            goto done;
        }
        for (size_t i = 0; i < (size_t)got; ++i) {
            uint64_t position = offset + i;
            unsigned char expected = (unsigned char)
                ((position * 31 + position / 251) % 256);
            if (buffer[i] != expected) {
                fprintf(stderr, "%s: pattern mismatch at offset %" PRIu64
                        ": expected=%u actual=%u\n", name, position,
                        (unsigned)expected, (unsigned)buffer[i]);
                goto done;
            }
        }
        if (EVP_DigestUpdate(hash, buffer, (size_t)got) != 1) {
            fprintf(stderr, "SHA-256 update failed\n");
            goto done;
        }
        offset += (uint64_t)got;
    }
    if (liz_read(client, context, file, (off_t)offset, 1, (char *)buffer) != 0) {
        fprintf(stderr, "%s: native EOF verification failed\n", name);
        goto done;
    }
    if (EVP_DigestFinal_ex(hash, digest, &digest_length) != 1 || digest_length != 32) {
        fprintf(stderr, "SHA-256 finalization failed\n");
        goto done;
    }
    if (liz_getattr(client, context, entry.ino, &after) < 0) {
        api_error("getattr after native read");
        goto done;
    }
    if (!expected_stat(&after.attr) ||
        before.attr.st_mtim.tv_sec != after.attr.st_mtim.tv_sec ||
        before.attr.st_mtim.tv_nsec != after.attr.st_mtim.tv_nsec ||
        before.attr.st_ctim.tv_sec != after.attr.st_ctim.tv_sec ||
        before.attr.st_ctim.tv_nsec != after.attr.st_ctim.tv_nsec) {
        fprintf(stderr, "%s: attributes changed during native read\n", name);
        goto done;
    }
    if (liz_get_chunks_info(client, context, entry.ino, 0, chunks, MAX_CHUNKS,
                            &chunk_count) < 0) {
        api_error("get_chunks_info");
        goto done;
    }
    have_chunks = 1;
    if (chunk_count != (FILE_SIZE + CHUNK_SIZE - 1) / CHUNK_SIZE) {
        fprintf(stderr, "%s: expected three physical chunks, got %u\n", name,
                chunk_count);
        goto done;
    }
    for (uint32_t i = 0; i < chunk_count; ++i) {
        if (!chunks[i].chunk_id || chunks[i].parts_size != 1 ||
            !chunks[i].parts || chunks[i].parts[0].part_type_id != 0 ||
            !chunks[i].parts[0].addr || !chunks[i].parts[0].port) {
            fprintf(stderr, "%s: chunk %u is not one ordinary goal-1 replica\n",
                    name, i);
            goto done;
        }
        distinct = add_ip(ips, distinct, chunks[i].parts[0].addr);
    }
    if (distinct < 2) {
        fprintf(stderr, "%s: actual chunks occupy only %u physical server IP; "
                "multi-DS placement not established\n", name, distinct);
        goto done;
    }
    if (liz_release(client, file) < 0) {
        file = NULL;
        api_error("release native file");
        goto done;
    }
    file = NULL;
    fputs("{\"name\":", out);
    json_string(out, name);
    fprintf(out, ",\"inode\":%u,\"size\":%" PRIu64 ",\"uid\":%u,"
            "\"gid\":%u,\"mode\":\"0644\",\"goal\":\"1\",\"sha256\":\"",
            entry.ino, offset, (unsigned)after.attr.st_uid,
            (unsigned)after.attr.st_gid);
    for (unsigned i = 0; i < digest_length; ++i)
        fprintf(out, "%02x", digest[i]);
    fprintf(out, "\",\"pattern_verified\":true,\"distinct_chunkserver_ips\":%u,"
            "\"chunks\":[", distinct);
    for (uint32_t i = 0; i < chunk_count; ++i) {
        const liz_chunk_part_info_t *part = &chunks[i].parts[0];
        if (i)
            fputc(',', out);
        fprintf(out, "{\"index\":%u,\"id\":\"%" PRIu64
                "\",\"version\":%u,\"addresses\":[{\"ip\":", i,
                chunks[i].chunk_id, chunks[i].chunk_version);
        json_ip(out, part->addr);
        fprintf(out, ",\"port\":%u,\"part_type_id\":%u,\"label\":",
                part->port, part->part_type_id);
        json_string(out, part->label);
        fputs("}]}", out);
    }
    fputs("]}", out);
    result = 0;
done:
    if (have_chunks)
        liz_destroy_chunks_info(chunks);
    if (file)
        liz_release(client, file);
    EVP_MD_CTX_free(hash);
    free(buffer);
    return result;
}

int main(int argc, char **argv)
{
    liz_init_params_t parameters;
    liz_t *client = NULL;
    liz_context_t *context = NULL;
    FILE *report = NULL;
    int result = 1;
    int is_setup = argc >= 2 && strcmp(argv[1], "--setup") == 0;
    int inspect = argc >= 2 && strcmp(argv[1], "--inspect") == 0;
    int oracle = argc >= 2 && strcmp(argv[1], "--oracle") == 0;
    if (argc == 2 && strcmp(argv[1], "--selftest") == 0)
        return selftest();
    if ((!is_setup && !inspect && !oracle) || argc < 3 ||
        ((is_setup || inspect) && argc != 3) || (oracle && argc < 4)) {
        fprintf(stderr, "Usage: %s --setup MASTER | --inspect MASTER | "
                "--oracle MASTER FILENAME... | --selftest\n", argv[0]);
        return 2;
    }
    for (int i = 3; oracle && i < argc; ++i) {
        if (!valid_name(argv[i])) {
            fprintf(stderr, "Rejected filename outside the lab fixture pattern\n");
            return 2;
        }
        for (int j = 3; j < i; ++j)
            if (strcmp(argv[i], argv[j]) == 0) {
                fprintf(stderr, "Duplicate fixture filename rejected\n");
                return 2;
            }
    }
    report = tmpfile();
    if (!report) {
        perror("tmpfile for atomic JSON report");
        return 1;
    }
    liz_set_default_init_params(&parameters, argv[2], "9421", "pnfs-native-oracle");
    parameters.subfolder = "/";
    parameters.io_retries = 3;
    parameters.total_read_timeout_ms = 10000;
    parameters.cache_expiration_time_ms = 0;
    parameters.attr_cache_timeout = 0;
    parameters.entry_cache_timeout = 0;
    parameters.direntry_cache_timeout = 0;
    parameters.verbose = false;
    client = liz_init_with_params(&parameters);
    if (!client) {
        api_error("connect to explicitly selected lab master");
        goto done;
    }
    context = liz_create_user_context(is_setup ? 0 : LAB_UID,
                                      is_setup ? 0 : LAB_GID, getpid(), 0);
    if (!context) {
        api_error("create explicit user context");
        goto done;
    }
    if (is_setup) {
        if (setup(client, context, report) < 0)
            goto done;
    } else if (inspect) {
        fputs("{\"ok\":true,\"operation\":\"inspect\",", report);
        if (servers_json(client, report, 0) < 0)
            goto done;
        fputs("}\n", report);
    } else {
        fputs("{\"ok\":true,\"operation\":\"oracle\","
              "\"backend\":\"LizardFS native C API\",\"files\":[", report);
        for (int i = 3; i < argc; ++i) {
            if (i != 3)
                fputc(',', report);
            if (verify_file(client, context, argv[i], report) < 0)
                goto done;
        }
        fputs("]}\n", report);
    }
    if (fflush(report) != 0 || ferror(report) || fseek(report, 0, SEEK_SET) != 0) {
        fprintf(stderr, "Cannot finish JSON report\n");
        goto done;
    }
    {
        char buffer[4096];
        size_t length;
        while ((length = fread(buffer, 1, sizeof(buffer), report)) != 0)
            if (fwrite(buffer, 1, length, stdout) != length)
                goto done;
        if (ferror(report) || fflush(stdout) != 0)
            goto done;
    }
    result = 0;
done:
    if (context)
        liz_destroy_context(context);
    if (client)
        liz_destroy(client);
    fclose(report);
    return result;
}
