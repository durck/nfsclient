/* Fixture-only MIT helper: private, ignored authdata in a real KDC-issued TGT.
 * Public API reference: MIT krb5 1.20.1 tests/adata.c and kdc/kdc_authdata.c.
 * This is a token-size test, not PAC or domain authorization emulation.
 */
#define _POSIX_C_SOURCE 200809L
#include <krb5.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define PAYLOAD_SIZE 4096
#define PRIVATE_TYPE (-42)
#define REQUIRE(test, message) do { if (!(test)) { \
    fprintf(stderr, "%s\n", message); goto cleanup; } } while (0)
#define CHECK(call) do { krb5_error_code code = (call); if (code != 0) { \
    fprintf(stderr, "%s failed (MIT error %ld)\n", #call, (long)code); \
    goto cleanup; } } while (0)

static int same_object(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}

int main(int argc, char **argv)
{
    krb5_context ctx = NULL;
    krb5_ccache input = NULL, output = NULL;
    krb5_keytab keytab = NULL;
    krb5_principal client = NULL, expected = NULL, home = NULL, service = NULL;
    krb5_creds request = {0}, *tgt = NULL, *service_creds = NULL;
    krb5_ticket *ticket = NULL;
    krb5_authdata datum = {0}, *list[2], **wrapped = NULL, **found = NULL;
    krb5_authdata **pac = NULL;
    unsigned char payload[PAYLOAD_SIZE];
    struct stat parent_info = {0}, directory_info = {0}, cache_info = {0}, current = {0};
    char *parent = NULL, *stage = NULL, *output_name = NULL;
    const char *leaf = NULL, *stage_leaf = NULL;
    int parent_fd = -1, stage_fd = -1, result = 1;
    int stage_created = 0, cache_known = 0, published = 0;
    unsigned int tgt_bytes = 0, service_bytes = 0;

    if (argc != 4) {
        fprintf(stderr, "Usage: gss-large-tgt INPUT_FILE_CACHE NEW_OUTPUT_PATH SERVER_KEYTAB\n");
        return 2;
    }
    REQUIRE(strncmp(argv[1], "FILE:/", 6) == 0 && argv[2][0] == '/' &&
            argv[3][0] == '/', "Explicit absolute FILE cache, output and keytab required");
    REQUIRE(strlen(argv[2]) <= 4096, "Output path too long");
    umask(0077);
    leaf = strrchr(argv[2], '/') + 1;
    REQUIRE(*leaf != '\0' && strcmp(leaf, ".") != 0 && strcmp(leaf, "..") != 0,
            "Output must name a cache file");
    parent = strndup(argv[2], (size_t)(leaf - argv[2] - 1));
    REQUIRE(parent != NULL && parent[0] != '\0', "Output requires a private parent directory");
    parent_fd = open(parent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    REQUIRE(parent_fd >= 0 && fstat(parent_fd, &parent_info) == 0 &&
            parent_info.st_uid == geteuid() && (parent_info.st_mode & 0777) == 0700,
            "Output parent must be an owned private directory");
    REQUIRE(fstatat(parent_fd, leaf, &current, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT,
            "Refusing existing or unavailable output cache");
    CHECK(krb5_init_context(&ctx));
    CHECK(krb5_cc_resolve(ctx, argv[1], &input));
    CHECK(krb5_cc_get_principal(ctx, input, &client));
    CHECK(krb5_parse_name(ctx, "alice@NFS.TEST", &expected));
    REQUIRE(krb5_principal_compare(ctx, client, expected), "Fixture requires Alice in NFS.TEST");
    CHECK(krb5_parse_name(ctx, "krbtgt/NFS.TEST@NFS.TEST", &home));
    CHECK(krb5_parse_name(ctx, "nfs/server.nfs.test@NFS.TEST", &service));

    memset(payload, 'X', sizeof(payload));
    datum.ad_type = PRIVATE_TYPE;
    datum.length = sizeof(payload);
    datum.contents = payload;
    list[0] = &datum;
    list[1] = NULL;
    CHECK(krb5_encode_authdata_container(ctx, KRB5_AUTHDATA_IF_RELEVANT, list, &wrapped));
    request.client = client;
    request.server = home;
    request.authdata = wrapped;
    /* Requested authdata is part of the cache match: an ordinary TGT cannot
     * satisfy this request. NO_STORE keeps the original cache unchanged. */
    CHECK(krb5_get_credentials(ctx, KRB5_GC_NO_STORE, input, &request, &tgt));
    REQUIRE(krb5_principal_compare(ctx, tgt->client, client) &&
            krb5_principal_compare(ctx, tgt->server, home) && !tgt->is_skey &&
            tgt->second_ticket.length == 0 && tgt->ticket.length > 2048,
            "KDC did not issue the expected large ordinary home TGT");

    stage = malloc(strlen(parent) + sizeof("/.gss-large-tgt-XXXXXX"));
    REQUIRE(stage != NULL, "Allocation failed");
    sprintf(stage, "%s/.gss-large-tgt-XXXXXX", parent);
    REQUIRE(mkdtemp(stage) != NULL, "Cannot create private cache staging directory");
    stage_created = 1;
    stage_leaf = strrchr(stage, '/') + 1;
    stage_fd = openat(parent_fd, stage_leaf, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    REQUIRE(stage_fd >= 0 && fstat(stage_fd, &directory_info) == 0 &&
            directory_info.st_uid == geteuid() && (directory_info.st_mode & 0777) == 0700 &&
            lstat(parent, &current) == 0 && same_object(&current, &parent_info),
            "Private staging directory identity or ownership changed");
    output_name = malloc(strlen(stage) + sizeof("FILE:/cache"));
    REQUIRE(output_name != NULL, "Allocation failed");
    sprintf(output_name, "FILE:%s/cache", stage);
    CHECK(krb5_cc_resolve(ctx, output_name, &output));
    /* MIT FILE initialization unlinks and recreates its path. Let the library
     * do so only inside our new private directory, then record its actual file. */
    CHECK(krb5_cc_initialize(ctx, output, client));
    REQUIRE(fstatat(stage_fd, "cache", &cache_info, AT_SYMLINK_NOFOLLOW) == 0 &&
            S_ISREG(cache_info.st_mode) && cache_info.st_uid == geteuid() &&
            (cache_info.st_mode & 0777) == 0600 && cache_info.st_nlink == 1,
            "MIT did not create a private ordinary cache");
    cache_known = 1;
    CHECK(krb5_cc_store_cred(ctx, output, tgt));

    /* Exercise the same fresh-TGS behavior as the Go client's FILE path. */
    request.server = service;
    request.authdata = NULL;
    CHECK(krb5_get_credentials(ctx, KRB5_GC_NO_STORE, output, &request, &service_creds));
    REQUIRE(krb5_principal_compare(ctx, service_creds->client, client) &&
            krb5_principal_compare(ctx, service_creds->server, service) &&
            service_creds->ticket.length > 2048,
            "Fresh service ticket identity or size mismatch");
    CHECK(krb5_decode_ticket(&service_creds->ticket, &ticket));
    CHECK(krb5_kt_resolve(ctx, argv[3], &keytab));
    CHECK(krb5_server_decrypt_ticket_keytab(ctx, keytab, ticket));
    REQUIRE(krb5_principal_compare(ctx, ticket->server, service) &&
            krb5_principal_compare(ctx, ticket->enc_part2->client, client),
            "Decrypted service identity mismatch");
    CHECK(krb5_find_authdata(ctx, ticket->enc_part2->authorization_data, NULL,
                           PRIVATE_TYPE, &found));
    REQUIRE(found != NULL && found[0] != NULL && found[1] == NULL &&
            found[0]->length == sizeof(payload) &&
            memcmp(found[0]->contents, payload, sizeof(payload)) == 0,
            "Exact private authdata did not propagate from TGT to service ticket");
    CHECK(krb5_find_authdata(ctx, ticket->enc_part2->authorization_data, NULL,
                           KRB5_AUTHDATA_WIN2K_PAC, &pac));
    REQUIRE(pac == NULL || pac[0] == NULL, "Unexpected PAC in size-only fixture");
    {
        krb5_ccache closing = output;
        output = NULL;
        CHECK(krb5_cc_close(ctx, closing));
    }
    REQUIRE(fstatat(stage_fd, "cache", &current, AT_SYMLINK_NOFOLLOW) == 0 &&
            same_object(&current, &cache_info) && S_ISREG(current.st_mode) &&
            current.st_uid == geteuid() && (current.st_mode & 0777) == 0600 &&
            current.st_nlink == 1, "Verified cache identity or mode changed");
    REQUIRE(fstatat(parent_fd, stage_leaf, &current, AT_SYMLINK_NOFOLLOW) == 0 &&
            same_object(&current, &directory_info), "Staging directory binding changed");
    REQUIRE(linkat(stage_fd, "cache", parent_fd, leaf, 0) == 0,
            "Cannot publish cache without replacing an existing path");
    published = 1;
    tgt_bytes = (unsigned)tgt->ticket.length;
    service_bytes = (unsigned)service_creds->ticket.length;
    result = 0;

cleanup:
    if (keytab != NULL) krb5_kt_close(ctx, keytab);
    if (output != NULL) krb5_cc_close(ctx, output);
    if (input != NULL) krb5_cc_close(ctx, input);
    if (ctx != NULL) {
        krb5_free_authdata(ctx, found);
        krb5_free_authdata(ctx, pac);
        krb5_free_authdata(ctx, wrapped);
        krb5_free_ticket(ctx, ticket);
        krb5_free_creds(ctx, tgt);
        krb5_free_creds(ctx, service_creds);
        krb5_free_principal(ctx, client);
        krb5_free_principal(ctx, expected);
        krb5_free_principal(ctx, home);
        krb5_free_principal(ctx, service);
        krb5_free_context(ctx);
    }
    if (stage_created) {
        int clean = stage_fd >= 0 &&
            fstatat(parent_fd, stage_leaf, &current, AT_SYMLINK_NOFOLLOW) == 0 &&
            same_object(&current, &directory_info);
        if (clean && cache_known) {
            clean = fstatat(stage_fd, "cache", &current, AT_SYMLINK_NOFOLLOW) == 0 &&
                same_object(&current, &cache_info) && unlinkat(stage_fd, "cache", 0) == 0;
        }
        if (clean) clean = unlinkat(parent_fd, stage_leaf, AT_REMOVEDIR) == 0;
        if (!clean) {
            fprintf(stderr, "Owned staging cleanup failed or its identity changed\n");
            result = 1;
        }
    }
    if (result != 0 && published &&
        fstatat(parent_fd, leaf, &current, AT_SYMLINK_NOFOLLOW) == 0 &&
        same_object(&current, &cache_info))
        unlinkat(parent_fd, leaf, 0);
    if (stage_fd >= 0) close(stage_fd);
    if (parent_fd >= 0) close(parent_fd);
    free(parent);
    free(stage);
    free(output_name);
    if (result == 0)
        printf("{\"private_authdata_bytes\":%u,\"tgt_ticket_bytes\":%u,"
               "\"service_ticket_bytes\":%u,\"exact_authdata_verified\":true,"
               "\"pac_present\":false,\"fresh_service_ticket_verified\":true}\n",
               (unsigned)sizeof(payload), tgt_bytes, service_bytes);
    return result;
}
