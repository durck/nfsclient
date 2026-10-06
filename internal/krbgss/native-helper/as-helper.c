/* Optional MIT Kerberos AS bridge. Build separately; the Go CLI has no cgo. */
#include <krb5.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static krb5_error_code refuse_prompt(krb5_context context, void *data,
                                   const char *name, const char *banner,
                                   int count, krb5_prompt prompts[]) {
    (void)context; (void)data; (void)name; (void)banner; (void)count; (void)prompts;
    return KRB5_LIBOS_CANTREADPWD;
}

int main(int argc, char **argv) {
    krb5_context ctx = NULL;
    krb5_principal client = NULL;
    krb5_keytab kt = NULL;
    krb5_ccache out = NULL;
    krb5_get_init_creds_opt *opt = NULL;
    krb5_creds creds;
    krb5_error_code ret = 0;
    int fast = argc == 13 && !strcmp(argv[4], "fast");
    int pkinit = argc == 17 && !strcmp(argv[4], "pkinit");
    const char *output;
    char *identity = NULL;
    krb5_enctype enctypes[] = { ENCTYPE_AES256_CTS_HMAC_SHA1_96,
                               ENCTYPE_AES128_CTS_HMAC_SHA1_96 };
    memset(&creds, 0, sizeof(creds));
    umask(077);
    if ((!fast && !pkinit) || strcmp(argv[1], "--protocol") || strcmp(argv[2], "1") ||
        strcmp(argv[3], "--mode") || strcmp(argv[5], "--principal")) {
        fputs("Invalid AS helper protocol/arguments\n", stderr);
        return 64;
    }
    if (fast && (strcmp(argv[7], "--keytab") ||
        strcmp(argv[9], "--armor") || strcmp(argv[11], "--output") ||
        strncmp(argv[8], "FILE:/", 6) || strncmp(argv[10], "FILE:/", 6) ||
        strncmp(argv[12], "FILE:/", 6))) {
        fputs("Invalid AS helper protocol/arguments\n", stderr);
        return 64;
    }
    if (pkinit && (strcmp(argv[7], "--cert") || strcmp(argv[9], "--key") ||
        strcmp(argv[11], "--anchors") || strcmp(argv[13], "--revoke") ||
        strcmp(argv[15], "--output") || strncmp(argv[8], "FILE:/", 6) ||
        strncmp(argv[10], "FILE:/", 6) || strncmp(argv[12], "FILE:/", 6) ||
        strncmp(argv[16], "FILE:/", 6) ||
        (strcmp(argv[14], "-") && strncmp(argv[14], "FILE:/", 6)))) return 64;
    output = fast ? argv[12] : argv[16];
    if ((ret = krb5_init_context(&ctx))) goto cleanup;
    if ((ret = krb5_parse_name(ctx, argv[6], &client))) goto cleanup;
    if (fast && (ret = krb5_kt_resolve(ctx, argv[8], &kt))) goto cleanup;
    if ((ret = krb5_cc_resolve(ctx, output, &out))) goto cleanup;
    if ((ret = krb5_get_init_creds_opt_alloc(ctx, &opt))) goto cleanup;
    krb5_get_init_creds_opt_set_etype_list(opt, enctypes, 2);
    krb5_get_init_creds_opt_set_address_list(opt, NULL);
    krb5_get_init_creds_opt_set_canonicalize(opt, 0);
    if (fast) {
      if ((ret = krb5_get_init_creds_opt_set_fast_ccache_name(ctx, opt, argv[10])))
          goto cleanup;
      if ((ret = krb5_get_init_creds_opt_set_fast_flags(ctx, opt,
                                                    KRB5_FAST_REQUIRED)))
          goto cleanup;
      if ((ret = krb5_get_init_creds_keytab(ctx, &creds, client, kt, 0, NULL, opt)))
          goto cleanup;
    } else {
      size_t size = strlen(argv[8]) + strlen(argv[10]) + 2;
      identity = malloc(size);
      if (!identity) { ret = ENOMEM; goto cleanup; }
      snprintf(identity, size, "%s,%s", argv[8], argv[10] + 5);
      if ((ret = krb5_get_init_creds_opt_set_pa(ctx, opt, "X509_user_identity", identity))) goto cleanup;
      if ((ret = krb5_get_init_creds_opt_set_pa(ctx, opt, "X509_anchors", argv[12]))) goto cleanup;
      /* Discover KDC freshness first. Optimistic PKINIT can omit a required
       * freshness token. The caller enables only PKINIT and no password. */
      if ((ret = krb5_get_init_creds_password(ctx, &creds, client, NULL,
                                           refuse_prompt, NULL, 0, NULL, opt))) goto cleanup;
    }
    if (!krb5_principal_compare(ctx, client, creds.client)) {
        ret = KRB5KRB_AP_ERR_MODIFIED;
        goto cleanup;
    }
    if ((ret = krb5_cc_initialize(ctx, out, client))) goto cleanup;
    if ((ret = krb5_cc_store_cred(ctx, out, &creds))) goto cleanup;
    if ((ret = krb5_cc_close(ctx, out))) { out = NULL; goto cleanup; }
    out = NULL;
    fputs(fast ? "nfs-viewer-as-helper/1 fast-required\n" :
                 "nfs-viewer-as-helper/1 pkinit-required\n", stdout);
cleanup:
    free(identity);
    if (out) krb5_cc_close(ctx, out);
    if (opt) krb5_get_init_creds_opt_free(ctx, opt);
    if (kt) krb5_kt_close(ctx, kt);
    if (ctx) {
        krb5_free_cred_contents(ctx, &creds);
        if (client) krb5_free_principal(ctx, client);
        krb5_free_context(ctx);
    }
    if (ret) {
        /* Codes only: library diagnostics must never expose credential data. */
        fprintf(stderr, "Native AS failed (%ld); selected mechanism remains required\n", (long)ret);
        return 1;
    }
    return 0;
}
