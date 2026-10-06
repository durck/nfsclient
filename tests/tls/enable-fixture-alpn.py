#!/usr/bin/env python3
"""Apply a narrow ALPN fix to pinned upstream ktls-utils 0.9 for this NFS lab."""
import pathlib
import sys

path = pathlib.Path(sys.argv[1])/'src/tlshd/server.c'
source = path.read_text()
needle = '\tgnutls_transport_set_int(session, parms->sockfd);'
assert source.count(needle) == 2  # X.509 then PSK, only X.509 is used here.
replacement = '''	/* This fixture daemon serves only SunRPC, RFC 9289 section 5. */
	gnutls_datum_t alpn = { (unsigned char *)"sunrpc", 6 };
	ret = gnutls_alpn_set_protocols(session, &alpn, 1, GNUTLS_ALPN_MANDATORY);
	if (ret != GNUTLS_E_SUCCESS) {
		tlshd_log_gnutls_error(ret);
		gnutls_deinit(session);
		goto out_free_creds;
	}
'''+needle
path.write_text(source.replace(needle, replacement, 1))
