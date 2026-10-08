# Optional MIT AS helper

FAST and FILE PKINIT use the portable pure-Go implementation by default on
Windows and Linux. No helper or system Kerberos installation is required.
The explicit `--as-helper` option retains the Linux MIT compatibility path
described below; a failed helper exchange never falls back to pure Go or to
another authentication mechanism.

From the project root, build on Linux with a C compiler and MIT Kerberos
development headers/libraries (`krb5-config` must be on PATH):

```sh
mkdir -p bin
cc -O2 -Wall -Wextra -Werror internal/krbgss/native-helper/as-helper.c $(krb5-config --cflags --libs) -o bin/nfs-viewer-as-helper
```

Select its absolute trusted path with `--as-helper`; it is not discovered through
PATH. The Go executable remains cgo-free. The helper accepts only protocol 1,
mode fast or pkinit, one principal and explicit FILE input/output paths. FAST requires
KRB5_FAST_REQUIRED, disables canonicalization, limits keys to AES128/AES256 and
checks the returned principal before emitting a cache and success record.
There is no unarmored or password fallback and no interactive input.

The Go caller supplies sanitized environment/configuration, private credential
copies, bounded output and a cancelable subprocess deadline. Source and helper
are part of the trusted authentication implementation; do not substitute an
untrusted executable. See [the FAST contract](../../../docs/AUTHENTICATION.md#fast-and-pkinit).

PKINIT requires a MIT installation built with its PKINIT/OpenSSL plugin. The
caller enables only that preauth plugin, selects certificate/key/CA and optional
mandatory CRL checking, and the helper refuses every password prompt. The
resulting canonical principal must match before a cache is emitted. See
[the PKINIT contract](../../../docs/AUTHENTICATION.md#fast-and-pkinit).
