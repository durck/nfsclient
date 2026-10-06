/* Regression checks for the separately named ntirpc UDP fixture repair. */
#include <rpc/rpc.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

static int failures;
#define CHECK(expr) do { if (!(expr)) { fprintf(stderr, "line %d: %s\n", __LINE__, #expr); failures++; } } while (0)

int main(void)
{
    char buffer[128];
    XDR x;
    xdr_vio v[4];
    const char data[] = "abcdEFGH";
    memset(buffer, 0, sizeof(buffer));
    xdrmem_create(&x, buffer, sizeof(buffer), XDR_ENCODE);
    CHECK(XDR_PUTBYTES(&x, "PREFIX00", 8));
    CHECK(XDR_PUTBYTES(&x, data, 8));
    CHECK(XDR_GETPOS(&x) == 16);
    memset(v, 0, sizeof(v));
    CHECK(XDR_FILLBUFS(&x, 9, v, 3));
    CHECK(v[0].vio_head == (uint8_t *)buffer + 9);
    CHECK(v[0].vio_length == 3);
    CHECK(v[0].vio_tail == (uint8_t *)buffer + 12);
    CHECK(!XDR_FILLBUFS(&x, 15, v, 2));
    CHECK(!XDR_FILLBUFS(&x, UINT32_MAX, v, 2));

    /* Integrity: existing data followed by length and MIC trailer. */
    memset(v, 0, sizeof(v));
    CHECK(XDR_FILLBUFS(&x, 8, v, 8));
    v[1].vio_type = VIO_TRAILER_LEN; v[1].vio_length = 4;
    v[2].vio_type = VIO_TRAILER; v[2].vio_length = 12;
    CHECK(XDR_SETPOS(&x, 8));
    CHECK(XDR_ALLOCHDRS(&x, 8, v, 3));
    CHECK(XDR_GETPOS(&x) == 32);
    CHECK(v[1].vio_head == (uint8_t *)buffer + 16);
    CHECK(v[2].vio_head == (uint8_t *)buffer + 20);
    CHECK(memcmp(buffer + 16, "\0\0\0\14", 4) == 0);
    CHECK(memcmp(buffer + 8, data, 8) == 0);
    XDR_DESTROY(&x);

    /* Privacy: overlapping in-place move to make room for a GSS header. */
    memset(buffer, 0, sizeof(buffer));
    xdrmem_create(&x, buffer, sizeof(buffer), XDR_ENCODE);
    CHECK(XDR_PUTBYTES(&x, "PREFIX00", 8));
    CHECK(XDR_PUTBYTES(&x, data, 8));
    CHECK(XDR_GETPOS(&x) == 16);
    memset(v, 0, sizeof(v));
    v[0].vio_type = VIO_HEADER; v[0].vio_length = 4;
    CHECK(XDR_FILLBUFS(&x, 8, &v[1], 8));
    v[2].vio_type = VIO_TRAILER; v[2].vio_length = 0;
    v[3].vio_type = VIO_TRAILER; v[3].vio_length = 16;
    CHECK(XDR_SETPOS(&x, 8));
    CHECK(XDR_ALLOCHDRS(&x, 8, v, 4));
    CHECK(XDR_GETPOS(&x) == 36);
    CHECK(v[1].vio_head == (uint8_t *)buffer + 12);
    CHECK(memcmp(buffer + 12, data, 8) == 0);
    CHECK(memcmp(buffer, "PREFIX00", 8) == 0);
    XDR_DESTROY(&x);

    /* Refuse oversized allocation without changing cursor, bytes or vectors. */
    xdrmem_create(&x, buffer, sizeof(buffer), XDR_ENCODE);
    CHECK(XDR_PUTBYTES(&x, data, 8));
    CHECK(XDR_GETPOS(&x) == 8);
    memset(v, 0, sizeof(v));
    CHECK(XDR_FILLBUFS(&x, 0, v, 8));
    v[1].vio_type = VIO_TRAILER; v[1].vio_length = sizeof(buffer);
    xdr_vio before[4]; memcpy(before, v, sizeof(v));
    CHECK(XDR_SETPOS(&x, 0));
    CHECK(!XDR_ALLOCHDRS(&x, 0, v, 2));
    CHECK(XDR_GETPOS(&x) == 0);
    CHECK(memcmp(buffer, data, 8) == 0);
    CHECK(memcmp(v, before, sizeof(v)) == 0);
    CHECK(!XDR_ALLOCHDRS(&x, UINT32_MAX, v, 2));
    XDR_DESTROY(&x);
    printf("xdr-memory regressions: %d failures\n", failures);
    return failures ? 1 : 0;
}
