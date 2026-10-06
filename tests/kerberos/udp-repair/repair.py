"""Bounded fixture-only repair for the exact Ubuntu ntirpc 4.3 source."""
import pathlib
import sys

p = pathlib.Path(sys.argv[1])
s = p.read_text()
start = s.index('static int\nxdrmem_iovcount(')
end = s.index('static const struct xdr_ops xdrmem_ops_aligned', start)
require = ('found_data == (vector[i].vio_type != VIO_DATA)', 'vector[0].vio_length = vector[0].vio_tail - vector[0].vio_head;')
assert all(fragment in s[start:end] for fragment in require), 'Unexpected source; do not apply blindly'
replacement = r'''static int
xdrmem_iovcount(XDR *xdrs, u_int start, u_int datalen)
{
    size_t used = xdrs->x_v.vio_tail - xdrs->x_v.vio_head;
    return start <= used && datalen <= used - start ? 1 : -1;
}

static bool
xdrmem_fillbufs(XDR *xdrs, u_int start, xdr_vio *vector, u_int datalen)
{
    if (xdrmem_iovcount(xdrs, start, datalen) < 0)
        return false;
    vector[0] = xdrs->x_v;
    vector[0].vio_type = VIO_DATA;
    vector[0].vio_head = xdrs->x_v.vio_head + start;
    vector[0].vio_tail = vector[0].vio_head + datalen;
    vector[0].vio_length = datalen;
    return true;
}

static bool
xdrmem_allochdrs(XDR *xdrs, u_int start, xdr_vio *vector, int iov_count)
{
    size_t capacity = xdrs->x_v.vio_wrap - xdrs->x_v.vio_head;
    size_t total = 0, prefix = 0;
    int i, data = -1;
    uint8_t *cursor;

    if (iov_count <= 0 || start > capacity)
        return false;
    /* Validate the whole layout before modifying bytes, vectors or cursor. */
    for (i = 0; i < iov_count; i++) {
        if (vector[i].vio_length > capacity - start - total)
            return false;
        if (vector[i].vio_type == VIO_DATA) {
            if (data != -1 || vector[i].vio_head != xdrs->x_v.vio_head + start ||
                vector[i].vio_length > UINT32_MAX ||
                xdrmem_iovcount(xdrs, start, vector[i].vio_length) < 0)
                return false;
            data = i;
            prefix = total;
        } else if (vector[i].vio_type != VIO_HEADER &&
                   vector[i].vio_type != VIO_TRAILER &&
                   vector[i].vio_type != VIO_TRAILER_LEN) {
            return false;
        }
        if (vector[i].vio_type == VIO_HEADER && data != -1)
            return false;
        if ((vector[i].vio_type == VIO_TRAILER ||
             vector[i].vio_type == VIO_TRAILER_LEN) && data == -1)
            return false;
        if (vector[i].vio_type == VIO_TRAILER_LEN &&
            (vector[i].vio_length != 4 || i + 1 == iov_count ||
             vector[i + 1].vio_type != VIO_TRAILER ||
             vector[i + 1].vio_length > UINT32_MAX))
            return false;
        total += vector[i].vio_length;
    }
    if (data == -1)
        return false;
    cursor = xdrs->x_v.vio_head + start;
    memmove(cursor + prefix, vector[data].vio_head, vector[data].vio_length);
    for (i = 0; i < iov_count; i++) {
        vector[i].vio_base = xdrs->x_v.vio_base;
        vector[i].vio_head = cursor;
        cursor += vector[i].vio_length;
        vector[i].vio_tail = cursor;
        vector[i].vio_wrap = xdrs->x_v.vio_wrap;
        if (vector[i].vio_type == VIO_TRAILER_LEN) {
            uint32_t length = htonl(vector[i + 1].vio_length);
            memcpy(vector[i].vio_head, &length, sizeof(length));
        }
    }
    xdrs->x_data = cursor;
    xdr_tail_update(xdrs);
    return true;
}

'''
p.write_text(s[:start] + replacement + s[end:])
