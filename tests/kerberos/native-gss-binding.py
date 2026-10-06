"""Disposable native MIT GSS binding oracle; never logs tokens or key material."""

import argparse
import ctypes as c
import socket
import struct


class Buffer(c.Structure):
    _fields_ = [("length", c.c_size_t), ("value", c.c_void_p)]


class Bindings(c.Structure):
    _fields_ = [
        ("initiator_addrtype", c.c_uint32), ("initiator_address", Buffer),
        ("acceptor_addrtype", c.c_uint32), ("acceptor_address", Buffer),
        ("application_data", Buffer),
    ]


lib = c.CDLL("libgssapi_krb5.so.2")
u32p, handlep = c.POINTER(c.c_uint32), c.POINTER(c.c_void_p)
lib.gss_accept_sec_context.argtypes = [
    u32p, handlep, c.c_void_p, c.POINTER(Buffer), c.POINTER(Bindings),
    handlep, handlep, c.POINTER(Buffer), u32p, u32p, handlep,
]
lib.gss_accept_sec_context.restype = c.c_uint32
lib.gss_release_buffer.argtypes = [u32p, c.POINTER(Buffer)]
lib.gss_delete_sec_context.argtypes = [u32p, handlep, c.POINTER(Buffer)]
lib.gss_release_name.argtypes = [u32p, handlep]
lib.gss_release_cred.argtypes = [u32p, handlep]


def accept(token, binding):
    token_data, binding_data = c.create_string_buffer(token), c.create_string_buffer(binding)
    request = Buffer(len(token), c.cast(token_data, c.c_void_p))
    channel = Bindings(255, Buffer(), 255, Buffer(), Buffer(len(binding), c.cast(binding_data, c.c_void_p)))
    context, name, mechanism, delegated = c.c_void_p(), c.c_void_p(), c.c_void_p(), c.c_void_p()
    minor, flags, lifetime = c.c_uint32(), c.c_uint32(), c.c_uint32()
    reply = Buffer()
    try:
        major = lib.gss_accept_sec_context(
            c.byref(minor), c.byref(context), None, c.byref(request), c.byref(channel),
            c.byref(name), c.byref(mechanism), c.byref(reply), c.byref(flags),
            c.byref(lifetime), c.byref(delegated),
        )
        return major, minor.value, flags.value, reply.length
    finally:
        lib.gss_release_buffer(c.byref(minor), c.byref(reply))
        if context.value:
            lib.gss_delete_sec_context(c.byref(minor), c.byref(context), None)
        if name.value:
            lib.gss_release_name(c.byref(minor), c.byref(name))
        if delegated.value:
            lib.gss_release_cred(c.byref(minor), c.byref(delegated))


def read_exact(conn, length):
    out = bytearray()
    while len(out) < length:
        part = conn.recv(length - len(out))
        if not part:
            raise EOFError("truncated oracle request")
        out.extend(part)
    return bytes(out)


def read_field(conn, limit):
    length, = struct.unpack("!I", read_exact(conn, 4))
    if not 0 < length <= limit:
        raise ValueError("oracle field length outside bounds")
    return read_exact(conn, length)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--address", default="127.0.0.1")
    args = parser.parse_args()
    with socket.create_server((args.address, args.port)) as listener:
        print("NATIVE_MIT_GSS_READY", flush=True)
        while True:
            conn, _ = listener.accept()
            with conn:
                conn.settimeout(10)
                try:
                    binding, token = read_field(conn, 4096), read_field(conn, 1 << 20)
                    conn.sendall(struct.pack("!4I", *accept(token, binding)))
                except (EOFError, ValueError, OSError):
                    print("NATIVE_MIT_GSS_REQUEST_REJECTED", flush=True)


if __name__ == "__main__":
    main()
