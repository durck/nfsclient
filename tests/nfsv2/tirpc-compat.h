/* Build-only portability for this IPv4 historical server. No protocol changes. */
#include <rpc/rpc.h>
#define HAVE_XDRPROC_T 1
#undef svc_getcaller
#define svc_getcaller(xprt) ((struct sockaddr_in *)svc_getrpccaller(xprt)->buf)

/* libtirpc expects a caller-supplied bound stream socket to be listening. */
static inline SVCXPRT *fixture_svctcp_create(int sock, unsigned send, unsigned recv)
{
    if (sock != RPC_ANYSOCK && listen(sock, SOMAXCONN) != 0)
        return NULL;
    return svctcp_create(sock, send, recv);
}
#define svctcp_create fixture_svctcp_create
