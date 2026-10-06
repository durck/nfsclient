FROM nfs-viewer-vfs-acl-build AS build
WORKDIR /udp-source
# This base has deb-src and the build dependencies. apt authenticates metadata;
# the exact original tarball digest is pinned independently of the patch script.
RUN apt-get update && apt-get source ntirpc=4.3-3.1build2 && echo 'f139a6972de50c1bd7ac18abfc966a996820a43855fccfe18611c34326a7c6b9  ntirpc_4.3.orig.tar.gz' | sha256sum -c -
COPY xdr-memory-test.c repair.py /checks/
RUN cc -Wall -Wextra -I/usr/include/ntirpc /checks/xdr-memory-test.c -lntirpc -o /checks/baseline && if /checks/baseline; then echo 'Expected packaged ntirpc regression was not reproduced'; exit 1; fi
RUN python3 /checks/repair.py /udp-source/ntirpc-4.3/src/xdr_mem.c
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends libnsl-dev
RUN cmake -S /udp-source/ntirpc-4.3 -B /udp-build -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_INSTALL_PREFIX=/opt/ntirpc-udp && cmake --build /udp-build -j4 && cmake --install /udp-build
RUN cc -Wall -Wextra -I/opt/ntirpc-udp/include/ntirpc /checks/xdr-memory-test.c -L/opt/ntirpc-udp/lib -Wl,-rpath,/opt/ntirpc-udp/lib -lntirpc -o /checks/repaired && /checks/repaired
FROM nfs-viewer-kerberos-test
COPY --from=build /opt/ntirpc-udp /opt/ntirpc-udp
ENV LD_LIBRARY_PATH=/opt/ntirpc-udp/lib
LABEL nfs-viewer.fixture="ntirpc-4.3-udp-xdr-repair"
