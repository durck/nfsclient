FROM nfs-viewer-unfs-build AS build
# Independent historical NFSv2 server with upstream Debian portability fixes.
COPY server-source.tar /server-source.tar
RUN mkdir /nfsv2 && tar -xf /server-source.tar -C /nfsv2
WORKDIR /nfsv2
COPY tirpc-compat.h /tirpc-compat.h
RUN CFLAGS='-O2 -fcommon -DTIME_WITH_SYS_TIME -I/usr/include/tirpc' LIBS='-ltirpc' ./BUILD --batch --multi=no --devtab=yes --ugidd=no --nis=no --hosts-access=no --log-mounts=yes && make -j4 CFLAGS='-O2 -fcommon -DTIME_WITH_SYS_TIME -I/usr/include/tirpc -include /tirpc-compat.h' rpc.nfsd rpc.mountd

FROM nfs-viewer-ganesha-test
# Only nfs-user-server is launched; reuse the existing isolated RPC runtime.
COPY --from=build /nfsv2/rpc.nfsd /nfsv2/rpc.mountd /usr/local/sbin/
COPY --from=build /nfsv2/COPYING /usr/local/share/nfs-user-server-COPYING
COPY start.sh /start.sh
CMD ["sh", "/start.sh"]
