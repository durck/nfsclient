FROM nfs-viewer-nfs2-kernel AS module-build
COPY . /repo
RUN apt-get -o APT::Update::Error-Mode=any update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends linux-headers-amd64 linux-source-6.1 build-essential libelf-dev
RUN set -eu; kernel=$(basename /lib/modules/*); mkdir /tmp/ssc-source; tar -xJf /usr/src/linux-source-6.1.tar.xz -C /tmp/ssc-source linux-source-6.1/fs/nfsd linux-source-6.1/fs/internal.h; cp /tmp/ssc-source/linux-source-6.1/fs/internal.h /tmp/internal.h; mv /tmp/ssc-source/linux-source-6.1/fs/nfsd /tmp/nfsd; make -j4 -C /lib/modules/$kernel/build M=/tmp/nfsd CONFIG_NFSD_V4_2_INTER_SSC=y KCFLAGS='-DCONFIG_NFSD_V4_2_INTER_SSC=1 -I/tmp/nfsd' modules; cp /tmp/nfsd/nfsd.ko /lib/modules/$kernel/kernel/fs/nfsd/nfsd.ko; depmod $kernel; printf 'Debian Linux 6.1.176-1, unmodified fs/nfsd sources; CONFIG_NFSD_V4_2_INTER_SSC=y; KCFLAGS=-DCONFIG_NFSD_V4_2_INTER_SSC=1\n' > /opt/nfsd-ssc-build.txt

FROM nfs-viewer-nfs2-kernel
COPY --from=module-build /lib/modules/ /lib/modules/
COPY --from=module-build /opt/nfsd-ssc-build.txt /opt/nfsd-ssc-build.txt
