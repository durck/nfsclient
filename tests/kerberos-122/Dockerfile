FROM golang:1.26.8 AS build
ADD --checksum=sha256:221b3e224708c1da2a1a88b6824380593579b2254ae7d914afa14cbd5d343334 https://deb.debian.org/debian/pool/main/m/m4/m4_1.4.19-8_amd64.deb /tmp/m4.deb
RUN dpkg-deb -x /tmp/m4.deb /
ADD --checksum=sha256:ce6eb1f7aad18850e32d223a68f54bcbe756d74f138c8ec5460ad9d220f4d335 https://deb.debian.org/debian/pool/main/b/bison/bison_3.8.2+dfsg-1+b2_amd64.deb /tmp/bison.deb
RUN dpkg-deb -x /tmp/bison.deb / && ln -s bison /usr/bin/yacc
ADD --checksum=sha256:3243ffbc8ea4d4ac22ddc7dd2a1dc54c57874c40648b60ff97009763554eaf13 https://web.mit.edu/kerberos/dist/krb5/1.22/krb5-1.22.2.tar.gz /tmp/krb5.tar.gz
RUN mkdir /tmp/krb5 && tar xzf /tmp/krb5.tar.gz --strip-components=1 -C /tmp/krb5 && cd /tmp/krb5/src && ./configure --prefix=/opt/mit122 --without-ldap --without-libedit --without-system-verto --disable-shared --enable-static --disable-pkinit LDFLAGS=-static CFLAGS=-fcommon > /tmp/configure.log  && make -j4 > /tmp/make.log && make install > /tmp/install.log
FROM nfs-viewer-kerberos-test
COPY --from=build /opt/mit122 /opt/mit122
COPY kerberos/start.sh /start.sh
ENV PATH=/opt/mit122/bin:/opt/mit122/sbin:$PATH
CMD ["sh", "/start.sh"]
