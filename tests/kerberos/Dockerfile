FROM nfs-viewer-ganesha-test
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends krb5-kdc krb5-admin-server krb5-user && rm -rf /var/lib/apt/lists/*
RUN groupadd -g 20001 alice && useradd -u 20001 -g 20001 -M -s /usr/sbin/nologin alice && groupadd -g 20002 bob && useradd -u 20002 -g 20002 -M -s /usr/sbin/nologin bob
COPY krb5.conf /etc/krb5.conf
COPY idmapd.conf /etc/idmapd.conf
COPY ganesha.conf /etc/ganesha/ganesha.conf
COPY start.sh /start.sh
COPY cross-realm.sh /cross-realm.sh
COPY cross.conf /cross.conf
COPY multi-hop.sh /multi-hop.sh
COPY multi-hop.conf /multi-hop.conf
CMD ["sh", "/start.sh"]
