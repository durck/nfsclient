FROM nfs-viewer-ganesha-test
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends samba-ad-dc samba-ad-provision samba-dsdb-modules samba-vfs-modules winbind krb5-user && rm -rf /var/lib/apt/lists/*
RUN groupadd -g 20001 alice && useradd -u 20001 -g 20001 -M -s /usr/sbin/nologin alice && groupadd -g 20002 bob && useradd -u 20002 -g 20002 -M -s /usr/sbin/nologin bob
COPY tests/samba-ad/provision.py /provision.py
COPY tests/samba-ad/start.sh /start.sh
COPY tests/samba-ad/krb5.conf /etc/krb5.conf
COPY tests/samba-ad/idmapd.conf /etc/idmapd.conf
COPY tests/kerberos/ganesha.conf /etc/ganesha/ganesha.conf
CMD ["sh", "/start.sh"]
