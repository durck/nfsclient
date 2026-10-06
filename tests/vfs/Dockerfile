ARG BASE_IMAGE=nfs-viewer-kerberos-test
FROM ${BASE_IMAGE}
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends nfs-ganesha-vfs acl && rm -rf /var/lib/apt/lists/*
RUN groupadd -g 20003 shared && usermod -a -G shared alice && mv /start.sh /auth-start.sh
COPY tests/vfs/ganesha.conf /etc/ganesha/ganesha.conf
COPY tests/vfs/start.sh /start.sh
CMD ["sh", "/start.sh"]
