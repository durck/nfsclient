FROM ubuntu:24.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends nfs-ganesha nfs-ganesha-mem rpcbind && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /run/ganesha /var/lib/nfs/ganesha
COPY ganesha.conf /etc/ganesha/ganesha.conf
CMD ["sh", "-c", "rpcbind; exec ganesha.nfsd -F -L /dev/stdout -f /etc/ganesha/ganesha.conf"]
