# Build with the authenticated offline Debian repository as the context.
FROM debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251
COPY . /repo
RUN printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d && chmod +x /usr/sbin/policy-rc.d && printf 'deb [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] file:/repo bookworm main\n' > /etc/apt/sources.list && mv /etc/apt/sources.list.d/debian.sources /etc/apt/debian.sources.disabled && apt-get -o APT::Update::Error-Mode=any update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends linux-image-amd64 qemu-system-x86 nfs-kernel-server rpcbind busybox-static cpio acl iproute2 e2fsprogs && rm -rf /var/lib/apt/lists/* /repo
