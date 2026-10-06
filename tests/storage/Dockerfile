# Disposable TCG guest; no host kernel mounts or privileged container required.
FROM nfs-viewer-nfs2-kernel-acl2
COPY --from=packages . /repo
RUN printf 'deb [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] file:/repo bookworm main\n' > /etc/apt/sources.list && apt-get -o APT::Update::Error-Mode=any update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends xfsprogs btrfs-progs dosfstools exfatprogs && rm -rf /var/lib/apt/lists/* /repo
COPY guest-init.sh run.sh /fixture/
CMD ["sh", "/fixture/run.sh"]
