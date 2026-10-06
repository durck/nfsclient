FROM nfs-viewer-unfs-test
# Supply --build-context packages=. for online builds, or a signed Ubuntu
# repository prepared by tests/kcm-native/prepare-repository.py for offline use.
ARG OFFLINE_REPOSITORY=0
RUN --mount=type=bind,from=packages,source=.,target=/repo \
    if [ "$OFFLINE_REPOSITORY" = 1 ]; then cp /repo/ubuntu.sources /etc/apt/sources.list.d/ubuntu.sources; fi; \
    apt-get -o APT::Update::Error-Mode=any update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends iproute2 iptables python3 && rm -rf /var/lib/apt/lists/*
COPY tests/network/control.py /network-control.py
CMD ["python3", "/network-control.py"]
