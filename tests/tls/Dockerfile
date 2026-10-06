FROM nfs-viewer-tlshd-build
# Pinned upstream 0.9 has no SunRPC ALPN for TLS. Keep the stock failure;
# this separate NFS-only daemon repairs negotiation, not the client policy.
COPY enable-fixture-alpn.py /enable-fixture-alpn.py
RUN python3 /enable-fixture-alpn.py /ktls && make -C /ktls -j4
