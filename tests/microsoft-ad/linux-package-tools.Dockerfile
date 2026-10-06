FROM nfs-viewer-msad-linux-tools
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends dpkg-dev && rm -rf /var/lib/apt/lists/*
