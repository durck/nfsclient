FROM nfs-viewer-unfs-build
# Supply authenticated Ubuntu noble debs from the printed dependency plan.
COPY debs /var/cache/apt/archives
RUN DEBIAN_FRONTEND=noninteractive apt-get --no-download -y install libgnutls28-dev libglib2.0-dev libkeyutils-dev libnl-3-dev libnl-genl-3-dev
COPY source.tar /source.tar
RUN mkdir /ktls && tar -xf /source.tar -C /ktls
WORKDIR /ktls
RUN ./autogen.sh && ./configure && make -j4
