FROM ubuntu:24.04 AS build
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates git build-essential autoconf automake flex bison pkg-config libtirpc-dev rpcsvc-proto
# Upstream unfs3-0.11.0, pinned to the annotated tag's commit.
RUN git init /source && cd /source && git remote add origin https://github.com/unfs3/unfs3.git && git fetch --depth 1 origin ec1660ba33c80d5c67131e163e68834c1a10e243 && git checkout --detach FETCH_HEAD && test "$(git rev-parse HEAD)" = ec1660ba33c80d5c67131e163e68834c1a10e243
WORKDIR /source
RUN ./bootstrap && ./configure --prefix=/usr/local && make -j4

FROM ubuntu:24.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends libtirpc3t64 acl && rm -rf /var/lib/apt/lists/*
RUN groupadd -g 20001 alice && groupadd -g 20002 bob && groupadd -g 20003 shared && useradd -u 20001 -g alice -G shared -M alice && useradd -u 20002 -g bob -M bob
COPY --from=build /source/unfsd /usr/local/sbin/unfsd
COPY --from=build /source/LICENSE /usr/local/share/unfs3-LICENSE
COPY tests/unfs/exports /etc/exports
COPY tests/unfs/start.sh /start.sh
CMD ["sh", "/start.sh"]
