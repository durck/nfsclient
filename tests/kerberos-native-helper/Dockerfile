FROM nfs-viewer-kerberos-122-test AS mit
FROM golang:1.26.9 AS build
COPY --from=mit /opt/mit122 /opt/mit122
COPY internal/krbgss/native-helper/as-helper.c /work/as-helper.c
RUN cc -O2 -Wall -Wextra -Werror -static -I/opt/mit122/include /work/as-helper.c -L/opt/mit122/lib -lkrb5 -lk5crypto -lcom_err -lkrb5support -lresolv -ldl -lpthread -o /work/nfs-viewer-as-helper
FROM nfs-viewer-kerberos-122-test
COPY --from=build /work/nfs-viewer-as-helper /opt/nfs-viewer-as-helper
