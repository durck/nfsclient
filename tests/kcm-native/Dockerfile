FROM nfs-viewer-kerberos-test
# Context is the isolated repository prepared by prepare-repository.py, with
# start.py copied into its root. No credentials are build inputs.
COPY . /repo
RUN printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d && chmod +x /usr/sbin/policy-rc.d && cp /repo/ubuntu.sources /etc/apt/sources.list.d/ubuntu.sources && apt-get -o APT::Update::Error-Mode=any update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends sssd-kcm python3 && cp /repo/start.py /kcm-native-start.py && rm -rf /var/lib/apt/lists/* /repo
ENTRYPOINT ["python3", "/kcm-native-start.py"]
