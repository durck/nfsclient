#!/bin/sh
set -eu
export LC_ALL=C DEBIAN_FRONTEND=noninteractive
profile=${1:-nfs-ad}
case "$profile" in
  nfs-ad) targets='nfs-kernel-server sssd-ad sssd-tools adcli krb5-user' ;;
  posix-acl) targets='acl' ;;
  *) echo 'Unknown package profile' >&2; exit 1 ;;
esac
test "$(dpkg --print-architecture)" = amd64
test ! -e /bundle/verified.json
mkdir -p /bundle/debs/partial /bundle/provenance
cat > /etc/apt/sources.list.d/ubuntu.sources <<'EOF'
Types: deb
URIs: https://archive.ubuntu.com/ubuntu/
Suites: noble noble-updates
Components: main universe
Architectures: amd64
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg

Types: deb
URIs: https://security.ubuntu.com/ubuntu/
Suites: noble-security
Components: main universe
Architectures: amd64
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
EOF
cp /etc/apt/sources.list.d/ubuntu.sources /bundle/provenance/ubuntu.sources
apt-get -o APT::Update::Error-Mode=any update
# An empty installed-state file includes the complete dependency closure, not
# merely packages missing in the Docker tool. Installation later resolves only
# the requested packages against the actual guest's installed state.
: > /tmp/empty-status
apt-get -y --download-only --no-install-recommends \
  -o Dir::State::status=/tmp/empty-status \
  -o Dir::Cache::archives=/bundle/debs \
  install $targets
python3 /scripts/verify-linux-bundle.py prepare /bundle --profile "$profile"
cd /bundle
dpkg-scanpackages debs /dev/null > Packages
python3 /scripts/verify-linux-bundle.py verify /bundle --profile "$profile"
