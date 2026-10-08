# nfsclient

![nfsclient — Browse remote files. Skip the mount. Windows / Linux.](docs/assets/readme-banner.png)

An interactive NFS client for **Windows and Linux**. Browse remote files,
inspect access and transfer data directly, without mounting a share or installing
an OS NFS client. One standalone Go executable.

[Download](https://github.com/durck/nfsclient/releases/tag/v0.2.0) ·
[User guide](docs/USAGE.md) · [Compatibility](docs/COMPATIBILITY.md)

## What it does

- **NFSv2, v3 and v4.0/4.1/4.2** — automatic version negotiation, TCP, and
  UDP for v2/v3. NFSv2 transfers are limited to files smaller than 2 GiB.
- **Browse and transfer** — preview text or hex, upload, download and resume
  transfers; work with links, permissions and ACLs.
- **AUTH_SYS identities** — set UID, GID and supplementary groups, scan for
  UIDs with read access, or automatically select owner UID/GID on NFSv3.
- **Kerberos** — `krb5`, `krb5i` and `krb5p`, including AD environments with
  matching server SPNs and permission mappings.
- **Discovery and scanning** — inspect exports and visible NFSv4 paths, scan
  hosts or address ranges, and report access and common misconfigurations.
- **Interactive shell** — Tab completion, server name/IP in the prompt,
  transfer progress and file hints for corporate and cloud infrastructure.
  Modification dates from the current year stand out in orange.

File hints use names and known paths; they do not inspect contents for secrets.
See [compatibility](docs/COMPATIBILITY.md) for protocol-specific limits.

## Demo

![Real Windows session: navigation, file hints, transfers, links and permissions over NFSv4.1](docs/assets/demo.gif)

A real Windows session against a local NFSv4.1 export: navigation, completion,
file previews, transfers, links and permissions.
[Watch the 2:13 video](docs/assets/demo.mp4) or
[download the asciinema recording](docs/assets/demo.cast).

## Install

Download a standalone executable from [v0.2.0](https://github.com/durck/nfsclient/releases/tag/v0.2.0):

| Platform | Executable | Bundle with licenses |
| --- | --- | --- |
| Windows x64 | [nfsclient-windows-amd64.exe](https://github.com/durck/nfsclient/releases/download/v0.2.0/nfsclient-windows-amd64.exe) | [ZIP](https://github.com/durck/nfsclient/releases/download/v0.2.0/nfsclient-v0.2.0-windows-amd64.zip) |
| Linux x64 | [nfsclient-linux-amd64](https://github.com/durck/nfsclient/releases/download/v0.2.0/nfsclient-linux-amd64) | [tar.gz](https://github.com/durck/nfsclient/releases/download/v0.2.0/nfsclient-v0.2.0-linux-amd64.tar.gz) |

The release also includes [SHA256SUMS](https://github.com/durck/nfsclient/releases/download/v0.2.0/SHA256SUMS)
and license files. See [build from source](docs/DEVELOPMENT.md#build-from-source)
if you prefer to build yourself.

## Connect and browse

Windows (PowerShell):

```powershell
.\nfsclient-windows-amd64.exe nfs.example.test --export /data
```

Linux:

```sh
chmod +x nfsclient-linux-amd64
./nfsclient-linux-amd64 nfs.example.test --export /data
```

Replace the server and export with your own. Omit `--export` to start with
discovery. Connections use AUTH_SYS over TCP by default; automatic version
selection tries 4.2, 4.1, 4.0, 3, then 2. Use `--nfs-version` to require one.

Inside the interactive shell:

```text
exports
ls
cd documents
cat notes.txt
get notes.txt local-notes.txt
put "local report.txt" "new report.txt"
help
exit
```

Use `use /data` to select another export. Remote paths use `/`; quote names
containing spaces. Tab completes commands and local/remote paths. `legend`
explains colors; `legend PATH` explains a file hint. Disable colors with
`--color=never` or `NO_COLOR`.

For AUTH_SYS, `uid UID [GID [G1,G2]]` changes the identity sent to the server;
`uid-scan PATH [START [END]]` searches for UIDs with read access. This does not
change a Kerberos principal or override server-side export rules/root squash.
For a fixed identity, start with `--uid`, `--gid`, `--groups`,
`--auto-uid=false` and `--auto-escape=false`.

See the [user guide](docs/USAGE.md) and [Kerberos setup](docs/AUTHENTICATION.md).

## Scan for NFS

Examples below assume the executable is named `nfsclient` (`nfsclient.exe` on
Windows) and is on your PATH.

```sh
nfsclient scan 192.0.2.10
nfsclient scan -f targets.txt --output json --no-squash-check --no-escape-check
```

The default scan includes root-squash and root-handle probes; the root-squash
check creates and removes a temporary file. Use both `--no-squash-check` and
`--no-escape-check` for read-only discovery, as in the second example.
Discovery reports partial results and cannot enumerate names hidden by the server.
See [network scanning](docs/USAGE.md#network-scan) for ranges, Kerberos and DNS discovery.

## Help and completion

```sh
nfsclient --help
nfsclient help auth
nfsclient help scan
nfsclient help shell gettree
```

Inside the client, use `help`, `help COMMAND` or `COMMAND --help`.
Interactive Tab completion works immediately. Generate operating-system shell
completion with `nfsclient completion bash`, `zsh`, `fish` or `powershell`;
see [installation instructions](docs/USAGE.md#help-and-completion).

## Documentation and development

- [User guide](docs/USAGE.md) — shell commands, file hints, identities and discovery.
- [Authentication](docs/AUTHENTICATION.md) — Kerberos and connection security.
- [Advanced operations](docs/ADVANCED.md) — transfers, ACLs, locks, recovery and pNFS.
- [Compatibility](docs/COMPATIBILITY.md) — supported profiles and limits.
- [Development](docs/DEVELOPMENT.md) — source builds, self-checks and releases.
- [Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md) · [Changelog](CHANGELOG.md).

## License

[MIT](LICENSE). Adapted GSS/Kerberos components retain their original notices;
release bundles include third-party licenses, also available as separate assets.
