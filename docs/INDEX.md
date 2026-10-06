# Documentation

[Quick start](../README.md) | [Client implementation plan](PLAN.md) | [Compatibility](COMPATIBILITY.md)

## Guides

| Topic | Guide |
| --- | --- |
| Kerberos identities and credential profiles | [authentication](AUTHENTICATION.md) |
| Transport and RPC security | [transport](TRANSPORT.md) |
| Transfers, publication and resume | [transfers](TRANSFERS.md) |
| Policy-preserving replacement | [replacement](REPLACEMENT.md) |
| Advisory locks and legacy NLM | [locks](LOCKS.md) |
| NFS state, migration and recovery | [state recovery](STATE_RECOVERY.md) |
| NFSv4.2 operations and offload recovery | [offload](OFFLOAD.md) |
| pNFS FILE and Flex layouts | [pnfs files](PNFS_FILES.md) |
| pNFS block storage and crash recovery | [pnfs block](PNFS_BLOCK.md) |
| pNFS OSD reads and secured range writes | [pnfs object](PNFS_OBJECT.md) |
| Development, checks, retained history | [Development](DEVELOPMENT.md) |
| Opt-in servers and native fixtures | [Fixture catalog](../tests/README.md) |

Update the guide that owns the behavior. Runtime test logs, audits and dated
journals belong in ignored artifacts. See [artifact handling](DEVELOPMENT.md#historical-evidence) for local history.
