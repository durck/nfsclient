package nfs

import "errors"

// ErrLegacyReplacementUnsupported means base NFSv2/v3 cannot expose enough
// access-policy metadata for this client's upload-replacement contract.
var ErrLegacyReplacementUnsupported = errors.New("NFSv2/v3 ACL-preserving replacement refused: ACL metadata is unavailable; upload to a new name or use NFSv4")
