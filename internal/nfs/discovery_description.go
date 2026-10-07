package nfs

import "fmt"

// ListingDescription describes observed READDIR results, never infers an
// empty directory from access permissions or an absence of discovered exports.
func (e DiscoveredExport) ListingDescription() string {
	if e.ListedEntries == nil || e.ListingComplete == nil {
		return "not enumerated; contents unknown"
	}
	if !*e.ListingComplete {
		return fmt.Sprintf("incomplete; %d entries observed, contents may remain", *e.ListedEntries)
	}
	if *e.ListedEntries == 0 {
		return "empty (READDIR reached end of directory)"
	}
	return fmt.Sprintf("%d entries observed (READDIR reached end of directory)", *e.ListedEntries)
}

// DiscoveryTraversalDescription expands stable machine statuses for people.
func DiscoveryTraversalDescription(status string) string {
	switch status {
	case "listed":
		return "directory enumeration completed"
	case "depth_limit":
		return "not enumerated: discovery depth limit reached"
	case "entry_limit":
		return "stopped: discovery entry budget exhausted"
	case "timeout":
		return "stopped: discovery time budget expired"
	case "cancelled":
		return "stopped: discovery cancelled"
	case "denied":
		return "server denied this operation under the current identity"
	case "wrong_security":
		return "server requires a different security flavor; identity was not changed"
	case "referral":
		return "server referred this path elsewhere; referral was not followed"
	case "not_found":
		return "server reported this path absent; other paths were not ruled out"
	case "already_visited":
		return "not enumerated again: directory identity already visited"
	case "symlink_not_followed":
		return "not followed: discovery does not follow symbolic links"
	case "":
		return ""
	default:
		return status
	}
}
