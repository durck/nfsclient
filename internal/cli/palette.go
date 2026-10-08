package cli

// Shared terminal palette. File categories describe names/types, while status
// colors describe observed outcomes. Never use color as the only status label.
const (
	cyan     = "38;5;80"    // Server identity and work in progress.
	blue     = "38;5;75"    // Ordinary configuration files.
	green    = "38;5;114"   // Successful outcomes and executable mode bits.
	yellow   = "38;5;214"   // Warnings or incomplete verification.
	red      = "1;38;5;203" // Errors and confirmed broken links.
	muted    = "38;5;245"   // Familiar names and secondary details.
	orange   = "1;38;5;208" // Modification dates in the current local year.
	magenta  = "38;5;211"   // Credential-related filename hints.
	lavender = "38;5;183"   // Data, documents, archives and backups.
	linkTone = "38;5;109"   // Symbolic links, regardless of target status.
	warm     = "38;5;222"   // Directories and paths.
	dim      = "2"
	bold     = "1"
)

func linkNote(state string) cell {
	switch state {
	case "reachable":
		return cell{}
	case "missing":
		return cell{" [missing]", red}
	case "loop":
		return cell{" [link loop]", red}
	case "denied":
		return cell{" [access denied]", yellow}
	case "unchecked":
		return cell{" [unchecked]", muted}
	default:
		return cell{" [unverified]", yellow}
	}
}
