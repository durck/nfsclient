package cli

import (
	"path"
	"strings"
	"time"

	"nfs-viewer/internal/nfs"
)

const (
	muted    = "38;5;245"
	orange   = "38;5;208"
	magenta  = "38;5;211"
	lavender = "38;5;183"
	linkTone = "38;5;109"
	faint    = "2;37"
	warm     = "38;5;222"
)

// Filename hints are purely presentational. They never inspect file contents or
// assert that a file actually contains credentials.
func fileTone(e nfs.Entry) string {
	if e.Attr.Type == 2 {
		return warm
	}
	if e.Attr.Type == 5 {
		return linkTone
	}
	if e.Attr.Type != 1 {
		return muted
	}
	name := strings.ToLower(e.Name)
	switch name {
	case "readme", "readme.md", "readme.txt", "license", "license.md", "license.txt", "copying", "notice", "changelog", "changelog.md", ".gitignore", ".gitattributes", ".ds_store", "thumbs.db", "desktop.ini", "package-lock.json", "yarn.lock", "go.sum":
		return muted
	}
	// Recognize common backup wrappers without hiding the underlying hint.
	base := name
	for _, suffix := range []string{".bak", ".old", ".backup", "~"} {
		base = strings.TrimSuffix(base, suffix)
	}
	ext := path.Ext(base)
	switch base {
	case ".env", ".netrc", "_netrc", ".pgpass", ".my.cnf", ".npmrc", ".pypirc", ".git-credentials", ".gitconfig", "credentials", "credentials.json", "credentials.xml", "secrets.json", "secrets.yaml", "secrets.yml", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "shadow", "gshadow", "passwd", "smbpasswd", "sam", "system", "security", "ntds.dit", "krb5.keytab", "wp-config.php", "web.config", "unattend.xml", "unattended.xml", "application.yml", "application.yaml", "application.properties", "appsettings.json", "config.php", "settings.py":
		return magenta
	}
	if strings.HasPrefix(base, ".env.") || strings.HasPrefix(base, "appsettings.") && ext == ".json" || strings.HasSuffix(base, ".kdbx") {
		return magenta
	}
	switch ext {
	case ".conf", ".cfg", ".ini", ".config", ".yaml", ".yml", ".toml", ".ovpn", ".rdp", ".pem", ".key", ".pfx", ".p12", ".ppk", ".jks", ".keystore", ".keytab", ".kdb", ".kdbx":
		return magenta
	case ".db", ".sqlite", ".sqlite3", ".sql", ".mdb", ".accdb", ".dump", ".json", ".xml", ".csv", ".xls", ".xlsx", ".doc", ".docx", ".pdf", ".log", ".history":
		return lavender
	}
	if strings.HasSuffix(base, "_history") || strings.HasPrefix(base, ".db.") || base != name {
		return lavender
	}
	switch path.Ext(name) {
	case ".zip", ".7z", ".rar", ".tar", ".gz", ".bz2", ".xz", ".tgz", ".vmdk", ".vhd", ".vhdx":
		return lavender
	case ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".mp3", ".mp4", ".woff", ".woff2", ".ttf", ".o", ".a", ".so", ".dll", ".pyc", ".class":
		return muted
	}
	if e.Attr.Mode&0111 != 0 {
		return green
	}
	return ""
}

func dateTone(modified, now time.Time) string {
	if !modified.IsZero() && modified.Local().Year() == now.Local().Year() {
		return orange
	}
	return muted
}
