package cli

import (
	"path"
	"strings"
	"time"

	"nfsclient/internal/nfs"
)

// Filename hints are purely presentational. They never inspect file contents or
// assert that a file actually contains credentials.
func fileTone(e nfs.Entry, parents ...string) string {
	parent := ""
	if len(parents) > 0 {
		parent = parents[0]
	}
	return classifyFile(e, parent).tone
}

type fileHint struct{ tone, reason string }

func classifyFile(e nfs.Entry, parent string) fileHint {
	name := strings.ToLower(e.Name)
	if e.Attr.Type == 2 {
		// Exact basename hints, not a claim that the directory is unmodified
		// or uninteresting. Do not propagate this style to its children.
		switch name {
		case "windows", "programdata", "program data", "program files", "program files (x86)", "system volume information", "$recycle.bin", "recycler", "recycled", "recovery", "documents and settings", "users", "appdata", "perflogs", "boot", "config.msi", "msocache", "$winreagent", "$windows.~bt", "$windows.~ws", "windows.old", "lost+found", "__macosx", ".spotlight-v100", ".trashes", ".fseventsd", "node_modules", "__pycache__":
			return fileHint{muted, "Familiar system or generated directory name"}
		}
		switch name {
		case ".ssh", ".gnupg", ".aws", ".azure", ".kube", ".docker", ".pki", "secrets":
			return fileHint{magenta, "Directory name associated with authentication or security configuration"}
		case "sysvol", "netlogon", ".git", ".svn", ".jenkins", "jenkins_home":
			return fileHint{blue, "Directory name associated with policy, deployment or source configuration"}
		case "backup", "backups", "dumps", "windowsimagebackup":
			return fileHint{lavender, "Backup or dump directory name"}
		}
		full := strings.ToLower(path.Join(parent, name))
		for _, suffix := range []string{"microsoft/credentials", "microsoft/vault", "microsoft/protect"} {
			if full == suffix || strings.HasSuffix(full, "/"+suffix) {
				return fileHint{magenta, "Known Windows credential/protection directory path: " + suffix}
			}
		}
		return fileHint{warm, "Directory"}
	}
	if e.Attr.Type == 5 {
		return fileHint{linkTone, "Symbolic link; target status is displayed separately"}
	}
	if e.Attr.Type != 1 {
		return fileHint{muted, "Special filesystem object"}
	}
	switch name {
	case "readme", "readme.md", "readme.txt", "license", "license.md", "license.txt", "copying", "notice", "changelog", "changelog.md", ".gitignore", ".gitattributes", ".ds_store", "thumbs.db", "desktop.ini", "package-lock.json", "yarn.lock", "go.sum", "pagefile.sys", "swapfile.sys", "hiberfil.sys", "dumpstack.log.tmp":
		return fileHint{muted, "Familiar system or boilerplate filename"}
	}
	base := unwrapFilename(name)
	hint := classifyRegular(base, parent)
	if base != name {
		if hint.tone == "" || hint.tone == muted {
			hint = fileHint{lavender, "Backup, archive or saved copy"}
		} else {
			hint.reason += "; backup/archive name retains the underlying hint"
		}
	}
	if hint.tone == "" && e.Attr.Mode&0111 != 0 {
		return fileHint{green, "Executable mode bits"}
	}
	return hint
}

// Strip complete suffix components repeatedly, including stacked backups.
// Do not treat a partial keyword (e.g. old-report.txt) as a backup marker.
func unwrapFilename(name string) string {
	for {
		previous := name
		for _, suffix := range []string{".bak", ".old", ".backup", ".orig", ".save", "~", ".zip", ".7z", ".rar", ".tar", ".gz", ".bz2", ".xz", ".tgz", ".zst"} {
			if len(name) > len(suffix) && strings.HasSuffix(name, suffix) {
				name = strings.TrimSuffix(name, suffix)
				break
			}
		}
		if name == previous {
			return name
		}
	}
}

func classifyRegular(base, parent string) fileHint {
	for _, suffix := range []string{".example", ".sample", ".template", ".dist", ".default"} {
		if strings.HasSuffix(base, suffix) {
			return fileHint{blue, "Example or template filename; contents are not verified"}
		}
	}
	// Paths are slash-separated. Remote backslashes remain literal filename
	// characters; the local caller converts native separators with filepath.ToSlash.
	full := strings.ToLower(path.Join(parent, base))
	for _, suffix := range []string{
		".docker/config.json", ".kube/config", ".aws/credentials",
		".azure/msal_token_cache.json", ".azure/msal_token_cache.bin", ".azure/accesstokens.json",
		".m2/settings.xml", ".gradle/gradle.properties", ".config/rclone/rclone.conf",
		"kubernetes/admin.conf", "kubernetes/super-admin.conf",
		"preferences/groups/groups.xml", "preferences/services/services.xml",
		"preferences/scheduledtasks/scheduledtasks.xml", "preferences/datasources/datasources.xml",
		"preferences/drives/drives.xml",
	} {
		if full == suffix || strings.HasSuffix(full, "/"+suffix) {
			return fileHint{magenta, "Known authentication or credential-capable configuration path: " + suffix}
		}
	}
	for _, suffix := range []string{".ssh/config", ".git/config", ".aws/config"} {
		if full == suffix || strings.HasSuffix(full, "/"+suffix) {
			return fileHint{blue, "Known configuration path: " + suffix}
		}
	}
	ext := path.Ext(base)
	switch base {
	case ".env", ".netrc", "_netrc", ".pgpass", "pgpass.conf", ".my.cnf", ".mylogin.cnf", ".npmrc", ".pypirc", ".git-credentials", "credentials", "credentials.json", "credentials.xml", "secrets.json", "secrets.yaml", "secrets.yml", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_ecdsa_sk", "id_ed25519_sk", "shadow", "gshadow", "smbpasswd", "sam", "system", "security", "ntds.dit", "krb5.keytab", "wp-config.php", "unattend.xml", "unattended.xml", "autounattend.xml",
		"secrets.tdb", "secrets.ldb", "sam.ldb", "passdb.tdb", "cwallet.sso", "ewallet.p12",
		"hudson.util.secret", "master.key", "secret.key", "application_default_credentials.json",
		"winscp.ini", "sitemanager.xml", "recentservers.xml", "rclone.conf", "sssd.conf", "kubeconfig", ".vault-token", ".vault_pass", ".vault-password",
		"passwords.txt", "passwords.csv", "passwords.xlsx", "пароли.txt", "пароли.xlsx":
		return fileHint{magenta, "Known credential, key, identity-store or connection-profile filename"}
	case ".gitconfig", "web.config", "application.yml", "application.yaml", "application.properties", "appsettings.json", "config.php", "settings.py":
		return fileHint{blue, "Application configuration filename"}
	case "passwd", "authorized_keys", "authorized_keys2", "known_hosts", "ssh_config", "sshd_config", "sudoers", "exports", "fstab", "hosts", "resolv.conf",
		"tnsnames.ora", "sqlnet.ora", "listener.ora", "odbc.ini", "odbcinst.ini", "krb5.conf", "smb.conf",
		"applicationhost.config", "machine.config", "tomcat-users.xml", "context.xml", "server.xml",
		"bootstrap.ini", "customsettings.ini", "sysprep.inf", "registry.pol", "gpt.ini",
		"jenkinsfile", "dockerfile", "vagrantfile", "ansible.cfg", "inventory", "running-config", "startup-config":
		return fileHint{blue, "Service, policy, network or deployment configuration filename"}
	case "consolehost_history.txt", "fish_history", "ntuser.dat", "usrclass.dat":
		return fileHint{lavender, "Command history or user registry data filename"}
	}
	if strings.HasPrefix(base, ".env.") {
		return fileHint{magenta, "Environment configuration filename; may contain credentials"}
	}
	if strings.HasPrefix(base, "appsettings.") && ext == ".json" {
		return fileHint{blue, "Application configuration filename"}
	}
	switch ext {
	case ".conf", ".cfg", ".ini", ".config", ".yaml", ".yml", ".toml", ".properties", ".ovpn", ".rdp", ".ora", ".tf", ".tfvars", ".service", ".ps1", ".bat", ".cmd", ".vbs":
		return fileHint{blue, "Configuration, deployment or administration-script extension"}
	case ".pem", ".key", ".pfx", ".p12", ".ppk", ".jks", ".keystore", ".keytab", ".kdb", ".kdbx", ".kubeconfig", ".tfstate", ".rdg", ".udl":
		return fileHint{magenta, "Key/container, connection-profile or infrastructure-state extension; contents unverified"}
	case ".db", ".sqlite", ".sqlite3", ".sql", ".mdb", ".accdb", ".dump", ".json", ".xml", ".csv", ".xls", ".xlsx", ".doc", ".docx", ".pdf", ".log", ".history",
		".pst", ".ost", ".mbox", ".eml", ".msg", ".edb", ".mdf", ".ndf", ".ldf", ".bkp", ".dmp", ".reg", ".evtx", ".pcap", ".pcapng", ".1cd", ".dt", ".cf":
		return fileHint{lavender, "Database, mail, document, log, capture or dump extension"}
	}
	if strings.HasSuffix(base, "_history") || strings.HasSuffix(base, "_history.txt") || strings.HasPrefix(base, ".db.") {
		return fileHint{lavender, "History or database filename pattern"}
	}
	switch ext {
	case ".vmdk", ".vhd", ".vhdx", ".qcow2", ".vdi", ".vma", ".wim", ".vib", ".vbk", ".vrb":
		return fileHint{lavender, "Disk image or backup extension"}
	case ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".mp3", ".mp4", ".woff", ".woff2", ".ttf", ".o", ".a", ".so", ".dll", ".pyc", ".class":
		return fileHint{muted, "Common media or compiled-file extension"}
	}
	return fileHint{"", "No specific filename or path hint"}
}

func dateTone(modified, now time.Time) string {
	if !modified.IsZero() && modified.Local().Year() == now.Local().Year() {
		return orange
	}
	return muted
}
