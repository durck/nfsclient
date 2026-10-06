package gssapi

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/go-logr/logr"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/spf13/afero"
)

const (
	krb5FilePrefix   = "FILE:"
	krb5Config       = "KRB5_CONFIG"
	krb5CCName       = "KRB5CCNAME"
	krb5KTName       = "KRB5_KTNAME"
	krb5ClientKTName = "KRB5_CLIENT_KTNAME"
)

//nolint:gochecknoglobals
var fs = afero.NewOsFs()

func findFile(logger logr.Logger, env string, try []string) (string, error) {
	logger.Info("looking for file", "env", env, "paths", try)

	path, ok := os.LookupEnv(env)
	if ok {
		path = strings.TrimPrefix(path, krb5FilePrefix)

		if _, err := fs.Stat(path); err != nil {
			return "", fmt.Errorf("%s: %w", env, err)
		}

		return path, nil
	}

	errs := fmt.Errorf("%s: not found", env)

	for _, t := range try {
		if _, err := fs.Stat(t); err != nil {
			errs = errors.Join(errs, err)

			if os.IsNotExist(err) {
				continue
			}

			return "", errs
		}

		return t, nil
	}

	return "", errs
}

func loadCCache(logger logr.Logger) (*credentials.CCache, error) {
	path, err := findFile(logger, krb5CCName, []string{fmt.Sprintf("/tmp/krb5cc_%d", os.Getuid())})
	if err != nil {
		return nil, err
	}

	return credentials.LoadCCache(path)
}

func loadKeytab(logger logr.Logger) (*keytab.Keytab, error) {
	path, err := findFile(logger, krb5KTName, []string{"/etc/krb5.keytab"})
	if err != nil {
		return nil, err
	}

	return readKeytab(path)
}

func loadClientKeytab(logger logr.Logger) (*keytab.Keytab, error) {
	path, err := findFile(logger,
		krb5ClientKTName,
		[]string{fmt.Sprintf("/var/kerberos/krb5/user/%d/client.keytab", os.Geteuid())})
	if err != nil {
		return nil, err
	}

	return readKeytab(path)
}

// Upstream parser errors can contain the complete input, including long-term
// keys. Only filesystem errors are safe to preserve across this boundary.
func readKeytab(path string) (*keytab.Keytab, error) {
	kt, err := keytab.Load(path)
	if err == nil {
		return kt, nil
	}
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		return nil, pathErr
	}
	return nil, errors.New("invalid keytab encoding")
}
