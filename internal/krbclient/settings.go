// Adapted from github.com/jcmturner/gokrb5/v8 v8.4.4 (Apache-2.0).
// Local changes are documented in README.md.
package client

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"nfsclient/internal/resolve"
)

// Settings holds optional client settings.
type Settings struct {
	asAlias                 string
	enterpriseUPN           string
	asStartRealm            string
	asReferralRealms        []string
	paths                   *CAPaths
	networkContext          context.Context
	dns                     resolve.Config
	disablePAFXFast         bool
	assumePreAuthentication bool
	preAuthEType            int32
	logger                  *log.Logger
}

// ProtectedASAlias selects a same-realm request alias while retaining the
// explicit canonical keytab principal for credentials and all later exchanges.
func ProtectedASAlias(alias string) func(*Settings) {
	return func(s *Settings) { s.asAlias = alias }
}

func EnterpriseAS(upn, start string, realms []string) func(*Settings) {
	return func(s *Settings) {
		s.enterpriseUPN = upn
		s.asStartRealm = start
		s.asReferralRealms = append([]string(nil), realms...)
	}
}

// jsonSettings is used when marshaling the Settings details to JSON format.
type jsonSettings struct {
	DisablePAFXFast         bool
	AssumePreAuthentication bool
}

// NewSettings creates a new client settings struct.
func NewSettings(settings ...func(*Settings)) *Settings {
	s := new(Settings)
	for _, set := range settings {
		set(s)
	}
	return s
}

// DisablePAFXFAST used to configure the client to not use PA_FX_FAST.
//
// s := NewSettings(DisablePAFXFAST(true))
func DisablePAFXFAST(b bool) func(*Settings) {
	return func(s *Settings) {
		s.disablePAFXFast = b
	}
}

// DisablePAFXFAST indicates is the client should disable the use of PA_FX_FAST.
func (s *Settings) DisablePAFXFAST() bool {
	return s.disablePAFXFast
}

// AssumePreAuthentication used to configure the client to assume pre-authentication is required.
//
// s := NewSettings(AssumePreAuthentication(true))
func AssumePreAuthentication(b bool) func(*Settings) {
	return func(s *Settings) {
		s.assumePreAuthentication = b
	}
}

// AssumePreAuthentication indicates if the client should proactively assume using pre-authentication.
func (s *Settings) AssumePreAuthentication() bool {
	return s.assumePreAuthentication
}

// Logger used to configure client with a logger.
//
// s := NewSettings(kt, Logger(l))
func Logger(l *log.Logger) func(*Settings) {
	return func(s *Settings) {
		s.logger = l
	}
}

// Logger returns the client logger instance.
func (s *Settings) Logger() *log.Logger {
	return s.logger
}

// Log will write to the service's logger if it is configured.
func (cl *Client) Log(format string, v ...interface{}) {
	if cl.settings.Logger() != nil {
		cl.settings.Logger().Output(2, fmt.Sprintf(format, v...))
	}
}

// JSON returns a JSON representation of the settings.
func (s *Settings) JSON() (string, error) {
	js := jsonSettings{
		DisablePAFXFast:         s.disablePAFXFast,
		AssumePreAuthentication: s.assumePreAuthentication,
	}
	b, err := json.MarshalIndent(js, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil

}

// NetworkContext bounds KDC discovery, connection and I/O for this client.
func NetworkContext(ctx context.Context) func(*Settings) {
	return func(s *Settings) { s.networkContext = ctx }
}

// DNS selects DNS transport/server for KDC SRV and address lookups.
func DNS(cfg resolve.Config) func(*Settings) {
	return func(s *Settings) { s.dns = cfg }
}
