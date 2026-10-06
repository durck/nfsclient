package client

import (
	"bufio"
	"fmt"
	"strings"
	"time"

	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// CAPaths is an immutable, explicitly configured client trust-path policy.
// A nil policy retains legacy KDC-directed routing. An empty policy allows
// only the home realm. Routes list intermediates in their configured order.
type CAPaths struct {
	routes map[string]map[string][]string
}

// ParseCAPaths reads a bounded subset of MIT's profile syntax. Never ignore
// includes/modules: they could contain a policy this parser would not enforce.
func ParseCAPaths(text string) (*CAPaths, error) {
	if len(text) > 1<<20 {
		return nil, fmt.Errorf("kerberos configuration exceeds 1 MiB")
	}
	var policy *CAPaths
	section, home := "", ""
	count, lineNum := 0, 0
	scanner := bufio.NewScanner(strings.NewReader(text))
	fail := func(reason string) (*CAPaths, error) {
		return nil, fmt.Errorf("kerberos configuration line %d: %s", lineNum, reason)
	}
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		first := strings.Fields(line)[0]
		if first == "include" || first == "includedir" || first == "module" {
			return fail("include/includedir/module profiles are unsupported; use one explicit configuration file")
		}
		if strings.HasPrefix(line, "[") {
			if home != "" || !strings.HasSuffix(line, "]") || strings.Count(line, "[") != 1 || strings.Count(line, "]") != 1 {
				return fail("invalid section header, final marker or unclosed capaths realm block")
			}
			section = strings.TrimSpace(line[1 : len(line)-1])
			if strings.EqualFold(section, "capaths") {
				if section != "capaths" || policy != nil {
					return fail("use exactly one lowercase [capaths] section")
				}
				policy = &CAPaths{routes: make(map[string]map[string][]string)}
			}
			continue
		}
		if section == "" {
			return fail("expected a section header")
		}
		if section != "capaths" {
			continue
		}
		if line == "}" {
			if home == "" {
				return fail("unexpected capaths closing brace")
			}
			home = ""
			continue
		}
		name, value, ok := strings.Cut(line, "=")
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
		if !ok || !simpleRealm(name) {
			return fail("invalid capaths realm/relation; use case-sensitive ASCII realm names")
		}
		if home == "" {
			if value != "{" || policy.routes[name] != nil || len(policy.routes) >= 64 {
				return fail("capaths requires unique realm blocks (maximum 64), with an opening brace on the relation line")
			}
			home = name
			policy.routes[home] = make(map[string][]string)
			continue
		}
		parts := strings.Fields(value)
		if len(parts) == 0 || len(parts) > 5 || name == home {
			return fail("capaths requires a foreign destination and at most five intermediates, or '.' for direct trust")
		}
		previous, exists := policy.routes[home][name]
		if len(parts) == 1 && parts[0] == "." {
			if exists {
				return fail("duplicate or mixed direct capaths route")
			}
			policy.routes[home][name] = []string{}
		} else {
			if exists && len(previous) == 0 {
				return fail("cannot extend a direct capaths route")
			}
			seen := map[string]bool{home: true, name: true}
			for _, hop := range previous {
				seen[hop] = true
			}
			for _, hop := range parts {
				if !simpleRealm(hop) || seen[hop] {
					return fail("invalid or repeated capaths intermediate (cycle or endpoint in path)")
				}
				seen[hop] = true
			}
			if len(previous)+len(parts) > 5 {
				return fail("capaths exceeds five intermediate realms")
			}
			policy.routes[home][name] = append(previous, parts...)
		}
		if !exists {
			count++
			if count > 256 {
				return fail("capaths exceeds 256 routes")
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("kerberos configuration scan: %w", err)
	}
	if home != "" {
		return fail("unclosed capaths realm block")
	}
	return policy, nil
}

func simpleRealm(s string) bool {
	if s == "" || s == "." || len(s) > 255 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// TrustPaths sets an immutable policy created by ParseCAPaths.
func TrustPaths(policy *CAPaths) func(*Settings) {
	return func(s *Settings) { s.paths = policy }
}

func (p *CAPaths) route(home, target string) ([]string, error) {
	if home == target {
		return []string{home}, nil
	}
	via, ok := p.routes[home][target]
	if !ok {
		return nil, fmt.Errorf("capaths policy: no permitted route from %s to %s", home, target)
	}
	return append(append([]string{home}, via...), target), nil
}

// Always acquire intermediates along this route rather than reusing a TGT
// acquired along a different path for another service. Only a valid service
// ticket from this immutable client policy and the home TGT can be reused.
func (cl *Client) serviceTicketViaPath(spn types.PrincipalName, realm string) (messages.Ticket, types.EncryptionKey, error) {
	var empty messages.Ticket
	var noKey types.EncryptionKey
	route, err := cl.settings.paths.route(cl.Credentials.Realm(), realm)
	if err != nil {
		return empty, noKey, err
	}
	if e, ok := cl.cache.getEntry(spn.PrincipalNameString()); ok && e.Ticket.Realm == realm && time.Now().After(e.StartTime) && time.Now().Before(e.EndTime) {
		return e.Ticket, e.SessionKey, nil
	}
	tgt, key, err := cl.sessionTGT(route[0])
	if err != nil {
		return empty, noKey, err
	}
	for i := 1; i < len(route); i++ {
		next := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/"+route[i])
		_, rep, err := cl.TGSREQGenerateAndExchange(next, route[i-1], tgt, key, false)
		if err != nil {
			return empty, noKey, fmt.Errorf("capaths hop %s -> %s: %w", route[i-1], route[i], err)
		}
		tgt, key = rep.Ticket, rep.DecryptedEncPart.Key
	}
	_, rep, err := cl.TGSREQGenerateAndExchange(spn, realm, tgt, key, false)
	if err != nil {
		return empty, noKey, err
	}
	return rep.Ticket, rep.DecryptedEncPart.Key, nil
}
