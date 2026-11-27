package route

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
)

const (
	ipAllowTag = "allow:ip"
	ipDenyTag  = "deny:ip"
)

// AccessDeniedHTTP checks rules on the target for HTTP proxy routes.
func (t *Target) AccessDeniedHTTP(r *http.Request) bool {
	denied, ip := t.checkAccessHTTP(r)
	if denied {
		log.Printf("[INFO] route rules denied access from %s to %s",
			ip.String(), t.URL.String())
		return true
	}

	// The request is allowed. Keep emitting the diagnostics the previous
	// implementation logged for unparseable source addresses.
	if len(t.accessRules) == 0 {
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		log.Printf("[ERROR] failed to get host from remote header %s: %s",
			r.RemoteAddr, err.Error())
		return false
	}
	if net.ParseIP(host) == nil {
		log.Printf("[WARN] failed to parse remote address %s", host)
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		for xip := range strings.SplitSeq(xff, ",") {
			xip = strings.TrimSpace(xip)
			if xip == host {
				continue
			}
			if net.ParseIP(xip) == nil {
				log.Printf("[WARN] failed to parse xff address %s", xip)
			}
		}
	}
	return false
}

// checkAccessHTTP is the single, log-free copy of the HTTP access decision.
// It reports whether the target's access rules deny the request and, if so,
// which source IP triggered the denial. The decision is shared by
// AccessDeniedHTTP - which adds the logging - and by the access-aware
// target selection in Route.pickTarget, which must not emit denial logs
// for requests that are eventually served by another target.
//
// The semantics are exactly those AccessDeniedHTTP always had: the remote
// address and every element of X-Forwarded-For must pass, elements equal
// to the remote host are skipped, unparseable elements are skipped and an
// unparseable RemoteAddr (e.g. missing port, or none at all as with gRPC)
// allows the request.
func (t *Target) checkAccessHTTP(r *http.Request) (denied bool, ip net.IP) {
	// No rules ... skip checks
	if len(t.accessRules) == 0 {
		return false, nil
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// unparseable remote address: allow
		return false, nil
	}

	// check remote source and return if denied
	if ip = net.ParseIP(host); ip != nil && t.checkIPRules(ip) {
		return true, ip
	}

	// check xff source if present
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Trusting XFF headers sent from clients is dangerous and generally
		// bad practice.  Therefore, we cannot assume which if any of the elements
		// is the actual client address.  To try and avoid the chance of spoofed
		// headers and/or loose upstream proxies we validate all elements in the header.
		// Specifically AWS does not strip XFF from anonymous internet sources:
		// https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/x-forwarded-headers.html#x-forwarded-for
		// See lengthy github discussion for more background: https://github.com/fabiolb/fabio/pull/449
		for xip := range strings.SplitSeq(xff, ",") {
			xip = strings.TrimSpace(xip)
			if xip == host {
				continue
			}
			if ip = net.ParseIP(xip); ip == nil {
				continue
			}
			if t.checkIPRules(ip) {
				return true, ip
			}
		}
	}

	// default allow
	return false, nil
}

// AccessDeniedTCP checks rules on the target for TCP proxy routes.
func (t *Target) AccessDeniedTCP(c net.Conn) bool {
	// Calling RemoteAddr on a proxy-protocol enabled connection may block.
	// Therefore we explicitly check and bail out early if there are no
	// rules defined for the target.
	// See https://github.com/fabiolb/fabio/issues/524 for background.
	if len(t.accessRules) == 0 {
		return false
	}
	// get remote address and validate assertion
	addr, ok := c.RemoteAddr().(*net.TCPAddr)
	if !ok {
		log.Printf("[ERROR] failed to assert remote connection address for %s", t.Service)
		return false
	}
	// check remote connection address
	if t.denyByIP(addr.IP) {
		return true
	}
	// default allow
	return false
}

func (t *Target) denyByIP(ip net.IP) bool {
	denied := t.checkIPRules(ip)
	if denied {
		log.Printf("[INFO] route rules denied access from %s to %s",
			ip.String(), t.URL.String())
	}
	return denied
}

// checkIPRules reports whether ip is denied by the target's access rules.
// It is the log-free core of denyByIP so that the decision can also be
// used by checkAccessHTTP where logging is not wanted.
func (t *Target) checkIPRules(ip net.IP) bool {
	if ip == nil || len(t.accessRules) == 0 {
		return false
	}
	// check allow (whitelist) first if it exists
	if blocks, ok := t.accessRules[ipAllowTag]; ok {
		for _, x := range blocks {
			if block, ok := x.(*net.IPNet); !ok {
				continue
			} else if block.Contains(ip) {
				// specific allow matched - allow this request
				return false
			}
		}
		// we checked all the blocks - deny this request
		return true
	}

	// still going - check deny (blacklist) if it exists
	if blocks, ok := t.accessRules[ipDenyTag]; ok {
		for _, x := range blocks {
			if block, ok := x.(*net.IPNet); !ok {
				continue
			} else if block.Contains(ip) {
				// specific deny matched - deny this request
				return true
			}
		}
	}

	// default - do not deny
	return false
}

// ProcessAccessRules processes access rules from options specified on the target route
func (t *Target) ProcessAccessRules() error {
	if t.Opts["allow"] != "" && t.Opts["deny"] != "" {
		return errors.New("specifying allow and deny on the same route is not supported")
	}

	for _, allowDeny := range []string{"allow", "deny"} {
		if t.Opts[allowDeny] != "" {
			if err := t.parseAccessRule(allowDeny); err != nil {
				return err
			}
		}
	}
	return nil
}

func (t *Target) parseAccessRule(allowDeny string) error {
	var accessTag string
	var temps []string
	var value string
	var ip net.IP

	// init rules if needed
	if t.accessRules == nil {
		t.accessRules = make(map[string][]any)
	}

	// loop over rule elements
	for c := range strings.SplitSeq(t.Opts[allowDeny], ",") {
		if temps = strings.SplitN(c, ":", 2); len(temps) != 2 {
			return fmt.Errorf("invalid access item, expected <type>:<data>, got %s", temps)
		}

		// form access type tag
		accessTag = allowDeny + ":" + strings.ToLower(strings.TrimSpace(temps[0]))

		// switch on formed access tag - currently only ip types are implemented
		switch accessTag {
		case ipAllowTag, ipDenyTag:
			if value = strings.TrimSpace(temps[1]); !strings.Contains(value, "/") {
				if ip = net.ParseIP(value); ip == nil {
					return fmt.Errorf("failed to parse IP %s", value)
				}
				if ip.To4() != nil {
					value = ip.String() + "/32"
				} else {
					value = ip.String() + "/128"
				}
			}
			_, net, err := net.ParseCIDR(value)
			if err != nil {
				return fmt.Errorf("failed to parse CIDR %s with error: %s",
					c, err.Error())
			}
			// add element to rule map
			t.accessRules[accessTag] = append(t.accessRules[accessTag], net)
		default:
			return fmt.Errorf("unknown access item type: %s", temps[0])
		}
	}

	return nil
}
