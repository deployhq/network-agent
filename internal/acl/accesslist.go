// Package acl implements the IP/CIDR access list used to restrict which destination
// hosts the agent may connect to.
//
// The access file format (agent.access) matches the Ruby implementation:
//   - Lines are split by newline
//   - Lines are whitespace-trimmed
//   - Empty lines and lines starting with '#' are ignored
//   - Only the first whitespace-separated field is used (rest is a comment)
//   - Entries can be plain IPs ("127.0.0.1") or CIDR ranges ("10.0.0.0/8")
package acl

import (
	"net"
	"os"
	"strings"
)

// AccessList holds parsed entries from an agent.access file.
type AccessList struct {
	entries []entry
}

type entry struct {
	network *net.IPNet // set for CIDR entries
	ip      net.IP     // set for plain-IP entries (host /32 or /128)
}

// LoadFile reads and parses the access list at path.
// Returns an empty list (deny all) if the file does not exist.
func LoadFile(path string) (*AccessList, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &AccessList{}, nil
	}
	if err != nil {
		return nil, err
	}
	return Parse(string(data)), nil
}

// Parse parses the access list from a string (for testing).
func Parse(content string) *AccessList {
	var entries []entry
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Only the first field matters (rest is a comment / description)
		field := strings.Fields(line)[0]
		e := parseEntry(field)
		if e != nil {
			entries = append(entries, *e)
		}
	}
	return &AccessList{entries: entries}
}

func parseEntry(s string) *entry {
	// Try CIDR first
	if strings.Contains(s, "/") {
		_, network, err := net.ParseCIDR(s)
		if err == nil {
			return &entry{network: network}
		}
		return nil // invalid CIDR — skip
	}
	// Try plain IP
	ip := net.ParseIP(s)
	if ip == nil {
		return nil // not a valid IP — skip (matches Ruby's rescue IPAddr::InvalidAddressError)
	}
	return &entry{ip: ip}
}

// Allows reports whether the given IP address string is permitted.
// Returns false if the access list is empty or the address is invalid.
func (a *AccessList) Allows(ipStr string) bool {
	if len(a.entries) == 0 {
		return false
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, e := range a.entries {
		if e.network != nil {
			if e.network.Contains(ip) {
				return true
			}
		} else if e.ip != nil {
			if e.ip.Equal(ip) {
				return true
			}
		}
	}
	return false
}

// Entries returns the raw string entries from the file (for display in 'accesslist' cmd).
func Entries(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		field := strings.Fields(line)[0]
		out = append(out, field)
	}
	return out
}
