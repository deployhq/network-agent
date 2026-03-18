package acl_test

import (
	"os"
	"testing"

	"github.com/deployhq/network-agent/internal/acl"
)

// Tests mirror the RSpec examples in deploy_agent_spec.rb.

func TestReadsDestinationsFromFile(t *testing.T) {
	f := tempFile(t, "127.0.0.1\n192.168.1.0/24\n")
	list, err := acl.LoadFile(f)
	if err != nil {
		t.Fatal(err)
	}
	if !list.Allows("127.0.0.1") {
		t.Error("should allow 127.0.0.1")
	}
	if !list.Allows("192.168.1.50") {
		t.Error("should allow 192.168.1.50 (in /24)")
	}
	if list.Allows("10.0.0.1") {
		t.Error("should deny 10.0.0.1")
	}
}

func TestStripsWhitespace(t *testing.T) {
	list := acl.Parse("  127.0.0.1  \n  192.168.1.1  \n")
	if !list.Allows("127.0.0.1") {
		t.Error("should allow 127.0.0.1")
	}
	if !list.Allows("192.168.1.1") {
		t.Error("should allow 192.168.1.1")
	}
}

func TestIgnoresEmptyLines(t *testing.T) {
	list := acl.Parse("127.0.0.1\n\n192.168.1.1\n")
	if !list.Allows("127.0.0.1") {
		t.Error("should allow 127.0.0.1")
	}
	if !list.Allows("192.168.1.1") {
		t.Error("should allow 192.168.1.1")
	}
}

func TestIgnoresCommentLines(t *testing.T) {
	list := acl.Parse("# Comment\n127.0.0.1\n# Another comment\n192.168.1.1\n")
	if !list.Allows("127.0.0.1") {
		t.Error("should allow 127.0.0.1")
	}
	if !list.Allows("192.168.1.1") {
		t.Error("should allow 192.168.1.1")
	}
}

func TestExtractsFirstFieldOnly(t *testing.T) {
	// 'accesslist' format: "127.0.0.1 localhost" — only first field matters
	list := acl.Parse("127.0.0.1 localhost\n192.168.1.1 description\n")
	if !list.Allows("127.0.0.1") {
		t.Error("should allow 127.0.0.1")
	}
	if !list.Allows("192.168.1.1") {
		t.Error("should allow 192.168.1.1")
	}
}

func TestEmptyFileDenieAll(t *testing.T) {
	list := acl.Parse("")
	if list.Allows("127.0.0.1") {
		t.Error("empty access list should deny all")
	}
}

func TestMissingFileDenieAll(t *testing.T) {
	list, err := acl.LoadFile("/tmp/does-not-exist-network-agent-test.access")
	if err != nil {
		t.Fatal(err)
	}
	if list.Allows("127.0.0.1") {
		t.Error("missing access list should deny all")
	}
}

func TestInvalidAddressSkipped(t *testing.T) {
	// Invalid entries are skipped; valid ones still work
	list := acl.Parse("not-a-valid-ip\n127.0.0.1\n")
	if !list.Allows("127.0.0.1") {
		t.Error("should allow 127.0.0.1 despite invalid entry above")
	}
}

func TestIPv6(t *testing.T) {
	list := acl.Parse("::1\n")
	if !list.Allows("::1") {
		t.Error("should allow ::1")
	}
}

func TestCIDRRange(t *testing.T) {
	list := acl.Parse("10.0.0.0/8\n")
	if !list.Allows("10.1.2.3") {
		t.Error("should allow 10.1.2.3 in 10.0.0.0/8")
	}
	if list.Allows("192.168.1.1") {
		t.Error("should deny 192.168.1.1 not in 10.0.0.0/8")
	}
}

// tempFile writes content to a temp file and returns its path.
func tempFile(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp("", "agent-access-test-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(f.Name()) })
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	f.Close()
	return f.Name()
}
