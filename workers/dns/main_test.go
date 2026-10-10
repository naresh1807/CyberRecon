package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestExcludedHostDoesNotResolve(t *testing.T) {
	var output bytes.Buffer
	input := `{"id":"fixture","hosts":["blocked.example.org"],"include":["*.example.org"],"exclude":["blocked.example.org"]}`
	if err := run(strings.NewReader(input), &output); err != nil {
		t.Fatal(err)
	}
	var result Result
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Error == "" || len(result.Addresses) != 0 {
		t.Fatal("excluded host processed")
	}
}
func TestIPAndWildcard(t *testing.T) {
	job := Job{Include: []string{"*.example.org", "192.0.2.0/24"}}
	if allowed("example.org", job) || allowed("example.org.evil.org", job) {
		t.Fatal("suffix bypass")
	}
	if !allowed("a.example.org", job) || !allowed("192.0.2.4", job) {
		t.Fatal("valid scope rejected")
	}
	var output bytes.Buffer
	if err := run(strings.NewReader(`{"hosts":["192.0.2.4"],"include":["192.0.2.0/24"]}`), &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "192.0.2.4") {
		t.Fatal("missing IP")
	}
}
func TestMalformedJob(t *testing.T) {
	if err := run(strings.NewReader(`{"hosts":[]}`), &bytes.Buffer{}); err == nil {
		t.Fatal("empty job accepted")
	}
}

func TestNonCanonicalInternetWideScopeRejected(t *testing.T) {
	for _, rule := range []string{"0.0.0.1/0", "192.0.2.4/0", "2001:db8::1/0", "::/0"} {
		raw, _ := json.Marshal(Job{ID: "fixture", Hosts: []string{"192.0.2.4"}, Include: []string{rule}})
		var output bytes.Buffer
		if err := run(bytes.NewReader(raw), &output); err == nil || output.Len() != 0 {
			t.Fatalf("internet-wide rule accepted: %s", rule)
		}
	}
}
func TestInputAndHostBounds(t *testing.T) {
	if err := run(strings.NewReader(strings.Repeat(" ", 1024*1024+1)), &bytes.Buffer{}); err == nil {
		t.Fatal("oversized input accepted")
	}
	hosts := make([]string, 31)
	for index := range hosts {
		hosts[index] = "192.0.2.4"
	}
	raw, _ := json.Marshal(Job{Hosts: hosts, Include: []string{"192.0.2.0/24"}})
	if err := run(bytes.NewReader(raw), &bytes.Buffer{}); err == nil {
		t.Fatal("31 hosts accepted")
	}
}

func TestScopedDNSResolutionAndFailure(t *testing.T) {
	original := lookupIPAddr
	defer func() { lookupIPAddr = original }()
	for _, failure := range []bool{false, true} {
		calls := 0
		lookupIPAddr = func(ctx context.Context, host string) ([]net.IPAddr, error) {
			calls++
			deadline, bounded := ctx.Deadline()
			if host != "owned.example.org." || !bounded || time.Until(deadline) > 3*time.Second {
				t.Errorf("invalid DNS name/deadline: %s", host)
			}
			if failure {
				return nil, errors.New("deterministic DNS error")
			}
			return []net.IPAddr{{IP: net.ParseIP("192.0.2.4")}, {IP: net.ParseIP("192.0.2.4")}, {IP: net.ParseIP("2001:db8::4")}}, nil
		}
		var output bytes.Buffer
		raw := `{"id":"dns","hosts":["owned.example.org"],"include":["owned.example.org"]}`
		if err := run(strings.NewReader(raw), &output); err != nil {
			t.Fatal(err)
		}
		var result Result
		if err := json.Unmarshal(output.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if calls != 1 {
			t.Fatal("Unexpected DNS calls")
		}
		if failure {
			if result.Error != "DNS resolution failed" || len(result.Addresses) != 0 {
				t.Fatal("Failure not reported")
			}
		} else if result.Error != "" || len(result.Addresses) != 2 {
			t.Fatal("DNS deduplication/results failed")
		}
	}
}
