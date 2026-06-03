package otpkit

import (
	"net/url"
	"strings"
	"testing"
)

func TestBuildURITOTP(t *testing.T) {
	cfg := URIConfig{
		Issuer:  "Example Co",
		Account: "alice@example.com",
		Secret:  seedSHA1,
		Options: Options{Digits: 6, Period: 30, Algorithm: SHA1},
	}
	uri, err := BuildURI("totp", cfg, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.HasPrefix(uri, "otpauth://totp/") {
		t.Errorf("unexpected scheme/host: %q", uri)
	}

	u, err := url.Parse(uri)
	if err != nil {
		t.Fatalf("result is not a valid URL: %v", err)
	}
	q := u.Query()
	if q.Get("secret") != seedSHA1 {
		t.Errorf("secret = %q, want %q", q.Get("secret"), seedSHA1)
	}
	if q.Get("issuer") != "Example Co" {
		t.Errorf("issuer = %q", q.Get("issuer"))
	}
	if q.Get("algorithm") != "SHA1" {
		t.Errorf("algorithm = %q", q.Get("algorithm"))
	}
	if q.Get("digits") != "6" {
		t.Errorf("digits = %q", q.Get("digits"))
	}
	if q.Get("period") != "30" {
		t.Errorf("period = %q", q.Get("period"))
	}
	// Label is "Issuer:Account"; url.Parse keeps it in Path.
	if !strings.Contains(u.Path, "alice@example.com") {
		t.Errorf("label missing account: %q", u.Path)
	}
}

func TestBuildURIHOTPIncludesCounter(t *testing.T) {
	cfg := URIConfig{Account: "bob", Secret: seedSHA1}
	uri, err := BuildURI("hotp", cfg, 7)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	u, _ := url.Parse(uri)
	if u.Query().Get("counter") != "7" {
		t.Errorf("counter = %q, want 7", u.Query().Get("counter"))
	}
}

func TestBuildURIErrors(t *testing.T) {
	if _, err := BuildURI("bogus", URIConfig{Secret: seedSHA1}, 0); err == nil {
		t.Errorf("expected error for invalid otp type")
	}
	if _, err := BuildURI("totp", URIConfig{}, 0); err == nil {
		t.Errorf("expected error for missing secret")
	}
}
