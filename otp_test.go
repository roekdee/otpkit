package otpkit

import "testing"

// Base32 encodings of the ASCII seeds used by the RFCs.
//
// RFC 4226 / RFC 6238 SHA1: "12345678901234567890" (20 bytes)
// RFC 6238 SHA256: that string repeated to 32 bytes
// RFC 6238 SHA512: that string repeated to 64 bytes
const (
	seedSHA1   = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	seedSHA256 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA===="
	seedSHA512 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA="
)

// TestHOTPRFC4226 checks the implementation against the HOTP test values in
// RFC 4226, Appendix D. Secret is "12345678901234567890", 6 digits, SHA1.
func TestHOTPRFC4226(t *testing.T) {
	// Counter -> expected 6-digit code (RFC 4226 Appendix D, "Truncated").
	want := []string{
		"755224", "287082", "359152", "969429", "338314",
		"254676", "287922", "162583", "399871", "520489",
	}
	for counter, code := range want {
		got, err := GenerateHOTP(seedSHA1, uint64(counter), Options{Digits: 6})
		if err != nil {
			t.Fatalf("counter %d: unexpected error: %v", counter, err)
		}
		if got != code {
			t.Errorf("HOTP counter %d = %q, want %q", counter, got, code)
		}
	}
}

// TestTOTPRFC6238 checks against the test vectors in RFC 6238, Appendix B.
// Codes are 8 digits. Each listed Unix time maps to a code per algorithm.
func TestTOTPRFC6238(t *testing.T) {
	cases := []struct {
		unix int64
		alg  Algorithm
		seed string
		want string
	}{
		// SHA1
		{59, SHA1, seedSHA1, "94287082"},
		{1111111109, SHA1, seedSHA1, "07081804"},
		{1111111111, SHA1, seedSHA1, "14050471"},
		{1234567890, SHA1, seedSHA1, "89005924"},
		{2000000000, SHA1, seedSHA1, "69279037"},
		{20000000000, SHA1, seedSHA1, "65353130"},
		// SHA256
		{59, SHA256, seedSHA256, "46119246"},
		{1111111109, SHA256, seedSHA256, "68084774"},
		{1111111111, SHA256, seedSHA256, "67062674"},
		{1234567890, SHA256, seedSHA256, "91819424"},
		{2000000000, SHA256, seedSHA256, "90698825"},
		{20000000000, SHA256, seedSHA256, "77737706"},
		// SHA512
		{59, SHA512, seedSHA512, "90693936"},
		{1111111109, SHA512, seedSHA512, "25091201"},
		{1111111111, SHA512, seedSHA512, "99943326"},
		{1234567890, SHA512, seedSHA512, "93441116"},
		{2000000000, SHA512, seedSHA512, "38618901"},
		{20000000000, SHA512, seedSHA512, "47863826"},
	}

	for _, c := range cases {
		opts := Options{Digits: 8, Period: 30, Algorithm: c.alg}
		got, err := GenerateTOTP(c.seed, c.unix, opts)
		if err != nil {
			t.Fatalf("%s t=%d: unexpected error: %v", c.alg, c.unix, err)
		}
		if got != c.want {
			t.Errorf("TOTP %s t=%d = %q, want %q", c.alg, c.unix, got, c.want)
		}
	}
}

func TestValidateTOTP(t *testing.T) {
	// At t=59 the SHA1 8-digit code is 94287082.
	ok, err := ValidateTOTP(seedSHA1, "94287082", 59, Options{Digits: 8})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Errorf("expected code to validate at t=59")
	}

	// A wrong code must not validate.
	ok, _ = ValidateTOTP(seedSHA1, "00000000", 59, Options{Digits: 8})
	if ok {
		t.Errorf("expected wrong code to fail validation")
	}
}

func TestValidateTOTPSkew(t *testing.T) {
	// The code one step earlier (t=29) should validate at t=59 when skew=1,
	// but not when skew=0.
	prev, err := GenerateTOTP(seedSHA1, 29, Options{Digits: 8})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ok, _ := ValidateTOTP(seedSHA1, prev, 59, Options{Digits: 8, Skew: 0})
	if ok {
		t.Errorf("previous-step code should fail with skew=0")
	}

	ok, _ = ValidateTOTP(seedSHA1, prev, 59, Options{Digits: 8, Skew: 1})
	if !ok {
		t.Errorf("previous-step code should validate with skew=1")
	}
}

func TestValidateHOTPReturnsCounter(t *testing.T) {
	// HOTP code for counter 3 is 969429; validating around counter 1 with
	// skew 2 should match and report counter 3.
	ok, matched, err := ValidateHOTP(seedSHA1, "969429", 1, Options{Digits: 6, Skew: 2})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatalf("expected match within skew window")
	}
	if matched != 3 {
		t.Errorf("matched counter = %d, want 3", matched)
	}
}

func TestGenerateDefaults(t *testing.T) {
	// With no options the defaults are 6 digits / SHA1; the HOTP counter-0
	// value is 755224.
	got, err := GenerateHOTP(seedSHA1, 0, Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "755224" {
		t.Errorf("default HOTP counter 0 = %q, want 755224", got)
	}
	if len(got) != DefaultDigits {
		t.Errorf("default code length = %d, want %d", len(got), DefaultDigits)
	}
}

func TestDecodeSecretTolerant(t *testing.T) {
	// Lowercase, spaces, and missing padding should all decode.
	for _, s := range []string{
		"gezdgnbvgy3tqojqgezdgnbvgy3tqojq",
		"GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ",
		"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
	} {
		got, err := GenerateHOTP(s, 0, Options{Digits: 6})
		if err != nil {
			t.Fatalf("secret %q: unexpected error: %v", s, err)
		}
		if got != "755224" {
			t.Errorf("secret %q: code = %q, want 755224", s, got)
		}
	}
}

func TestInvalidSecret(t *testing.T) {
	if _, err := GenerateHOTP("not!base32", 0, Options{}); err == nil {
		t.Errorf("expected error for invalid base32 secret")
	}
	if _, err := GenerateHOTP("", 0, Options{}); err == nil {
		t.Errorf("expected error for empty secret")
	}
}

func TestInvalidDigits(t *testing.T) {
	if _, err := GenerateHOTP(seedSHA1, 0, Options{Digits: 9}); err == nil {
		t.Errorf("expected error for digits out of range")
	}
}
