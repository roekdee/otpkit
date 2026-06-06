// Package otpkit implements HOTP (RFC 4226) and TOTP (RFC 6238)
// one-time-password generation and validation for two-factor authentication.
//
// Defensive / educational — implements standard RFCs for 2FA.
package otpkit

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"strings"
)

// Algorithm selects the HMAC hash used to derive codes.
type Algorithm int

const (
	// SHA1 is the default algorithm and the one assumed by most authenticator apps.
	SHA1 Algorithm = iota
	SHA256
	SHA512
)

func (a Algorithm) String() string {
	switch a {
	case SHA256:
		return "SHA256"
	case SHA512:
		return "SHA512"
	default:
		return "SHA1"
	}
}

func (a Algorithm) hasher() func() hash.Hash {
	switch a {
	case SHA256:
		return sha256.New
	case SHA512:
		return sha512.New
	default:
		return sha1.New
	}
}

// Default values used when a field of Options is left zero.
const (
	DefaultDigits = 6
	DefaultPeriod = 30
)

// digitsPow10 maps a digit count to 10^digits, used to truncate the dynamic
// binary code to the requested number of decimal digits.
var digitsPow10 = []uint32{
	1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000,
}

// Options configures code generation and validation.
//
// A zero value is not valid on its own; use the package functions which fill
// in defaults (6 digits, 30s period, SHA1) when fields are zero.
type Options struct {
	// Digits is the length of the generated code. Common values are 6 and 8.
	Digits int
	// Period is the TOTP time step in seconds (ignored by HOTP).
	Period int
	// Algorithm is the HMAC hash used. Defaults to SHA1.
	Algorithm Algorithm
	// Skew is the number of steps before and after the current one that are
	// accepted during validation, to tolerate clock drift. Zero means only the
	// exact step is accepted.
	Skew int
}

func (o Options) withDefaults() Options {
	if o.Digits == 0 {
		o.Digits = DefaultDigits
	}
	if o.Period == 0 {
		o.Period = DefaultPeriod
	}
	return o
}

// decodeSecret decodes a Base32 secret. It is tolerant of lowercase input and
// missing padding, which authenticator secrets commonly omit.
func decodeSecret(secret string) ([]byte, error) {
	s := strings.ToUpper(strings.TrimSpace(secret))
	s = strings.ReplaceAll(s, " ", "")
	// Add padding to a multiple of 8 so the standard decoder accepts it.
	if pad := len(s) % 8; pad != 0 {
		s += strings.Repeat("=", 8-pad)
	}
	key, err := base32.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("otpkit: invalid base32 secret: %w", err)
	}
	if len(key) == 0 {
		return nil, fmt.Errorf("otpkit: empty secret")
	}
	return key, nil
}

// computeCode runs the HOTP truncation defined in RFC 4226 §5.3 over the given
// 8-byte counter, for the supplied raw key, algorithm and digit count.
func computeCode(key []byte, counter uint64, alg Algorithm, digits int) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)

	mac := hmac.New(alg.hasher(), key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	// Dynamic truncation: low 4 bits of the last byte select the offset.
	offset := sum[len(sum)-1] & 0x0f
	binCode := (uint32(sum[offset]&0x7f) << 24) |
		(uint32(sum[offset+1]) << 16) |
		(uint32(sum[offset+2]) << 8) |
		uint32(sum[offset+3])

	code := binCode % digitsPow10[digits]
	return fmt.Sprintf("%0*d", digits, code)
}

// GenerateHOTP returns the HOTP code (RFC 4226) for a Base32 secret and counter.
func GenerateHOTP(secret string, counter uint64, opts Options) (string, error) {
	opts = opts.withDefaults()
	if opts.Digits < 1 || opts.Digits > 8 {
		return "", fmt.Errorf("otpkit: digits must be between 1 and 8, got %d", opts.Digits)
	}
	key, err := decodeSecret(secret)
	if err != nil {
		return "", err
	}
	return computeCode(key, counter, opts.Algorithm, opts.Digits), nil
}

// GenerateTOTP returns the TOTP code (RFC 6238) for a Base32 secret at a given
// Unix time in seconds.
func GenerateTOTP(secret string, unix int64, opts Options) (string, error) {
	opts = opts.withDefaults()
	counter := uint64(unix / int64(opts.Period))
	return GenerateHOTP(secret, counter, opts)
}

// ValidateHOTP reports whether code matches the HOTP value for the given
// counter, within opts.Skew counters on either side. Comparison is
// constant-time. It returns the matched counter so callers can resynchronise.
func ValidateHOTP(secret, code string, counter uint64, opts Options) (bool, uint64, error) {
	opts = opts.withDefaults()
	key, err := decodeSecret(secret)
	if err != nil {
		return false, 0, err
	}
	if opts.Digits < 1 || opts.Digits > 8 {
		return false, 0, fmt.Errorf("otpkit: digits must be between 1 and 8, got %d", opts.Digits)
	}

	skew := opts.Skew
	if skew < 0 {
		skew = -skew
	}
	for delta := -skew; delta <= skew; delta++ {
		c := counter
		if delta < 0 {
			d := uint64(-delta)
			if d > c {
				continue // avoid wrapping below zero
			}
			c -= d
		} else {
			c += uint64(delta)
		}
		candidate := computeCode(key, c, opts.Algorithm, opts.Digits)
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(code)) == 1 {
			return true, c, nil
		}
	}
	return false, 0, nil
}

// ResyncHOTP validates an HOTP code against the resynchronisation window
// described in RFC 4226 §7.4. It checks the code against the counters
// counter..counter+lookAhead (forward only, since an HOTP counter only ever
// advances) using constant-time comparison.
//
// On a match it returns ok=true and newCounter set to matchedCounter+1, which is
// the next counter value the server should store. On no match it returns
// (false, 0). A lookAhead of 0 checks only the current counter.
func ResyncHOTP(secret, code string, counter uint64, lookAhead uint, opts Options) (ok bool, newCounter uint64, err error) {
	opts = opts.withDefaults()
	if opts.Digits < 1 || opts.Digits > 8 {
		return false, 0, fmt.Errorf("otpkit: digits must be between 1 and 8, got %d", opts.Digits)
	}
	key, err := decodeSecret(secret)
	if err != nil {
		return false, 0, err
	}

	for i := uint(0); i <= lookAhead; i++ {
		c := counter + uint64(i)
		candidate := computeCode(key, c, opts.Algorithm, opts.Digits)
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(code)) == 1 {
			return true, c + 1, nil
		}
	}
	return false, 0, nil
}

// ValidateTOTP reports whether code is valid at the given Unix time, accepting
// codes from opts.Skew steps before and after to tolerate clock drift.
// Comparison is constant-time.
func ValidateTOTP(secret, code string, unix int64, opts Options) (bool, error) {
	opts = opts.withDefaults()
	counter := uint64(unix / int64(opts.Period))
	ok, _, err := ValidateHOTP(secret, code, counter, opts)
	return ok, err
}
