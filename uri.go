package otpkit

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// URIConfig describes the parameters of an otpauth:// URI as consumed by
// authenticator apps (Google Authenticator key URI format).
type URIConfig struct {
	// Issuer is the provider or service name (e.g. "Example Co").
	Issuer string
	// Account identifies the user, typically an email address.
	Account string
	// Secret is the Base32-encoded shared secret.
	Secret string
	// Options carries digits, period and algorithm. Zero fields use defaults.
	Options Options
}

// BuildURI returns an otpauth:// URI for the given type ("totp" or "hotp").
// For "hotp" the counter is included as the initial counter value.
func BuildURI(otpType string, cfg URIConfig, counter uint64) (string, error) {
	otpType = strings.ToLower(otpType)
	if otpType != "totp" && otpType != "hotp" {
		return "", fmt.Errorf("otpkit: otp type must be \"totp\" or \"hotp\", got %q", otpType)
	}
	if cfg.Secret == "" {
		return "", fmt.Errorf("otpkit: secret is required")
	}

	opts := cfg.Options.withDefaults()

	label := cfg.Account
	if cfg.Issuer != "" {
		label = cfg.Issuer + ":" + cfg.Account
	}

	q := url.Values{}
	q.Set("secret", strings.ToUpper(strings.TrimSpace(cfg.Secret)))
	if cfg.Issuer != "" {
		q.Set("issuer", cfg.Issuer)
	}
	q.Set("algorithm", opts.Algorithm.String())
	q.Set("digits", strconv.Itoa(opts.Digits))
	if otpType == "totp" {
		q.Set("period", strconv.Itoa(opts.Period))
	} else {
		q.Set("counter", strconv.FormatUint(counter, 10))
	}

	u := url.URL{
		Scheme:   "otpauth",
		Host:     otpType,
		Path:     "/" + label,
		RawQuery: q.Encode(),
	}
	return u.String(), nil
}
