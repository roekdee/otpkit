# otpkit

![CI](https://github.com/roekdee/otpkit/actions/workflows/ci.yml/badge.svg)

otpkit is a small Go library that generates and validates one-time passwords for
two-factor authentication. It implements HOTP (RFC 4226) and TOTP (RFC 6238),
which are the schemes authenticator apps like Google Authenticator and Authy use.

I built it to have a dependency-free, RFC-correct OTP implementation I understand
end to end. It uses only the Go standard library (`crypto/hmac`, the SHA hashes,
`encoding/base32`, and `crypto/subtle` for constant-time comparison).

What you can do with it:

- Generate a HOTP code from a Base32 secret and counter.
- Generate a TOTP code from a Base32 secret and a Unix time.
- Validate a submitted code, with a configurable window (`Skew`) to tolerate
  clock drift.
- Resynchronise an HOTP counter with a forward look-ahead window (RFC 4226
  §7.4) when the client's counter has run ahead of the server's.
- Choose digits (6 or 8), period (default 30s), and algorithm (SHA1/256/512).
- Build an `otpauth://` URI for provisioning a secret into an authenticator app.

## Usage

```go
package main

import (
	"fmt"
	"time"

	"github.com/roekdee/otpkit"
)

func main() {
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" // Base32

	// Current TOTP code (6 digits, 30s period, SHA1 by default).
	code, _ := otpkit.GenerateTOTP(secret, time.Now().Unix(), otpkit.Options{})
	fmt.Println("code:", code)

	// Validate a submitted code, allowing one step of clock drift.
	ok, _ := otpkit.ValidateTOTP(secret, code, time.Now().Unix(), otpkit.Options{Skew: 1})
	fmt.Println("valid:", ok)

	// Resync an HOTP counter: the client may have generated a few codes the
	// server never saw. Check counter..counter+lookAhead and, on a match,
	// store the returned next counter.
	hotpSecret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	ok, next, _ := otpkit.ResyncHOTP(hotpSecret, "520489", 0, 10, otpkit.Options{})
	fmt.Println("resynced:", ok, "next counter:", next)

	// Provisioning URI for an authenticator app.
	uri, _ := otpkit.BuildURI("totp", otpkit.URIConfig{
		Issuer:  "Example Co",
		Account: "alice@example.com",
		Secret:  secret,
	}, 0)
	fmt.Println(uri)
}
```

There is also a tiny CLI that prints the current code for a secret:

```
go run ./cmd/otpkit -secret GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
go run ./cmd/otpkit -secret GEZDGNBVGY3TQOJQ -digits 8 -alg SHA256
```

## Build and test

```
go build ./...
go vet ./...
go test ./... -count=1
```

The tests check the code against the official **RFC 6238 Appendix B** TOTP test
vectors (the SHA1/SHA256/SHA512 seeds and listed Unix times → expected 8-digit
codes) and the **RFC 4226 Appendix D** HOTP vectors. If those pass, the core
algorithm matches the specs.

## Notes

One design point: validation compares the submitted code against each candidate
in the skew window using `crypto/subtle.ConstantTimeCompare` rather than `==`, so
the comparison time does not depend on how many leading characters match. That
keeps the check from leaking information through timing.

Honest limits:

- There is no replay protection. HOTP/TOTP only tell you a code is currently
  valid; preventing the same code from being accepted twice (consuming used
  counters/time-steps) is the caller's responsibility and needs persistent
  state.
- It does not generate secrets for you — you bring your own Base32 secret. The
  decoder is lenient about case, spaces, and missing padding, but it does not
  enforce a minimum secret length, so picking a strong secret is on the caller.

Defensive / educational — implements standard RFCs for 2FA.
