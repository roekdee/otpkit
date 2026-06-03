// Command otpkit prints the current TOTP code for a Base32 secret.
//
// Defensive / educational — implements standard RFCs for 2FA.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/roekdee/otpkit"
)

func main() {
	secret := flag.String("secret", "", "Base32-encoded shared secret (required)")
	digits := flag.Int("digits", otpkit.DefaultDigits, "number of digits (6 or 8)")
	period := flag.Int("period", otpkit.DefaultPeriod, "time step in seconds")
	algName := flag.String("alg", "SHA1", "HMAC algorithm: SHA1, SHA256 or SHA512")
	flag.Parse()

	if *secret == "" {
		fmt.Fprintln(os.Stderr, "error: -secret is required")
		flag.Usage()
		os.Exit(2)
	}

	alg, err := parseAlg(*algName)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}

	opts := otpkit.Options{Digits: *digits, Period: *period, Algorithm: alg}
	code, err := otpkit.GenerateTOTP(*secret, time.Now().Unix(), opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	fmt.Println(code)
}

func parseAlg(name string) (otpkit.Algorithm, error) {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "SHA1":
		return otpkit.SHA1, nil
	case "SHA256":
		return otpkit.SHA256, nil
	case "SHA512":
		return otpkit.SHA512, nil
	default:
		return otpkit.SHA1, fmt.Errorf("unknown algorithm %q (use SHA1, SHA256 or SHA512)", name)
	}
}
