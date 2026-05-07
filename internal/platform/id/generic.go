package id

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

const alphaNumCharset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// GenerateHexID returns a cryptographically secure hex identifier.
func GenerateHexID(byteLen int) (string, error) {
	if byteLen <= 0 {
		return "", fmt.Errorf("invalid byte length: %d", byteLen)
	}
	buf := make([]byte, byteLen)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// GenerateAlphaNumID returns a cryptographically secure alpha-numeric identifier.
func GenerateAlphaNumID(length int) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("invalid id length: %d", length)
	}
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	out := make([]byte, length)
	for i, b := range buf {
		out[i] = alphaNumCharset[int(b)%len(alphaNumCharset)]
	}
	return string(out), nil
}
