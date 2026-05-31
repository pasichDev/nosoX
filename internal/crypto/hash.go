package crypto

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"golang.org/x/crypto/ripemd160"
)

// SHA256String returns the uppercase hex encoding of SHA-256(s as UTF-8).
// This matches `HashSha256String` in `nosocrypto.pas:177`, which calls
// `THashFactory.TCrypto.CreateSHA2_256().ComputeString(s, UTF8).ToString()`
// — the `.ToString()` of HashLib4Pascal returns hex in uppercase.
//
// Critical: the *string* representation of a Base64 public key is passed
// in, not its decoded bytes. See the address derivation pipeline.
func SHA256String(s string) string {
	sum := sha256.Sum256([]byte(s))
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// RIPEMD160String returns the uppercase hex encoding of RIPEMD-160(s as UTF-8).
// In Noso this is typically called on the uppercase hex string output of
// SHA256String, so the RIPEMD-160 input is the 64-byte ASCII hex string,
// not the 32-byte raw digest.
func RIPEMD160String(s string) string {
	//nolint:gosec // RIPEMD-160 is required for Noso address derivation.
	h := ripemd160.New()
	_, _ = h.Write([]byte(s))
	return strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
}

// MD5String returns the uppercase hex encoding of MD5(s as UTF-8).
// MD5 is collision-vulnerable but required for Noso consensus and
// block-file fingerprints.
func MD5String(s string) string {
	sum := md5.Sum([]byte(s)) //nolint:gosec
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// MD5Bytes is like MD5String but takes raw bytes; useful for hashing whole
// files (e.g. computing the per-block hash used in `blchhead.nos`).
func MD5Bytes(b []byte) string {
	sum := md5.Sum(b) //nolint:gosec
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}
