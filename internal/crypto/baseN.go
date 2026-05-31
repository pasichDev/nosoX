// Package crypto implements the Noso cryptographic primitives byte-for-byte
// compatible with the original Pascal node (`nosocrypto.pas`,
// `mpsignerutils.pas`) and the Dart client (`NosoDart/lib/crypto/*`).
//
// Notable Noso-specific quirks preserved here:
//
//   - Hashes consume the UTF-8 bytes of the string representation of their
//     input, not the raw decoded bytes. In particular, SHA256/RIPEMD160 in
//     address derivation are applied to the Base64 *string* of the public
//     key. Naive ports that decode Base64 first will produce wrong addresses.
//   - RIPEMD160 of a 32-byte SHA256 digest is, in Noso, RIPEMD160 over the
//     uppercase hex *string* of that digest (64 ASCII bytes).
//   - The Base58 checksum is a simple sum of alphabet indices, not a hash.
//   - Signatures use SHA-1 + ECDSA on secp256k1, DER-wrapped, Base64-encoded.
//
// These are not improvements; they are spec.
package crypto

import (
	"fmt"
	"math/big"
	"strings"
)

const (
	// AlphabetB58 is the Noso Base58 alphabet (matches Bitcoin's: omits 0, O, I, l).
	AlphabetB58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

	// AlphabetB36 is lowercase only — note that some Base36 implementations
	// use uppercase. Noso uses lowercase, and changing this breaks OrderID
	// formats.
	AlphabetB36 = "0123456789abcdefghijklmnopqrstuvwxyz"
)

var (
	bigZero = big.NewInt(0)
	big58   = big.NewInt(58)
	big36   = big.NewInt(36)
	big16   = big.NewInt(16)
	big10   = big.NewInt(10)
)

// EncodeBaseN encodes a non-negative big.Int into a string over the given
// alphabet. Returns "1" when the value is zero, matching `BMHexTo58` in
// `nosocrypto.pas:915` (which produces a leading '1' equivalent to a 0
// digit in Bitcoin's Base58).
//
// The alphabet's length determines the base.
func EncodeBaseN(value *big.Int, alphabet string) string {
	if value.Sign() == 0 {
		return string(alphabet[0])
	}
	base := big.NewInt(int64(len(alphabet)))
	v := new(big.Int).Set(value)
	mod := new(big.Int)
	var sb strings.Builder
	for v.Sign() > 0 {
		v.QuoRem(v, base, mod)
		sb.WriteByte(alphabet[mod.Int64()])
	}
	// Reverse — the loop appends least-significant digit first.
	s := sb.String()
	out := make([]byte, len(s))
	for i := range s {
		out[len(s)-1-i] = s[i]
	}
	return string(out)
}

// DecodeBaseN decodes a string back to a big.Int using the given alphabet.
// Returns an error if the string contains a character outside the alphabet.
func DecodeBaseN(s, alphabet string) (*big.Int, error) {
	base := big.NewInt(int64(len(alphabet)))
	result := new(big.Int)
	tmp := new(big.Int)
	for _, c := range s {
		idx := strings.IndexRune(alphabet, c)
		if idx < 0 {
			return nil, fmt.Errorf("crypto.DecodeBaseN: char %q not in alphabet", c)
		}
		result.Mul(result, base)
		tmp.SetInt64(int64(idx))
		result.Add(result, tmp)
	}
	return result, nil
}

// IsValidB58 reports whether every character of s is in the Noso B58
// alphabet. Mirrors `IsValid58` in `nosocrypto.pas`.
func IsValidB58(s string) bool {
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(AlphabetB58, s[i]) < 0 {
			return false
		}
	}
	return true
}

// HexToBigInt parses a hex string (any case) into a big.Int. An odd-length
// input is left-padded with a zero, matching `BMHexToDec` semantics.
func HexToBigInt(s string) (*big.Int, error) {
	s = strings.TrimSpace(s)
	if len(s)%2 != 0 {
		s = "0" + s
	}
	v, ok := new(big.Int).SetString(s, 16)
	if !ok {
		return nil, fmt.Errorf("crypto.HexToBigInt: invalid hex %q", s)
	}
	return v, nil
}

// HexToB58 converts an uppercase hex string to Noso Base58, matching
// `B16ToB58` (`nosocrypto.pas:575`). Returns "1" on empty/invalid input
// — the Pascal function does the same as a defensive default.
func HexToB58(hex string) string {
	v, err := HexToBigInt(hex)
	if err != nil {
		return "1"
	}
	return EncodeBaseN(v, AlphabetB58)
}

// HexToB36 converts a hex string to Noso Base36 (lowercase). Used by
// OrderID hashes.
func HexToB36(hex string) string {
	v, err := HexToBigInt(hex)
	if err != nil {
		return AlphabetB36[:1]
	}
	return EncodeBaseN(v, AlphabetB36)
}

// DecToB58 converts a decimal string (as produced by Pascal's IntToStr) to
// Base58. Mirrors `BMDecTo58`.
func DecToB58(decimal string) string {
	v, ok := new(big.Int).SetString(decimal, 10)
	if !ok {
		return "1"
	}
	return EncodeBaseN(v, AlphabetB58)
}

// B58Checksum returns the sum of alphabet indices for every character of s
// that exists in the Base58 alphabet. Characters not in the alphabet
// contribute zero, matching the Pascal behavior where `Pos(c, alpha) = 0`
// yields `-1` after subtraction; however, Pascal then adds -1 to total,
// which would silently underflow. The Pascal code is buggy in this edge
// case but the bug is never triggered in practice because input is always
// pre-validated to be in the alphabet. We mirror the practical behavior
// (skip out-of-alphabet chars) which matches the Dart implementation as
// well (`base58Checksum` in `noso_core.dart:124-135`).
func B58Checksum(s string) int {
	total := 0
	for i := 0; i < len(s); i++ {
		idx := strings.IndexByte(AlphabetB58, s[i])
		if idx >= 0 {
			total += idx
		}
	}
	return total
}

// PadLeftChar prepends ch to s until its length reaches n. Mirrors
// `AddChar('1', s, 3)` used in certificate checksums.
func PadLeftChar(s string, ch byte, n int) string {
	if len(s) >= n {
		return s
	}
	pad := make([]byte, n-len(s))
	for i := range pad {
		pad[i] = ch
	}
	return string(pad) + s
}
