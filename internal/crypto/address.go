package crypto

import (
	"errors"
	"strconv"
)

// AddressTypeRegular is the standard "N…" address. AddressTypeMulti is the
// less-used "M…" multisig variant.
const (
	AddressTypeRegular = 0
	AddressTypeMulti   = 1
)

// AddressFromPublicKey derives a Noso address from a Base64-encoded public
// key string using the exact algorithm in `GetAddressFromPublicKey`
// (`nosocrypto.pas:245-258`). `addrType` selects the leading byte: `N` for
// regular addresses (type 0), `M` for multisig (type 1).
//
// The pipeline is:
//
//	sha   = SHA-256(pubkeyB64 as UTF-8) → uppercase 64-char hex
//	md160 = RIPEMD-160(sha as UTF-8)    → uppercase 40-char hex
//	body  = Base58(big-int parse of md160)
//	chk   = Base58(decimal sum-of-B58-indices of body)
//	addr  = "N" + body + chk
//
// The function returns an empty string and an error if the input is empty.
// It does not validate that pubkey is a real EC point; that's the caller's
// responsibility.
func AddressFromPublicKey(pubkeyB64 string, addrType int) (string, error) {
	if pubkeyB64 == "" {
		return "", errors.New("crypto.AddressFromPublicKey: empty pubkey")
	}
	if addrType != AddressTypeRegular && addrType != AddressTypeMulti {
		return "", errors.New("crypto.AddressFromPublicKey: bad address type")
	}
	sha := SHA256String(pubkeyB64)
	md160 := RIPEMD160String(sha)
	body := HexToB58(md160)
	chk := DecToB58(strconv.Itoa(B58Checksum(body)))
	prefix := byte('N')
	if addrType == AddressTypeMulti {
		prefix = 'M'
	}
	return string(prefix) + body + chk, nil
}

// IsValidAddress reports whether `addr` passes the same structural checks
// `IsValidHashAddress` does (`nosocrypto.pas:327-342`):
//
//  1. starts with 'N' or 'M'
//  2. len > 20
//  3. body (addr minus prefix minus the last 2 checksum chars) is all-B58
//  4. recomputed addr (prefix + body + B58(B58checksum(body))) equals input
//
// Pascal extracts the body as `Copy(addr, 2, length(addr) - 3)`, which is
// (length-3) characters starting at position 2 — i.e. it strips the prefix
// AND the last 2 chars. The validator therefore implicitly requires the
// stored checksum to be exactly 2 chars long. For typical Noso addresses
// (~28-char Base58 body, RIPEMD-160-derived) the checksum is almost always
// 2 chars; rare addresses with 1- or 3-char checksums would be rejected by
// the original Pascal validator too, and we preserve that behavior.
func IsValidAddress(addr string) bool {
	if len(addr) <= 20 {
		return false
	}
	if addr[0] != 'N' && addr[0] != 'M' {
		return false
	}
	body := addr[1 : len(addr)-2]
	if !IsValidB58(body) {
		return false
	}
	rebuilt := string(addr[0]) + body + DecToB58(strconv.Itoa(B58Checksum(body)))
	return rebuilt == addr
}

// TransferHash is the canonical hash used for transaction TrfrID:
// "tR" + Base58(SHA256(text)) + Base58(checksum). Source:
// `GetTransferHash` in `nosocrypto.pas:345-352`.
func TransferHash(text string) string {
	sha := SHA256String(text)
	b58 := HexToB58(sha)
	chk := DecToB58(strconv.Itoa(B58Checksum(b58)))
	return "tR" + b58 + chk
}

// OrderHash is the canonical OrderID hash: "OR" + Base36(SHA256(text)).
// Source: `GetOrderHash` in `nosocrypto.pas:355-359`. Note the use of
// Base36 here, not Base58.
func OrderHash(text string) string {
	sha := SHA256String(text)
	return "OR" + HexToB36(sha)
}
