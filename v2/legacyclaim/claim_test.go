package legacyclaim

import (
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"testing"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	legacy "github.com/pasichDev/noso-go/internal/crypto"
)

// Synthetic public test scalar 1. Never use this key for real funds.
func fixture(t *testing.T) (Context, Source, Proof) {
	t.Helper()
	secret := make([]byte, 32)
	secret[31] = 1
	var scalar secp.ModNScalar
	if len(secret) != 32 || scalar.SetByteSlice(secret) || scalar.IsZero() {
		t.Fatal("invalid synthetic scalar")
	}
	key := secp.PrivKeyFromBytes(secret)
	pub := base64.StdEncoding.EncodeToString(key.PubKey().SerializeUncompressed())
	address, err := legacy.AddressFromPublicKey(pub, legacy.AddressTypeRegular)
	if err != nil {
		t.Fatal(err)
	}
	ctx := Context{12345, sha256.Sum256([]byte("synthetic genesis")), sha256.Sum256([]byte("synthetic complete unsigned destination transaction"))}
	source := Source{[33]byte(key.PubKey().SerializeCompressed()), address, 123456789}
	digest, err := Digest(ctx, source)
	if err != nil {
		t.Fatal(err)
	}
	proof := Proof{pub, base64.StdEncoding.EncodeToString(ecdsa.Sign(key, digest[:]).Serialize())}
	return ctx, source, proof
}

func TestSyntheticOwnership(t *testing.T) {
	ctx, source, proof := fixture(t)
	if err := Verify(ctx, source, proof); err != nil {
		t.Fatal(err)
	}
	digest, _ := Digest(ctx, source)
	if source.Address != "N212RRYvTQTBRA3Hv2eX2HNhv5sKjBy" || hex.EncodeToString(digest[:]) != "47be004f023ef078da24925df4e0935a27ff6c48606d26beaf2681651e305eb1" || proof.PublicKeyBase64 != "BHm+Zn753LusVaBilc6HCwcCm/zbLc4o2VnygVsW+BeYSDradyajxGVdpPv8DhEIqP0XtEimhVQZnEfQj/sQ1Lg=" || proof.SignatureBase64 != "MEQCIGg26chVUpKfzZEbALfQr0e728dGr48Qf12068S9iiLVAiBLdDzDV1EKiX0Chjxaif96qJx7kglHjgzGWbmKfTrFYQ==" {
		t.Fatal("synthetic procedure vector changed")
	}
}

func TestContextAndOwnershipBinding(t *testing.T) {
	ctx, source, proof := fixture(t)
	tests := map[string]func(*Context, *Source, *Proof){
		"network":     func(c *Context, s *Source, p *Proof) { c.Network++ },
		"genesis":     func(c *Context, s *Source, p *Proof) { c.Genesis[0] ^= 1 },
		"destination": func(c *Context, s *Source, p *Proof) { c.DestinationTransaction[0] ^= 1 },
		"source":      func(c *Context, s *Source, p *Proof) { s.Commitment[0] ^= 1 },
		"amount":      func(c *Context, s *Source, p *Proof) { s.Amount++ },
		"negative":    func(c *Context, s *Source, p *Proof) { s.Amount = -1 },
		"zero amount": func(c *Context, s *Source, p *Proof) { s.Amount = 0 },
		"no network":  func(c *Context, s *Source, p *Proof) { c.Network = 0 },

		"no genesis":                func(c *Context, s *Source, p *Proof) { c.Genesis = [32]byte{} },
		"no destination":            func(c *Context, s *Source, p *Proof) { c.DestinationTransaction = [32]byte{} },
		"no source":                 func(c *Context, s *Source, p *Proof) { s.Commitment = [33]byte{} },
		"invalid source point":      func(c *Context, s *Source, p *Proof) { s.Commitment = [33]byte{2} },
		"noncanonical source point": func(c *Context, s *Source, p *Proof) { s.Commitment[0] = 4 },
		"no address":                func(c *Context, s *Source, p *Proof) { s.Address = "" },
		"other owner": func(c *Context, s *Source, p *Proof) {
			raw := make([]byte, 32)
			raw[31] = 2
			p.PublicKeyBase64 = base64.StdEncoding.EncodeToString(secp.PrivKeyFromBytes(raw).PubKey().SerializeUncompressed())
		},
		"multisig unsupported": func(c *Context, s *Source, p *Proof) { s.Address = "M" + s.Address[1:] },
		"no key":               func(c *Context, s *Source, p *Proof) { p.PublicKeyBase64 = "" },
		"no signature":         func(c *Context, s *Source, p *Proof) { p.SignatureBase64 = "" },
		"newline key":          func(c *Context, s *Source, p *Proof) { p.PublicKeyBase64 += "\n" },
		"newline signature":    func(c *Context, s *Source, p *Proof) { p.SignatureBase64 += "\n" },
		"off curve key": func(c *Context, s *Source, p *Proof) {
			raw := make([]byte, 65)
			raw[0] = 4
			p.PublicKeyBase64 = base64.StdEncoding.EncodeToString(raw)
		},
		"compressed key": func(c *Context, s *Source, p *Proof) {
			raw, _ := base64.StdEncoding.DecodeString(p.PublicKeyBase64)
			pub, _ := secp.ParsePubKey(raw)
			p.PublicKeyBase64 = base64.StdEncoding.EncodeToString(pub.SerializeCompressed())
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			c, s, p := ctx, source, proof
			mutate(&c, &s, &p)
			if err := Verify(c, s, p); err == nil {
				t.Fatal("accepted invalid claim")
			}
		})
	}
}

func TestStrictDERAndLowS(t *testing.T) {
	ctx, source, proof := fixture(t)
	raw, _ := base64.StdEncoding.DecodeString(proof.SignatureBase64)
	var valid struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(raw, &valid); err != nil {
		t.Fatal(err)
	}
	n := secp.Params().N
	for name, pair := range map[string]struct{ R, S *big.Int }{
		"high-S": {valid.R, new(big.Int).Sub(n, valid.S)},
		"zero R": {big.NewInt(0), valid.S}, "zero S": {valid.R, big.NewInt(0)},
		"negative R": {big.NewInt(-1), valid.S}, "negative S": {valid.R, big.NewInt(-1)},
		"overflow R": {n, valid.S}, "overflow S": {valid.R, n},
		"wrong signature": {big.NewInt(1), big.NewInt(1)},
	} {
		t.Run(name, func(t *testing.T) {
			der, err := asn1.Marshal(pair)
			if err != nil {
				t.Fatal(err)
			}
			p := proof
			p.SignatureBase64 = base64.StdEncoding.EncodeToString(der)
			if Verify(ctx, source, p) == nil {
				t.Fatal("accepted invalid signature")
			}
		})
	}
	for name, der := range map[string][]byte{"trailing bytes": append(append([]byte{}, raw...), 0), "truncated": raw[:len(raw)-1], "redundant integer padding": {0x30, 7, 2, 2, 0, 1, 2, 1, 1}} {
		t.Run(name, func(t *testing.T) {
			p := proof
			p.SignatureBase64 = base64.StdEncoding.EncodeToString(der)
			if Verify(ctx, source, p) == nil {
				t.Fatal("accepted malformed DER")
			}
		})
	}
}

func TestCanonicalBase64PadBits(t *testing.T) {
	ctx, source, proof := fixture(t)
	// A non-zero unused bit in the final public-key sextet decodes identically
	// with permissive decoders, but must not change an address preimage here.
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	p := proof
	for i, c := range alphabet {
		if byte(c) == p.PublicKeyBase64[86] {
			p.PublicKeyBase64 = p.PublicKeyBase64[:86] + string(alphabet[i+1]) + "="
			break
		}
	}
	if Verify(ctx, source, p) == nil {
		t.Fatal("accepted noncanonical pad bits")
	}
}
