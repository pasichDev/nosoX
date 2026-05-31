package crypto

import (
	"strings"
	"testing"
)

func TestBaseAlphabets(t *testing.T) {
	if len(AlphabetB58) != 58 {
		t.Fatalf("B58 alphabet len = %d", len(AlphabetB58))
	}
	if len(AlphabetB36) != 36 {
		t.Fatalf("B36 alphabet len = %d", len(AlphabetB36))
	}
	for _, c := range "0OIl" {
		if strings.ContainsRune(AlphabetB58, c) {
			t.Fatalf("B58 alphabet must not contain %q", c)
		}
	}
}

func TestAddressDerivationStable(t *testing.T) {
	// We don't have a known (pubkey, address) golden pair in the source
	// tree, so we verify two things instead:
	//  1. The derivation is deterministic.
	//  2. Round-tripping a fresh key through derivation + IsValidAddress
	//     succeeds — the validation logic re-runs the checksum, so passing
	//     this round-trip exercises the checksum end-to-end.
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if !kp.IsValid() {
		t.Fatalf("generated keypair fails length check: pub=%d priv=%d",
			len(kp.PublicKey), len(kp.PrivateKey))
	}
	addr1, err := AddressFromPublicKey(kp.PublicKey, AddressTypeRegular)
	if err != nil {
		t.Fatal(err)
	}
	addr2, _ := AddressFromPublicKey(kp.PublicKey, AddressTypeRegular)
	if addr1 != addr2 {
		t.Fatalf("address derivation not deterministic: %q vs %q", addr1, addr2)
	}
	if addr1[0] != 'N' {
		t.Fatalf("regular address must start with N: %q", addr1)
	}
	if !IsValidAddress(addr1) {
		t.Fatalf("IsValidAddress rejected freshly derived %q", addr1)
	}
	// Multisig type.
	addrM, _ := AddressFromPublicKey(kp.PublicKey, AddressTypeMulti)
	if addrM[0] != 'M' {
		t.Fatalf("multisig address must start with M: %q", addrM)
	}
	if !IsValidAddress(addrM) {
		t.Fatalf("IsValidAddress rejected multisig %q", addrM)
	}
}

func TestIsValidAddressRejectsGarbage(t *testing.T) {
	bad := []string{
		"",
		"X",
		"N",
		"NshortAddress",
		"NThisLooksLikeAValidAddressButIsntCheckedCorrectly___",
	}
	for _, b := range bad {
		if IsValidAddress(b) {
			t.Errorf("IsValidAddress(%q) = true; want false", b)
		}
	}
	// Mutating a single character of a real address should invalidate it.
	kp, _ := GenerateKeyPair()
	addr, _ := AddressFromPublicKey(kp.PublicKey, AddressTypeRegular)
	mutated := addr[:5] + "x" + addr[6:]
	if IsValidAddress(mutated) {
		t.Errorf("IsValidAddress accepted mutated address %q", mutated)
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	kp, _ := GenerateKeyPair()
	msg := []byte("OWN" + "Naddress" + "1234567890")
	sig, err := SignString(msg, kp.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyString(msg, sig, kp.PublicKey) {
		t.Fatal("good signature failed to verify")
	}
	if VerifyString([]byte("tampered"), sig, kp.PublicKey) {
		t.Fatal("verify succeeded on tampered message")
	}
	other, _ := GenerateKeyPair()
	if VerifyString(msg, sig, other.PublicKey) {
		t.Fatal("verify succeeded with wrong key")
	}
}

func TestTransferAndOrderHashShape(t *testing.T) {
	th := TransferHash("hello")
	if !strings.HasPrefix(th, "tR") {
		t.Fatalf("TransferHash prefix wrong: %q", th)
	}
	oh := OrderHash("hello")
	if !strings.HasPrefix(oh, "OR") {
		t.Fatalf("OrderHash prefix wrong: %q", oh)
	}
	// Determinism.
	if TransferHash("x") != TransferHash("x") {
		t.Fatal("TransferHash not deterministic")
	}
	if OrderHash("x") != OrderHash("x") {
		t.Fatal("OrderHash not deterministic")
	}
}

func TestHashStringsAreUppercaseHex(t *testing.T) {
	for _, s := range []string{"", "x", "Noso"} {
		got := SHA256String(s)
		if len(got) != 64 || strings.ToUpper(got) != got {
			t.Fatalf("SHA256String(%q) = %q (not 64 uppercase hex chars)", s, got)
		}
		got = RIPEMD160String(s)
		if len(got) != 40 || strings.ToUpper(got) != got {
			t.Fatalf("RIPEMD160String(%q) = %q", s, got)
		}
		got = MD5String(s)
		if len(got) != 32 || strings.ToUpper(got) != got {
			t.Fatalf("MD5String(%q) = %q", s, got)
		}
	}
}

func TestGenesisAddressValidates(t *testing.T) {
	// The Noso genesis premine address, hardcoded in `nosounit.pas` and
	// referenced across the codebase. If our IsValidAddress can't accept
	// this, the port is fundamentally wrong.
	addr := "N4PeJyqj8diSXnfhxSQdLpo8ddXTaGd"
	if !IsValidAddress(addr) {
		t.Fatalf("IsValidAddress rejected genesis address %q", addr)
	}
	// And a well-known dev fund address used in PROJCT payments.
	dev := "NpryectdevepmentfundsGE"
	// We don't know the dev address is checksum-valid (it's a vanity-style
	// human label embedded in the codebase as a string), so we only assert
	// the prefix/length shape.
	if dev[0] != 'N' || len(dev) <= 20 {
		t.Fatalf("dev fund address shape unexpected: %q", dev)
	}
}

func TestB58ChecksumKnownValues(t *testing.T) {
	// Index of each character in AlphabetB58:
	// '1' -> 0, '2' -> 1, '3' -> 2, ...
	if got := B58Checksum("1"); got != 0 {
		t.Errorf("B58Checksum('1') = %d, want 0", got)
	}
	if got := B58Checksum("12"); got != 0+1 {
		t.Errorf("B58Checksum('12') = %d, want 1", got)
	}
	if got := B58Checksum("123"); got != 0+1+2 {
		t.Errorf("B58Checksum('123') = %d, want 3", got)
	}
}
