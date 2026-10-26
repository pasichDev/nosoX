package blockchain

import (
	"github.com/pasichDev/noso-go/internal/crypto"
	"testing"
)

func TestOrderBindsOwnerKey(t *testing.T) {
	attacker, _ := crypto.GenerateKeyPair()
	victim, _ := crypto.GenerateKeyPair()
	addr, _ := crypto.AddressFromPublicKey(victim.PublicKey, crypto.AddressTypeRegular)
	// The signed payload names a victim while signer controls another key.
	o, err := NewTransferOrder(Sender{Hash: addr, PublicKey: attacker.PublicKey, PrivateKey: attacker.PrivateKey}, addr, 1, "", 1700000000, 1)
	if err == nil && VerifyOrder(o) {
		t.Fatal("attacker signed for unrelated address")
	}
}
