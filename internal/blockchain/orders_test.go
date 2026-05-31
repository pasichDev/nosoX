package blockchain

import (
	"testing"

	"github.com/noso-project/noso-go/internal/crypto"
)

func TestTransferOrderRoundTrip(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	addr, err := crypto.AddressFromPublicKey(kp.PublicKey, crypto.AddressTypeRegular)
	if err != nil {
		t.Fatal(err)
	}
	receiverKP, _ := crypto.GenerateKeyPair()
	receiver, _ := crypto.AddressFromPublicKey(receiverKP.PublicKey, crypto.AddressTypeRegular)

	s := Sender{Hash: addr, PublicKey: kp.PublicKey, PrivateKey: kp.PrivateKey}
	order, err := NewTransferOrder(s, receiver, 1_000_000_000, "hello", 1_700_000_000, 60_000)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyOrder(order) {
		t.Fatalf("freshly built order failed to verify\n%+v", order)
	}
	// Tamper with the amount; verification must fail.
	order.AmmountTrf++
	if VerifyOrder(order) {
		t.Fatal("verification accepted tampered amount")
	}
}

func TestCustomOrderRoundTrip(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()
	addr, _ := crypto.AddressFromPublicKey(kp.PublicKey, crypto.AddressTypeRegular)
	s := Sender{Hash: addr, PublicKey: kp.PublicKey, PrivateKey: kp.PrivateKey}
	order, err := NewCustomOrder(s, "myalias", 1_700_000_000, 200_000)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyOrder(order) {
		t.Fatal("custom order failed to verify")
	}
	if order.AmmountFee != CustomizationFeeLate {
		t.Errorf("late-era custom fee = %d, want %d", order.AmmountFee, CustomizationFeeLate)
	}
	// Early-era order.
	early, _ := NewCustomOrder(s, "alias", 1_700_000_000, 100_000)
	if early.AmmountFee != CustomizationFeeEarly {
		t.Errorf("early-era custom fee = %d, want %d", early.AmmountFee, CustomizationFeeEarly)
	}
}
