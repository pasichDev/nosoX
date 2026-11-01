package mempool

import (
	"errors"
	"github.com/pasichDev/nosoX/v2/types"
	"testing"
)

func TestPoolRejectsUnvalidated(t *testing.T) {
	p := New(2)
	if _, err := p.Add(mkTx(1)); err == nil {
		t.Fatal("unvalidated transaction admitted")
	}
}
func TestPoolRejectsNil(t *testing.T) {
	defer func() {
		if p := recover(); p != nil {
			t.Fatalf("nil panicked: %v", p)
		}
	}()
	if _, e := New(2).Add(nil); e == nil {
		t.Fatal("nil accepted")
	}
}
func TestTxIDBindsFullBody(t *testing.T) {
	a := mkTx(1)
	b := mkTx(1)
	b.Outputs = []types.Output{{RangeProof: []byte{1}}}
	if TxID(a) == TxID(b) {
		t.Fatal("distinct transaction bodies share id")
	}
}

// These tests isolate pool ownership; production uses Chain.ValidateTransaction.
func TestPoolOwnsTransactions(t *testing.T) {
	p := NewValidated(2, func(*types.Transaction) error { return nil })
	tx := mkTx(2)
	tx.Outputs = []types.Output{{RangeProof: []byte{3}}}
	_, err := p.Add(tx)
	if err != nil {
		t.Fatal(err)
	}
	tx.Outputs[0].RangeProof[0] = 4
	tx.Kernels[0].Fee = 9
	snap := p.Snapshot()
	if snap[0].Outputs[0].RangeProof[0] != 3 || snap[0].Kernels[0].Fee != 2 {
		t.Fatal("caller mutated pool")
	}
	snap[0].Outputs[0].RangeProof[0] = 8
	if p.Snapshot()[0].Outputs[0].RangeProof[0] != 3 {
		t.Fatal("snapshot mutated pool")
	}
}
func TestPoolRejectsConflictingInputs(t *testing.T) {
	p := NewValidated(4, func(*types.Transaction) error { return nil })
	a, b := mkTx(2), mkTx(1)
	a.Inputs = []types.Input{{Commit: types.Commitment{1}}}
	b.Inputs = a.Inputs
	if _, e := p.Add(a); e != nil {
		t.Fatal(e)
	}
	if _, e := p.Add(b); !errors.Is(e, ErrConflict) {
		t.Fatalf("lower-paying conflicting spend: %v", e)
	}
}

// Structural admission uses a stub only to isolate the byte-accounting boundary;
// successful admission here makes no claim about ownership validation.
func TestPoolByteBudgetAndRemoval(t *testing.T) {
	p := NewValidated(2, func(*types.Transaction) error { return nil })
	tx := mkTx(1)
	tx.Inputs = []types.Input{{Commit: types.Commitment{1}}}
	tx.Outputs = []types.Output{{RangeProof: make([]byte, types.MaxRangeProofBytes)}}
	id, err := p.Add(tx)
	if err != nil {
		t.Fatal(err)
	}
	if p.bytes < 64+types.MaxRangeProofBytes {
		t.Fatal("input and proof bytes not charged")
	}
	p.Remove(id)
	if p.bytes != 0 {
		t.Fatalf("byte charge leaked after removal: %d", p.bytes)
	}
	tx.Outputs[0].RangeProof = append(tx.Outputs[0].RangeProof, 0)
	if _, err := p.Add(tx); err == nil {
		t.Fatal("oversized range proof admitted")
	}
	if p.bytes != 0 || len(p.entries) != 0 {
		t.Fatal("failed admission changed pool")
	}
}
