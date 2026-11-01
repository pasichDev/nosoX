package wallet

import (
	"testing"

	v2crypto "github.com/pasichDev/nosoX/v2/crypto"
	"github.com/pasichDev/nosoX/v2/types"
)

func TestNewPlainOutputIsOpenableAndProven(t *testing.T) {
	const value = int64(1_000_000_000)
	out, err := NewPlainOutput(value)
	if err != nil {
		t.Fatal(err)
	}
	if out.Value != value || out.Output.Features != types.OutputFeaturesPlain {
		t.Fatalf("unexpected output: value=%d features=%d", out.Value, out.Output.Features)
	}
	// The stored blinding factor must open the commitment to the stated value.
	opened, err := v2crypto.PedersenCommit(value, out.Blinding[:])
	if err != nil {
		t.Fatal(err)
	}
	if types.Commitment(opened) != out.Output.Commit {
		t.Fatal("blinding factor does not open the commitment")
	}
	if !v2crypto.VerifyRange(out.Output.Commit, out.Output.RangeProof) {
		t.Fatal("range proof fails to verify")
	}
	// A proof is bound to its commitment.
	other, err := NewPlainOutput(value)
	if err != nil {
		t.Fatal(err)
	}
	if v2crypto.VerifyRange(other.Output.Commit, out.Output.RangeProof) {
		t.Fatal("range proof verifies against a different commitment")
	}
	if out.Blinding == other.Blinding {
		t.Fatal("blinding factors repeat")
	}
}

func TestNewPlainOutputRejectsNegativeValue(t *testing.T) {
	if _, err := NewPlainOutput(-1); err == nil {
		t.Fatal("negative value accepted")
	}
}
