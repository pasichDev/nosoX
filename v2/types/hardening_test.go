package types

import "testing"

func TestOutputIdentityBindsProof(t *testing.T) {
	a := Output{RangeProof: []byte{1, 2, 3}}
	b := a
	b.RangeProof = []byte{1, 2, 4}
	if OutputID(&a) == OutputID(&b) {
		t.Fatal("proof mutation preserves output identity")
	}
}

func TestOutputIdentityBindsAllMetadata(t *testing.T) {
	a := Output{Features: OutputFeaturesPlain}
	b := a
	b.LegacyAddress = "ignored"
	if OutputID(&a) == OutputID(&b) {
		t.Fatal("metadata mutation preserves output identity")
	}
}

func TestBodyCommitmentsBindEveryField(t *testing.T) {
	original := func() *Block { return &Block{Inputs: []Input{{}}, Outputs: []Output{{}}, Kernels: []Kernel{{}}} }
	mutations := []func(*Block){
		func(b *Block) { b.Inputs[0].Commit[1]++ },
		func(b *Block) { b.Inputs[0].Features++ },
		func(b *Block) { b.Inputs[0].LegacySig = "s" },
		func(b *Block) { b.Inputs[0].LegacyAddr = "a" },
		func(b *Block) { b.Inputs[0].LegacyAmount++ },
		func(b *Block) { b.Outputs[0].Commit[1]++ },
		func(b *Block) { b.Outputs[0].Features++ },
		func(b *Block) { b.Outputs[0].RangeProof = []byte{1} },
		func(b *Block) { b.Outputs[0].LegacyAddress = "a" },
		func(b *Block) { b.Outputs[0].LegacyAmount++ },
		func(b *Block) { b.Outputs[0].GVTNumber++ },
		func(b *Block) { b.Kernels[0].Features++ },
		func(b *Block) { b.Kernels[0].Fee++ },
		func(b *Block) { b.Kernels[0].LockHeight++ },
		func(b *Block) { b.Kernels[0].Excess[1]++ },
		func(b *Block) { b.Kernels[0].ExcessSig = []byte{1} },
		func(b *Block) { b.Outputs = append(b.Outputs, b.Outputs[0]) },
		func(b *Block) { b.Inputs = append(b.Inputs, b.Inputs[0]) },
		func(b *Block) { b.Kernels = append(b.Kernels, b.Kernels[0]) },
	}
	a, b := BlockRoots(original())
	for i, mutate := range mutations {
		block := original()
		mutate(block)
		x, y := BlockRoots(block)
		if a == x && b == y {
			t.Errorf("mutation %d not bound", i)
		}
	}
}

func FuzzTransactionEncoding(f *testing.F) {
	f.Add([]byte("x"), []byte("yz"))
	f.Fuzz(func(t *testing.T, a, b []byte) {
		if len(a) > 4096 || len(b) > 4096 {
			t.Skip()
		}
		x := Transaction{Inputs: []Input{{LegacySig: string(a), LegacyAddr: string(b)}}}
		y := Transaction{Inputs: []Input{{LegacySig: string(append(append([]byte{}, a...), 0)), LegacyAddr: string(b)}}}
		if TransactionID(&x) == TransactionID(&y) {
			t.Fatal("length-delimiting collision")
		}
		if TransactionID(&x) != TransactionID(&x) {
			t.Fatal("nondeterministic")
		}
	})
}

func TestIssuanceScheduleIndependentSum(t *testing.T) {
	// Independent closed-form total versus every public BlockReward result.
	// This is arithmetic verification, not a 2.31-million-block network test.
	var got int64
	end := BlockHalvingInterval * (HalvingSteps + 1)
	for h := uint64(1); h <= end; h++ {
		got += BlockReward(h)
	}
	want := (int64(BlockHalvingInterval) - 1) * InitialReward
	for era := uint64(1); era <= HalvingSteps; era++ {
		want += int64(BlockHalvingInterval) * (InitialReward >> era)
	}
	if got != want {
		t.Fatalf("issued sum %d != independent era sum %d", got, want)
	}
	for _, h := range []uint64{0, end, end + 1, ^uint64(0)} {
		if BlockReward(h) != 0 {
			t.Fatalf("unauthorized subsidy at %d", h)
		}
	}
}
