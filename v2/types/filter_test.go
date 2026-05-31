package types

import (
	"crypto/rand"
	"testing"
)

func TestCompactFilterPositive(t *testing.T) {
	b := &Block{
		Header: BlockHeader{Height: 42},
		Outputs: []Output{
			{Features: OutputFeaturesLegacy, Commit: [33]byte{0, 1, 2, 3}, LegacyAddress: "Nfoo"},
			{Features: OutputFeaturesPlain, Commit: [33]byte{4, 5, 6, 7}},
		},
	}
	f := BuildFilter(b)
	if !f.MatchBytes([]byte("Nfoo")) {
		t.Error("filter missed legacy address it contains")
	}
	commit := [33]byte{4, 5, 6, 7}
	if !f.MatchBytes(commit[:]) {
		t.Error("filter missed commit it contains")
	}
}

func TestCompactFilterFalsePositiveRateBounded(t *testing.T) {
	// Inserting a handful of items, the false-positive rate against
	// random queries should stay below 5%.
	b := &Block{}
	for i := 0; i < 20; i++ {
		var c [33]byte
		rand.Read(c[:])
		b.Outputs = append(b.Outputs, Output{Commit: c})
	}
	f := BuildFilter(b)
	hits, total := 0, 1000
	for i := 0; i < total; i++ {
		var q [33]byte
		rand.Read(q[:])
		if f.MatchBytes(q[:]) {
			hits++
		}
	}
	if hits*20 > total { // > 5%
		t.Errorf("false-positive rate %d/%d above 5%%", hits, total)
	}
}
