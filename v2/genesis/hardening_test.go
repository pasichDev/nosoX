package genesis

import (
	"testing"

	"github.com/pasichDev/nosoX/v2/types"
)

func TestDefaultTimestampPreservesNetworkAndDifficulty(t *testing.T) {
	cfg := Config{NetworkMagic: types.NetworkMagicTestnet, InitialDifficulty: 1}
	b, err := Build(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if b.Header.NetworkMagic != types.NetworkMagicTestnet || b.Header.Difficulty != 1 {
		t.Fatal("defaulting timestamp discarded explicit config")
	}
	if b.Header.Timestamp != Default().Timestamp {
		t.Fatal("timestamp did not default")
	}
	other := cfg
	other.NetworkMagic = types.NetworkMagicMainnet
	c, err := Build(other)
	if err != nil {
		t.Fatal(err)
	}
	if types.HeaderID(&b.Header) == types.HeaderID(&c.Header) {
		t.Fatal("network domain missing from genesis")
	}
}

func TestBuildRejectsZeroMagic(t *testing.T) {
	if b, err := Build(Config{InitialDifficulty: 1}); err == nil || b != nil {
		t.Fatalf("zero network magic must be an error, got block=%v err=%v", b != nil, err)
	}
}
