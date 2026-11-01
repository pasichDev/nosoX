package chain

import (
	"github.com/pasichDev/nosoX/v2/types"
	"testing"
)

func TestSecurityMissingCoinbaseRejected(t *testing.T) {
	c := NewMemory()
	g := easyGenesisBlock(t)
	if err := c.LoadOrInit(t.TempDir(), g); err != nil {
		t.Fatal(err)
	}
	b := mineEasy(types.HeaderID(&g.Header), 1)
	b.Outputs = nil
	b.Kernels = nil
	types.SetBlockRoots(b)
	if err := c.AddBlock(b); err == nil {
		t.Fatal("accepted block without subsidy output/kernel/signature")
	}
}

func TestSecurityStoredBlocksAreImmutable(t *testing.T) {
	c := NewMemory()
	g := easyGenesisBlock(t)
	if err := c.LoadOrInit(t.TempDir(), g); err != nil {
		t.Fatal(err)
	}
	want, _ := c.Tip()
	g.Header.Nonce++
	got, _ := c.Tip()
	if got != want {
		t.Fatal("caller mutation rewrote accepted genesis")
	}
	b, _ := c.BlockByHeight(0)
	b.Header.Nonce++
	got, _ = c.Tip()
	if got != want {
		t.Fatal("getter mutation rewrote accepted history")
	}
}

func TestSecurityReopenPinsGenesis(t *testing.T) {
	dir := t.TempDir()
	c := NewMemory()
	g := easyGenesisBlock(t)
	if err := c.LoadOrInit(dir, g); err != nil {
		t.Fatal(err)
	}
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	other := *g
	other.Header.Nonce++
	if err := NewMemory().LoadOrInit(dir, &other); err == nil {
		t.Fatal("reopened state under a different trusted genesis")
	}
}
