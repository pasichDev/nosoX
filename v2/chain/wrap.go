package chain

import "github.com/noso-project/noso-go/v2/types"

// HasUTXOByCommitWrap is a public, mutex-protected wrapper so the RPC
// layer can probe the UTXO set without leaking the internal Store
// interface. Mirrors LookupLegacyBalance's design.
func (c *Chain) HasUTXOByCommitWrap(commit types.Commitment) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.store.HasUTXO(commit)
}
