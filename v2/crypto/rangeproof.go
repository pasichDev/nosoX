package crypto

// ProveRange constructs the project's custom bit-decomposition OR proof.
// This construction has not received an independent cryptographic review.
func ProveRange(commit [33]byte, blinding []byte, value int64) ([]byte, error) {
	return ProveRangeBorromeanCT(commit, blinding, value)
}

// VerifyRange rejects the unverifiable development version-1 shape.
// Only the exact version-2 proof encoding is supported.
func VerifyRange(commit [33]byte, proof []byte) bool {
	return VerifyRangeBorromean(commit, proof)
}
