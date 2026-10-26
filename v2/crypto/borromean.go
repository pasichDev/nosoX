package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"
)

// Borromean-style range proof over 64-bit non-negative values.
//
// Structure: we decompose v = Σ_i b_i · 2^i (i=0..63) and form one
// Pedersen commitment C_i = b_i·H + r_i·G per bit. The blinding factors
// r_i are chosen so that Σ_i r_i · 2^i equals the original commit's
// blinding factor — guaranteeing Σ_i C_i · 2^i = C(v, r).
//
// For each bit we publish a non-interactive Schnorr OR-proof showing
// that C_i opens to (b=0, r_i) OR (b=1, r_i). Both branches are
// indistinguishable to a verifier; only one is real.
//
// Wire size (per output): 64·33 + 64·194 = 14528 bytes. Larger than
// Bulletproofs (~700B) but conceptually simpler and self-contained.
//
// Public API matches ProveRange / VerifyRange in rangeproof.go so a
// future Bulletproofs implementation can drop in without changes
// elsewhere in the codebase.

const (
	borromeanVersion uint8 = 2 // distinguishes the proof from SimpleRangeProof(v=1)
	rangeBits              = 64
	orProofSize            = 33 + 33 + 32 + 32 + 32 + 32 // T0, T1, e0, e1, s0, s1
)

// ProveRangeBorromean builds a Borromean range proof for value v with the
// given commitment blinding factor r. The function panics if v is
// negative; callers must ensure non-negative inputs.
func ProveRangeBorromean(commit [33]byte, blinding []byte, value int64) ([]byte, error) {
	if value < 0 {
		return nil, errors.New("rangeproof: negative value")
	}
	if len(blinding) != 32 {
		return nil, errors.New("rangeproof: blinding must be 32 bytes")
	}
	want, err := PedersenCommit(value, blinding)
	if err != nil {
		return nil, err
	}
	if want != commit || !ValidPublicPoint(commit) {
		return nil, errors.New("rangeproof: commitment does not match opening")
	}

	curve := Curve()
	n := curve.Params().N

	// Per-bit blinding factors. r_63 is chosen so Σ_i r_i · 2^i equals
	// the input blinding r.
	r := make([]*big.Int, rangeBits)
	rSum := new(big.Int)
	for i := 0; i < rangeBits-1; i++ {
		ri, err := randomScalar()
		if err != nil {
			return nil, err
		}
		r[i] = ri
		t := new(big.Int).Lsh(ri, uint(i)) // ri * 2^i
		rSum.Add(rSum, t)
	}
	// Solve for r_63: r_total = rSum + r_63 * 2^63, so r_63 = (r_total - rSum) / 2^63 (mod n).
	rTotal := new(big.Int).SetBytes(blinding)
	rTotal.Mod(rTotal, n)
	rSum.Mod(rSum, n)
	diff := new(big.Int).Sub(rTotal, rSum)
	diff.Mod(diff, n)
	twoTo63Inv := new(big.Int).ModInverse(new(big.Int).Lsh(big.NewInt(1), 63), n)
	r[rangeBits-1] = new(big.Int).Mul(diff, twoTo63Inv)
	r[rangeBits-1].Mod(r[rangeBits-1], n)

	// Sanity: r_63 must be in range. (ModInverse always exists because gcd(2^63, n) = 1 for secp256k1 N.)
	if twoTo63Inv == nil {
		return nil, errors.New("rangeproof: 2^63 has no inverse mod n (unexpected)")
	}

	uv := uint64(value)
	commits := make([][33]byte, rangeBits)
	orProofs := make([][]byte, rangeBits)
	for i := 0; i < rangeBits; i++ {
		bit := (uv >> i) & 1
		C, err := PedersenCommit(int64(bit), r[i].FillBytes(make([]byte, 32)))
		if err != nil {
			return nil, err
		}
		commits[i] = C
		orProofs[i], err = bitOrProve(C, r[i], bit == 1)
		if err != nil {
			return nil, err
		}
	}

	// Assemble proof body: version || 64 commits || 64 or-proofs.
	out := make([]byte, 0, 1+rangeBits*(33+orProofSize))
	out = append(out, borromeanVersion)
	for i := 0; i < rangeBits; i++ {
		out = append(out, commits[i][:]...)
	}
	for i := 0; i < rangeBits; i++ {
		out = append(out, orProofs[i]...)
	}
	return out, nil
}

// VerifyRangeBorromean returns whether `proof` is a valid Borromean
// range proof binding `commit` to a non-negative 64-bit value.
func VerifyRangeBorromean(commit [33]byte, proof []byte) bool {
	expected := 1 + rangeBits*(33+orProofSize)
	if len(proof) != expected || proof[0] != borromeanVersion || !ValidPublicPoint(commit) {
		return false
	}
	curve := Curve()
	commits := make([][33]byte, rangeBits)
	off := 1
	for i := 0; i < rangeBits; i++ {
		copy(commits[i][:], proof[off:off+33])
		off += 33
		if !ValidPublicPoint(commits[i]) {
			return false
		}
	}
	// Σ C_i · 2^i == commit ?
	cx, cy := big.NewInt(0), big.NewInt(0)
	for i := 0; i < rangeBits; i++ {
		bx, by, err := decompress(commits[i])
		if err != nil {
			return false
		}
		// Multiply (bx, by) by 2^i.
		scalar := new(big.Int).Lsh(big.NewInt(1), uint(i))
		px, py := curve.ScalarMult(bx, by, scalar.Bytes())
		if cx.Sign() == 0 && cy.Sign() == 0 {
			cx, cy = px, py
		} else {
			cx, cy = curve.Add(cx, cy, px, py)
		}
	}
	got := compress(cx, cy)
	if got != commit {
		return false
	}
	// Per-bit OR-proof verification.
	for i := 0; i < rangeBits; i++ {
		chunk := proof[off : off+orProofSize]
		off += orProofSize
		if !bitOrVerify(commits[i], chunk) {
			return false
		}
	}
	return true
}

// ---- single-bit OR-proof: C opens to (0, r) OR (1, r) -----------------
//
// For b=0: prover knows r s.t. C = r·G.
//   Real:   T0 = k0·G ; e = H(C||T0||T1) ; e0 = e - e1 ; s0 = k0 + e0·r
//   Fake:   pick e1, s1 random ; T1 = s1·G - e1·(C - H)
//
// For b=1: prover knows r s.t. C - H = r·G.
//   Real:   T1 = k1·G ; e = H(C||T0||T1) ; e1 = e - e0 ; s1 = k1 + e1·r
//   Fake:   pick e0, s0 random ; T0 = s0·G - e0·C

func bitOrProve(C [33]byte, r *big.Int, b bool) ([]byte, error) {
	curve := Curve()
	n := curve.Params().N

	var (
		T0, T1 [33]byte
		e0, e1 *big.Int
		s0, s1 *big.Int
	)
	cx, cy, err := decompress(C)
	if err != nil {
		return nil, err
	}
	// h := H point coordinates (constant from package init).
	hx := generatorH.X()
	hy := generatorH.Y()
	cmhx, cmhy := curve.Add(cx, cy, hx, new(big.Int).Sub(curve.Params().P, hy)) // C - H

	if !b {
		// Real branch is "0": T0 = k0·G, fake "1".
		k0, err := randomScalar()
		if err != nil {
			return nil, err
		}
		t0x, t0y := curve.ScalarBaseMult(k0.Bytes())
		T0 = compress(t0x, t0y)
		// Fake "1" branch.
		e1, err = randomScalar()
		if err != nil {
			return nil, err
		}
		s1, err = randomScalar()
		if err != nil {
			return nil, err
		}
		// T1 = s1·G - e1·(C - H)
		s1Gx, s1Gy := curve.ScalarBaseMult(s1.Bytes())
		e1CmHx, e1CmHy := curve.ScalarMult(cmhx, cmhy, e1.Bytes())
		negY := new(big.Int).Sub(curve.Params().P, e1CmHy)
		t1x, t1y := curve.Add(s1Gx, s1Gy, e1CmHx, negY)
		T1 = compress(t1x, t1y)
		// e = H(C || T0 || T1)
		e := orChallenge(C, T0, T1)
		// e0 = e - e1
		e0 = new(big.Int).Sub(e, e1)
		e0.Mod(e0, n)
		// s0 = k0 + e0·r mod n
		s0 = new(big.Int).Mul(e0, r)
		s0.Add(s0, k0)
		s0.Mod(s0, n)
	} else {
		// Real branch is "1": T1 = k1·G, fake "0".
		k1, err := randomScalar()
		if err != nil {
			return nil, err
		}
		t1x, t1y := curve.ScalarBaseMult(k1.Bytes())
		T1 = compress(t1x, t1y)
		// Fake "0" branch.
		e0, err = randomScalar()
		if err != nil {
			return nil, err
		}
		s0, err = randomScalar()
		if err != nil {
			return nil, err
		}
		// T0 = s0·G - e0·C
		s0Gx, s0Gy := curve.ScalarBaseMult(s0.Bytes())
		e0Cx, e0Cy := curve.ScalarMult(cx, cy, e0.Bytes())
		negY := new(big.Int).Sub(curve.Params().P, e0Cy)
		t0x, t0y := curve.Add(s0Gx, s0Gy, e0Cx, negY)
		T0 = compress(t0x, t0y)
		// e = H(C || T0 || T1)
		e := orChallenge(C, T0, T1)
		// e1 = e - e0
		e1 = new(big.Int).Sub(e, e0)
		e1.Mod(e1, n)
		// s1 = k1 + e1·r mod n
		s1 = new(big.Int).Mul(e1, r)
		s1.Add(s1, k1)
		s1.Mod(s1, n)
	}

	out := make([]byte, 0, orProofSize)
	out = append(out, T0[:]...)
	out = append(out, T1[:]...)
	out = append(out, padScalar(e0)...)
	out = append(out, padScalar(e1)...)
	out = append(out, padScalar(s0)...)
	out = append(out, padScalar(s1)...)
	return out, nil
}

func bitOrVerify(C [33]byte, body []byte) bool {
	if len(body) != orProofSize {
		return false
	}
	curve := Curve()
	n := curve.Params().N
	var T0, T1 [33]byte
	copy(T0[:], body[0:33])
	copy(T1[:], body[33:66])
	e0 := new(big.Int).SetBytes(body[66:98])
	e1 := new(big.Int).SetBytes(body[98:130])
	s0 := new(big.Int).SetBytes(body[130:162])
	s1 := new(big.Int).SetBytes(body[162:194])

	if !ValidPublicPoint(C) || !ValidPublicPoint(T0) || !ValidPublicPoint(T1) || e0.Cmp(n) >= 0 || e1.Cmp(n) >= 0 || s0.Cmp(n) >= 0 || s1.Cmp(n) >= 0 {
		return false
	}

	// Check e == e0 + e1 mod n.
	want := orChallenge(C, T0, T1)
	got := new(big.Int).Add(e0, e1)
	got.Mod(got, n)
	if want.Mod(want, n).Cmp(got) != 0 {
		return false
	}

	cx, cy, err := decompress(C)
	if err != nil {
		return false
	}
	hx := generatorH.X()
	hy := generatorH.Y()
	cmhx, cmhy := curve.Add(cx, cy, hx, new(big.Int).Sub(curve.Params().P, hy))

	// Check s0·G == T0 + e0·C.
	s0Gx, s0Gy := curve.ScalarBaseMult(s0.Bytes())
	e0Cx, e0Cy := curve.ScalarMult(cx, cy, e0.Bytes())
	t0x, t0y, err := decompressXY(T0)
	if err != nil {
		return false
	}
	wantX, wantY := curve.Add(t0x, t0y, e0Cx, e0Cy)
	if s0Gx.Cmp(wantX) != 0 || s0Gy.Cmp(wantY) != 0 {
		return false
	}
	// Check s1·G == T1 + e1·(C - H).
	s1Gx, s1Gy := curve.ScalarBaseMult(s1.Bytes())
	e1CmHx, e1CmHy := curve.ScalarMult(cmhx, cmhy, e1.Bytes())
	t1x, t1y, err := decompressXY(T1)
	if err != nil {
		return false
	}
	wantX, wantY = curve.Add(t1x, t1y, e1CmHx, e1CmHy)
	return s1Gx.Cmp(wantX) == 0 && s1Gy.Cmp(wantY) == 0
}

// ---- helpers ----------------------------------------------------------

func randomScalar() (*big.Int, error) {
	curve := Curve()
	for tries := 0; tries < 8; tries++ {
		var b [32]byte
		if _, err := rand.Read(b[:]); err != nil {
			return nil, err
		}
		x := new(big.Int).SetBytes(b[:])
		if x.Sign() > 0 && x.Cmp(curve.Params().N) < 0 {
			return x, nil
		}
	}
	return nil, errors.New("rangeproof: rejection sampling failed")
}

func orChallenge(C, T0, T1 [33]byte) *big.Int {
	h := sha256.New()
	h.Write([]byte("Noso-v2-Borromean"))
	h.Write(C[:])
	h.Write(T0[:])
	h.Write(T1[:])
	return new(big.Int).SetBytes(h.Sum(nil))
}

func padScalar(s *big.Int) []byte {
	b := s.Bytes()
	if len(b) >= 32 {
		return b[len(b)-32:]
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

func decompressXY(c [33]byte) (*big.Int, *big.Int, error) {
	return decompress(c)
}

// keep one binary.Size reference so the import is used by future
// wire-prefix length tweaks.
var _ = binary.LittleEndian
