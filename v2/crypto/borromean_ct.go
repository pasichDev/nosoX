package crypto

// Constant-time Borromean range-proof prover.
//
// The original prover in borromean.go uses `math/big` and
// `elliptic.Curve.ScalarBaseMult` whose timing correlates with the
// secret bit value and per-bit blinding factor r_i. This file mirrors
// the construction using decred's `secp256k1.ModNScalar` for scalar
// arithmetic and `secp256k1.PrivateKey.PubKey()` for the secret
// fixed-base multiplication, both of which are designed for
// constant-time execution.
//
// Fake-branch math (where the prover chose the scalars themselves)
// stays variable-time because it leaks nothing about the secret r.
//
// Verifier remains in borromean.go — its inputs are entirely public.

import (
	"crypto/rand"
	"errors"
	"math/big"
	"sync"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// twoTo63InvCT and generatorHCT are lazily computed because their
// derivation depends on `generatorH` which is initialized in
// `pedersen.go`. Go runs init() in file-alphabetic order within a
// package; `borromean_ct.go` precedes `pedersen.go`, so a plain init()
// here would see a nil generatorH.
var (
	ctOnce       sync.Once
	twoTo63InvCT secp.ModNScalar
	generatorHCT *secp.PublicKey
)

func ensureCTConstants() {
	ctOnce.Do(func() {
		// Inverse of 2^63 mod n.
		var twoTo63 big.Int
		twoTo63.Lsh(big.NewInt(1), 63)
		var inv big.Int
		if inv.ModInverse(&twoTo63, Curve().Params().N) == nil {
			panic("borromean_ct: 2^63 has no inverse mod n")
		}
		var buf [32]byte
		invBytes := inv.Bytes()
		copy(buf[32-len(invBytes):], invBytes)
		twoTo63InvCT.SetBytes(&buf)

		// Parse H from its compressed encoding.
		hComp := compress(generatorH.X(), generatorH.Y())
		pub, err := secp.ParsePubKey(hComp[:])
		if err != nil {
			panic("borromean_ct: cannot parse generator H: " + err.Error())
		}
		generatorHCT = pub
	})
}

// ProveRangeBorromeanCT is the constant-time variant of
// ProveRangeBorromean. Produces wire-identical output (same proof
// structure) so existing verifiers accept it as-is.
func ProveRangeBorromeanCT(commit [33]byte, blinding []byte, value int64) ([]byte, error) {
	ensureCTConstants()
	if value < 0 {
		return nil, errors.New("rangeproof: negative value")
	}
	if len(blinding) != 32 {
		return nil, errors.New("rangeproof: blinding must be 32 bytes")
	}

	// Per-bit blinding factors as ModNScalar.
	var rs [rangeBits]secp.ModNScalar
	var rSum secp.ModNScalar
	for i := 0; i < rangeBits-1; i++ {
		if err := sampleScalarCT(&rs[i]); err != nil {
			return nil, err
		}
		var twoI secp.ModNScalar
		scalarSetUint64CT(&twoI, uint64(1)<<uint(i))
		var weighted secp.ModNScalar
		weighted.Mul2(&rs[i], &twoI)
		rSum.Add(&weighted)
	}
	// r[63] = (rTotal - rSum) * (2^63)^-1 mod n.
	var rTotal secp.ModNScalar
	var rTotalBuf [32]byte
	copy(rTotalBuf[:], blinding)
	rTotal.SetBytes(&rTotalBuf)
	var negRSum secp.ModNScalar
	negRSum.Set(&rSum).Negate()
	var diff secp.ModNScalar
	diff.Set(&rTotal).Add(&negRSum)
	rs[rangeBits-1].Mul2(&diff, &twoTo63InvCT)

	uv := uint64(value)
	commits := make([][33]byte, rangeBits)
	orProofs := make([][]byte, rangeBits)
	for i := 0; i < rangeBits; i++ {
		bit := (uv >> uint(i)) & 1
		// C_i = bit·H + r_i·G.
		rBytesArr := rs[i].Bytes()
		C, err := PedersenCommit(int64(bit), rBytesArr[:])
		if err != nil {
			return nil, err
		}
		commits[i] = C
		orProofs[i], err = bitOrProveCT(C, &rs[i], bit == 1)
		if err != nil {
			return nil, err
		}
	}

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

// bitOrProveCT is the constant-time variant of bitOrProve. Wire output
// matches bitOrProve so verifiers don't need to change.
func bitOrProveCT(C [33]byte, r *secp.ModNScalar, bit bool) ([]byte, error) {
	// Three random scalars: real-branch nonce, fake-branch challenge, fake response.
	var k, eFake, sFake secp.ModNScalar
	if err := sampleScalarCT(&k); err != nil {
		return nil, err
	}
	if err := sampleScalarCT(&eFake); err != nil {
		return nil, err
	}
	if err := sampleScalarCT(&sFake); err != nil {
		return nil, err
	}

	// Real branch: T_real = k·G via constant-time PrivateKey.PubKey().
	kPriv := secp.NewPrivateKey(&k)
	tRealCompressed := kPriv.PubKey().SerializeCompressed()
	var TReal [33]byte
	copy(TReal[:], tRealCompressed)

	// Fake branch target depends on which branch is fake (opposite of bit).
	//   bit=0 → fake branch is "1" → target = C − H
	//   bit=1 → fake branch is "0" → target = C
	cPub, err := secp.ParsePubKey(C[:])
	if err != nil {
		return nil, err
	}
	var targetFake *secp.PublicKey
	if !bit {
		hCompressed := generatorHCT.SerializeCompressed()
		var hArr [33]byte
		copy(hArr[:], hCompressed)
		cMinusH, err := PointSubtract(C, hArr)
		if err != nil {
			return nil, err
		}
		targetFake, err = secp.ParsePubKey(cMinusH[:])
		if err != nil {
			return nil, err
		}
	} else {
		targetFake = cPub
	}

	// T_fake = sFake·G − eFake·targetFake.
	// Both scalars (sFake, eFake) are sampled by the prover, so the
	// remaining variable-time arithmetic on them leaks nothing about r
	// or about the bit value.
	tFake, err := pointAddVT(
		scalarTimesG(&sFake),
		scalarTimesPointNeg(&eFake, targetFake),
	)
	if err != nil {
		return nil, err
	}
	tFakeCompressed := tFake.SerializeCompressed()
	var TFake [33]byte
	copy(TFake[:], tFakeCompressed)

	// Slot T_real and T_fake into T0/T1 based on bit value.
	var T0, T1 [33]byte
	if !bit {
		T0 = TReal
		T1 = TFake
	} else {
		T0 = TFake
		T1 = TReal
	}

	// e_total = H(C || T0 || T1) mod n.
	eHash := orChallenge(C, T0, T1)
	var eTotal secp.ModNScalar
	var eBuf [32]byte
	eBytes := eHash.Bytes()
	copy(eBuf[32-len(eBytes):], eBytes)
	eTotal.SetBytes(&eBuf)

	// Real branch derives its own challenge from eTotal − eFake.
	var negEFake secp.ModNScalar
	negEFake.Set(&eFake).Negate()
	var eReal secp.ModNScalar
	eReal.Set(&eTotal).Add(&negEFake)

	// s_real = k + e_real·r (constant-time Mul + Add on ModNScalar).
	var eRealR secp.ModNScalar
	eRealR.Mul2(&eReal, r)
	var sReal secp.ModNScalar
	sReal.Set(&k).Add(&eRealR)

	// Assemble (e0, e1, s0, s1) according to bit.
	var e0, e1, s0, s1 secp.ModNScalar
	if !bit {
		e0.Set(&eReal)
		e1.Set(&eFake)
		s0.Set(&sReal)
		s1.Set(&sFake)
	} else {
		e0.Set(&eFake)
		e1.Set(&eReal)
		s0.Set(&sFake)
		s1.Set(&sReal)
	}

	// Wire format: T0 || T1 || e0 || e1 || s0 || s1.
	out := make([]byte, 0, orProofSize)
	out = append(out, T0[:]...)
	out = append(out, T1[:]...)
	e0Arr := e0.Bytes()
	e1Arr := e1.Bytes()
	s0Arr := s0.Bytes()
	s1Arr := s1.Bytes()
	out = append(out, e0Arr[:]...)
	out = append(out, e1Arr[:]...)
	out = append(out, s0Arr[:]...)
	out = append(out, s1Arr[:]...)
	return out, nil
}

// ---- helpers --------------------------------------------------------

func sampleScalarCT(out *secp.ModNScalar) error {
	for tries := 0; tries < 16; tries++ {
		var b [32]byte
		if _, err := rand.Read(b[:]); err != nil {
			return err
		}
		if overflow := out.SetBytes(&b); overflow == 0 && !out.IsZero() {
			return nil
		}
	}
	return errors.New("rangeproof: scalar sample rejection failed")
}

func scalarSetUint64CT(out *secp.ModNScalar, v uint64) {
	var b [32]byte
	b[24] = byte(v >> 56)
	b[25] = byte(v >> 48)
	b[26] = byte(v >> 40)
	b[27] = byte(v >> 32)
	b[28] = byte(v >> 24)
	b[29] = byte(v >> 16)
	b[30] = byte(v >> 8)
	b[31] = byte(v)
	out.SetBytes(&b)
}

// scalarTimesG returns s·G via PrivateKey.PubKey() (constant-time
// fixed-base mul).
func scalarTimesG(s *secp.ModNScalar) *secp.PublicKey {
	// Clone s into a fresh ModNScalar to avoid the constructor's
	// "we own this pointer" semantics.
	var clone secp.ModNScalar
	clone.Set(s)
	priv := secp.NewPrivateKey(&clone)
	return priv.PubKey()
}

// scalarTimesPointNeg returns (−s)·P using variable-time arithmetic
// (the scalar is public to the prover, so this is safe).
func scalarTimesPointNeg(s *secp.ModNScalar, p *secp.PublicKey) *secp.PublicKey {
	// Negate s into a fresh scalar.
	var negS secp.ModNScalar
	negS.Set(s).Negate()
	// Compute negS·P with ScalarMultNonConst.
	var pj, result secp.JacobianPoint
	p.AsJacobian(&pj)
	secp.ScalarMultNonConst(&negS, &pj, &result)
	result.ToAffine()
	return secp.NewPublicKey(&result.X, &result.Y)
}

// pointAddVT adds two public keys via variable-time Jacobian add.
// Safe for fake-branch math.
func pointAddVT(a, b *secp.PublicKey) (*secp.PublicKey, error) {
	var aj, bj, result secp.JacobianPoint
	a.AsJacobian(&aj)
	b.AsJacobian(&bj)
	secp.AddNonConst(&aj, &bj, &result)
	result.ToAffine()
	return secp.NewPublicKey(&result.X, &result.Y), nil
}
