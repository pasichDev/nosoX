package types

import (
	"crypto/sha256"
	"encoding/binary"
)

// appendField length-delimits every variable-width field. uint64 lengths avoid
// truncation even for in-memory objects; network and validation impose bounds.
func appendField(dst, field []byte) []byte {
	dst = binary.BigEndian.AppendUint64(dst, uint64(len(field)))
	return append(dst, field...)
}

func encodeInput(in *Input) []byte {
	b := []byte{byte(in.Features)}
	b = append(b, in.Commit[:]...)
	b = appendField(b, []byte(in.LegacySig))
	b = appendField(b, []byte(in.LegacyAddr))
	b = binary.BigEndian.AppendUint64(b, uint64(in.LegacyAmount))
	b = appendField(b, []byte(in.LegacyPubKey))
	b = append(b, in.LegacyOutputID[:]...)
	return append(b, in.LegacyKernelID[:]...)
}

func encodeInputsKernels(inputs []Input, kernels []Kernel) []byte {
	b := binary.BigEndian.AppendUint64(nil, uint64(len(inputs)))
	for i := range inputs {
		b = appendField(b, encodeInput(&inputs[i]))
	}
	b = binary.BigEndian.AppendUint64(b, uint64(len(kernels)))
	for i := range kernels {
		b = appendField(b, EncodeKernel(&kernels[i]))
		b = appendField(b, kernels[i].ExcessSig)
	}
	return b
}

func encodeOutputs(outputs []Output) []byte {
	b := binary.BigEndian.AppendUint64(nil, uint64(len(outputs)))
	for i := range outputs {
		b = appendField(b, EncodeOutput(&outputs[i]))
	}
	return b
}

// BlockRoots commits to the entire ordered body, including input authorization
// metadata, proofs and signatures. These v4 roots replace the incomplete v1
// duplicate-last Merkle trees. Counts prevent list-length ambiguity.
func BlockRoots(b *Block) (Hash, Hash) {
	o := append([]byte("NosoX/block/outputs/v4\x00"), encodeOutputs(b.Outputs)...)
	k := append([]byte("NosoX/block/inputs-kernels/v4\x00"), encodeInputsKernels(b.Inputs, b.Kernels)...)
	return sha256.Sum256(o), sha256.Sum256(k)
}

func SetBlockRoots(b *Block) { b.Header.OutputRoot, b.Header.KernelRoot = BlockRoots(b) }

// EncodeTransaction binds every transaction field. KernelID intentionally
// excludes its signature, because it is itself the kernel signing message.
func EncodeTransaction(tx *Transaction) []byte {
	b := []byte("NosoX/transaction/v4\x00")
	b = appendField(b, encodeInputsKernels(tx.Inputs, tx.Kernels))
	return appendField(b, encodeOutputs(tx.Outputs))
}
func TransactionID(tx *Transaction) Hash { return sha256.Sum256(EncodeTransaction(tx)) }
