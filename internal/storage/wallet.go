package storage

import (
	"errors"
	"os"

	"github.com/noso-project/noso-go/internal/types"
)

// LoadWallet reads every WalletData record from path and returns them in
// file order. Returns an empty slice (not an error) if the file does not
// exist — Pascal treats a missing wallet as "fresh wallet to be created".
func LoadWallet(path string) ([]types.WalletData, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	count, err := recordCount("wallet.pkw", data, types.WalletRecordSize)
	if err != nil {
		return nil, err
	}
	out := make([]types.WalletData, 0, count)
	for i := 0; i < count; i++ {
		var w types.WalletData
		if !w.Unmarshal(data[i*types.WalletRecordSize : (i+1)*types.WalletRecordSize]) {
			return nil, errors.New("storage: wallet.pkw record unmarshal failed")
		}
		out = append(out, w)
	}
	return out, nil
}

// SaveWallet writes records atomically to path. As an extra safety net
// (matching the Pascal behavior at `nosowallcon.pas:278-306`), it also
// copies the resulting file to path+".bak" once the rename has succeeded.
//
// The on-wire bytes are byte-identical to what the Pascal node would
// produce.
func SaveWallet(path string, records []types.WalletData) error {
	buf := make([]byte, 0, len(records)*types.WalletRecordSize)
	for i := range records {
		buf = append(buf, records[i].Marshal()...)
	}
	if err := atomicWriteFile(path, buf); err != nil {
		return err
	}
	// Best-effort backup; do not fail the save if the .bak write errors,
	// since the primary file is already written safely.
	_ = atomicWriteFile(path+".bak", buf)
	return nil
}
