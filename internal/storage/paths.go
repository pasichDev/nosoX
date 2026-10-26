// Package storage reads and writes the on-disk Noso data folder.
// Directory layout mirrors what the Pascal node creates at startup
// (`mpdisk.pas:66-85`):
//
//	NOSODATA/
//	├── BLOCKS/{N}.blk
//	│   └── DB/blocks_db.nos
//	├── LOGS/{console,eventlog,deepdeb,exceptlog}.txt
//	├── UPDATES/
//	├── SUMMARKS/{N}.bak             — periodic sumary.psk snapshots
//	│   ├── RPC/                     — RPC-created wallets backup
//	│   └── GVTS/
//	├── wallet.pkw   + .bak
//	├── sumary.psk   + sumary.zip
//	├── blchhead.nos + blchhead.zip
//	├── psos.dat
//	├── gvts.psk
//	├── masternodes.txt
//	├── nosocfg.psk                  — text, space-separated sections
//	└── advopt.txt                   — text, key-value pairs
//
// All paths in this package are relative to a configurable Root (the
// "NOSODATA" folder). The Pascal node assumes Root = `./NOSODATA`; the Go
// port lets the caller override it via cmd-line / env.
package storage

import (
	"os"
	"path/filepath"
)

// Layout owns the resolved absolute paths the rest of the package uses.
type Layout struct {
	Root         string // NOSODATA root
	BlocksDir    string // NOSODATA/BLOCKS
	BlocksDB     string // NOSODATA/BLOCKS/DB/blocks_db.nos
	LogsDir      string // NOSODATA/LOGS
	UpdatesDir   string // NOSODATA/UPDATES
	SumMarksDir  string // NOSODATA/SUMMARKS
	RPCBakDir    string // NOSODATA/SUMMARKS/RPC
	GVTSMarksDir string // NOSODATA/SUMMARKS/GVTS
	Wallet       string // NOSODATA/wallet.pkw
	WalletBak    string // NOSODATA/wallet.pkw.bak
	Summary      string // NOSODATA/sumary.psk
	SummaryZip   string // NOSODATA/sumary.zip
	Headers      string // NOSODATA/blchhead.nos
	HeadersZip   string // NOSODATA/blchhead.zip
	PSOs         string // NOSODATA/psos.dat
	GVTs         string // NOSODATA/gvts.psk
	Masternodes  string // NOSODATA/masternodes.txt
	NosoCFG      string // NOSODATA/nosocfg.psk
	AdvOpt       string // NOSODATA/advopt.txt
}

// NewLayout builds a Layout rooted at root. Pass an absolute path or
// "./NOSODATA" to match Pascal's default. The directories are NOT created
// here — call EnsureDirectories() once at node startup.
func NewLayout(root string) *Layout {
	join := func(parts ...string) string {
		return filepath.Join(append([]string{root}, parts...)...)
	}
	return &Layout{
		Root:         root,
		BlocksDir:    join("BLOCKS"),
		BlocksDB:     join("BLOCKS", "DB", "blocks_db.nos"),
		LogsDir:      join("LOGS"),
		UpdatesDir:   join("UPDATES"),
		SumMarksDir:  join("SUMMARKS"),
		RPCBakDir:    join("SUMMARKS", "RPC"),
		GVTSMarksDir: join("SUMMARKS", "GVTS"),
		Wallet:       join("wallet.pkw"),
		WalletBak:    join("wallet.pkw.bak"),
		Summary:      join("sumary.psk"),
		SummaryZip:   join("sumary.zip"),
		Headers:      join("blchhead.nos"),
		HeadersZip:   join("blchhead.zip"),
		PSOs:         join("psos.dat"),
		GVTs:         join("gvts.psk"),
		Masternodes:  join("masternodes.txt"),
		NosoCFG:      join("nosocfg.psk"),
		AdvOpt:       join("advopt.txt"),
	}
}

// EnsureDirectories creates every subdirectory the node may need. Safe to
// call multiple times. Files are NOT created — they spring into existence
// as the node operates.
func (l *Layout) EnsureDirectories() error {
	for _, d := range []string{
		l.Root, l.BlocksDir, filepath.Dir(l.BlocksDB),
		l.LogsDir, l.UpdatesDir, l.SumMarksDir,
		l.RPCBakDir, l.GVTSMarksDir,
	} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	return nil
}

// BlockPath returns the absolute path to a given block's .blk file.
func (l *Layout) BlockPath(number int64) string {
	return filepath.Join(l.BlocksDir, blockFileName(number))
}

// blockFileName returns the file name Pascal uses, which is just the
// integer-formatted number with a `.blk` suffix — no zero-padding.
func blockFileName(number int64) string {
	return formatInt64(number) + ".blk"
}
