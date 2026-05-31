package storage

import (
	"errors"
	"os"
	"strings"
)

// NosoCFG is the parsed view of `nosocfg.psk`, a single-line text file with
// space-separated sections defined in `nosonosocfg.pas:41-47`:
//
//	[0] Mode              (NORMAL | MNSONLY | ...)
//	[1] Seed nodes        ("ip;port:ip;port:...")
//	[2] NTP servers       ("host:host:...")
//	[3] Deprecated
//	[4] Deprecated
//	[5] Frozen addresses  ("addr:addr:..." or "null:")
//
// Items inside a section are colon-separated. Both top-level sections and
// inside-section lists tolerate trailing colons.
type NosoCFG struct {
	Mode     string
	Seeds    []string
	NTP      []string
	Frozen   []string
	Raw      string // original file content
	Sections []string
}

// LoadNosoCFG parses the file at path. A missing file produces an empty
// NosoCFG with default values.
func LoadNosoCFG(path string) (*NosoCFG, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return defaultCFG(), nil
		}
		return nil, err
	}
	return parseNosoCFG(string(data)), nil
}

func defaultCFG() *NosoCFG {
	return &NosoCFG{Mode: "NORMAL"}
}

func parseNosoCFG(raw string) *NosoCFG {
	cfg := &NosoCFG{Raw: raw}
	trimmed := strings.TrimRight(raw, "\r\n ")
	sections := strings.Split(trimmed, " ")
	cfg.Sections = sections
	if len(sections) > 0 {
		cfg.Mode = sections[0]
	}
	if cfg.Mode == "" {
		cfg.Mode = "NORMAL"
	}
	if len(sections) > 1 {
		cfg.Seeds = splitColons(sections[1])
	}
	if len(sections) > 2 {
		cfg.NTP = splitColons(sections[2])
	}
	if len(sections) > 5 {
		cfg.Frozen = splitColons(sections[5])
	}
	return cfg
}

// splitColons mirrors the trivial Pascal parser: split by ':' and discard
// trailing empty tokens (the file conventionally ends with a colon).
func splitColons(s string) []string {
	parts := strings.Split(s, ":")
	out := parts[:0]
	for _, p := range parts {
		if p == "" || p == "null" {
			continue
		}
		out = append(out, p)
	}
	return out
}

// SeedHosts returns the parsed (ip, port) pairs from cfg.Seeds. Format is
// `ip;port` per entry; default port 8080 if omitted.
func (cfg *NosoCFG) SeedHosts(defaultPort int) []SeedHost {
	out := make([]SeedHost, 0, len(cfg.Seeds))
	for _, s := range cfg.Seeds {
		out = append(out, parseSeedEntry(s, defaultPort))
	}
	return out
}

// SeedHost is a parsed ip;port pair.
type SeedHost struct {
	IP   string
	Port int
}

func parseSeedEntry(s string, defaultPort int) SeedHost {
	parts := strings.SplitN(s, ";", 2)
	if len(parts) == 1 {
		return SeedHost{IP: parts[0], Port: defaultPort}
	}
	port := defaultPort
	if p, err := atoiSafe(parts[1]); err == nil {
		port = p
	}
	return SeedHost{IP: parts[0], Port: port}
}

func atoiSafe(s string) (int, error) {
	var n int
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errors.New("not a number")
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}
