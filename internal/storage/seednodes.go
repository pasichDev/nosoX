package storage

import (
	"errors"
	"os"
	"strings"
)

// LoadSeedNodes parses seednodes.txt / defseeds.nos. Both files share the
// same one-line text format defined in `nosonetwork.pas:156`:
//
//	DefNodes ip1 ip2 ip3 ... ip10
//
// The leading word `DefNodes` is a label; the rest are bare IPs (no port —
// they all default to the node's listen port, 8080).
func LoadSeedNodes(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return parseSeedNodes(string(data))
}

func parseSeedNodes(text string) ([]string, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, nil
	}
	parts := strings.Fields(text)
	if len(parts) == 0 {
		return nil, errors.New("storage: empty seednodes")
	}
	if strings.EqualFold(parts[0], "DefNodes") {
		parts = parts[1:]
	}
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out, nil
}
