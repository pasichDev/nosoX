package chain

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func writeMarkerFile(t *testing.T, dir string, m verifiedMarker) {
	t.Helper()
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, markerFile), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}
