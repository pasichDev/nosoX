package p2p

import "testing"

func TestParseSeedTXT(t *testing.T) {
	cases := []struct {
		txt  string
		want string
		ok   bool
	}{
		{"v=nosox1;addr=/ip4/1.2.3.4/tcp/7781/p2p/12D3KooW", "/ip4/1.2.3.4/tcp/7781/p2p/12D3KooW", true},
		{"v=nosox1;addr=/dns4/seed.example.com/tcp/7781/p2p/abc", "/dns4/seed.example.com/tcp/7781/p2p/abc", true},
		{"v=other;addr=/ip4/1.2.3.4/tcp/7781/p2p/abc", "", false},
		{"random text", "", false},
		{"v=nosox1;", "", false},
	}
	for _, tc := range cases {
		got, ok := parseSeedTXT(tc.txt)
		if ok != tc.ok || got != tc.want {
			t.Errorf("parseSeedTXT(%q) = (%q, %v); want (%q, %v)",
				tc.txt, got, ok, tc.want, tc.ok)
		}
	}
}

func TestFormatSeedTXT(t *testing.T) {
	got := formatSeedTXT("/ip4/1.2.3.4/tcp/7781/p2p/abc")
	want := "v=nosox1;addr=/ip4/1.2.3.4/tcp/7781/p2p/abc"
	if got != want {
		t.Errorf("formatSeedTXT = %q want %q", got, want)
	}
}
