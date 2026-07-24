package probe

import "testing"

func TestTokenize(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"/bin/foo", []string{"/bin/foo"}},
		{"/bin/foo bar baz", []string{"/bin/foo", "bar", "baz"}},
		{"/bin/foo 'has space'", []string{"/bin/foo", "has space"}},
		{`/bin/foo "has space"`, []string{"/bin/foo", "has space"}},
		{"  /bin/foo   bar  ", []string{"/bin/foo", "bar"}},
		{"/nix/store/xxxx-nixnet-netbird-address-probe-host-b/bin/nixnet-netbird-address-probe-host-b", []string{"/nix/store/xxxx-nixnet-netbird-address-probe-host-b/bin/nixnet-netbird-address-probe-host-b"}},
	}
	for _, c := range cases {
		got, err := tokenize(c.in)
		if err != nil {
			t.Errorf("tokenize(%q): %v", c.in, err)
			continue
		}
		if len(got) != len(c.want) {
			t.Errorf("tokenize(%q) = %v, want %v", c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("tokenize(%q) = %v, want %v", c.in, got, c.want)
				break
			}
		}
	}

	if _, err := tokenize(`/bin/foo "unterminated`); err == nil {
		t.Errorf("tokenize with an unterminated quote should error, got nil")
	}
}

func TestFirstNonEmptyLine(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"\n\n\n", ""},
		{`{"address":"203.0.113.20"}`, `{"address":"203.0.113.20"}`},
		{"\n  \n" + `{"healthy":true}` + "\ntrailing garbage\n", `{"healthy":true}`},
	}
	for _, c := range cases {
		got := firstNonEmptyLine([]byte(c.in))
		if got != c.want {
			t.Errorf("firstNonEmptyLine(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
