package token

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// fakeIdPAccessToken returns a JWT-shaped string of n bytes. Only the
// alphabet matters here: base64url characters need no JSON escaping, so
// the sealed size grows like a real token's would.
func fakeIdPAccessToken(n int) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	var b strings.Builder
	b.Grow(n)
	for i := range n {
		if i == n/3 || i == 2*n/3 {
			b.WriteByte('.')
			continue
		}
		b.WriteByte(alphabet[i%len(alphabet)])
	}
	return b.String()
}

func dnGroups(n int) []string {
	g := make([]string, n)
	for i := range g {
		g[i] = fmt.Sprintf("CN=app-team-engineering-group-%03d,OU=Groups,DC=corp,DC=example", i)
	}
	return g
}

func TestSetMaxSealedLen_PerPurpose(t *testing.T) {
	m := mustNewManager(t, make([]byte, 32))
	payload := map[string]string{"blob": strings.Repeat("x", maxSealedLen)}
	sealed, err := m.SealJSON(payload, PurposeCode)
	if err != nil {
		t.Fatalf("SealJSON: %v", err)
	}
	if len(sealed) <= maxSealedLen {
		t.Fatalf("fixture too small: %d bytes", len(sealed))
	}
	var got map[string]string
	if err := m.OpenJSON(sealed, &got, PurposeCode); err == nil {
		t.Fatal("default cap must refuse a payload over maxSealedLen")
	}

	m.SetMaxSealedLen(PurposeCode, ForwardingMaxSealedLen)
	if err := m.OpenJSON(sealed, &got, PurposeCode); err != nil {
		t.Fatalf("raised code cap must open the payload: %v", err)
	}
	// Other purposes keep the default cap: raising one must not widen
	// the decode work an attacker can force on the rest.
	if limit := m.maxSealedLenFor(PurposeClient); limit != maxSealedLen {
		t.Errorf("client cap = %d, want default %d", limit, maxSealedLen)
	}

	m.SetMaxSealedLen(PurposeCode, 0)
	if err := m.OpenJSON(sealed, &got, PurposeCode); err == nil {
		t.Error("n <= 0 must restore the default cap")
	}
}

func TestIssueWithIdPToken_RoundTrip(t *testing.T) {
	m := mustNewManager(t, make([]byte, 32))
	idpAT := fakeIdPAccessToken(2048)
	at, claims, err := m.IssueWithIdPToken("https://proxy.example", "sub-1", "user@example.com", "cid",
		[]string{"g1", "g2"}, time.Hour, "https://proxy.example/mcp",
		IdPToken{AccessToken: idpAT, ExpiresAt: time.Now().Add(2 * time.Hour)})
	if err != nil {
		t.Fatalf("IssueWithIdPToken: %v", err)
	}
	if claims.IdPAccessToken != idpAT {
		t.Error("returned claims do not carry the IdP access token")
	}
	got, err := m.Validate(at)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got.IdPAccessToken != idpAT {
		t.Error("validated claims do not carry the IdP access token byte-for-byte")
	}
	if got.Subject != "sub-1" || got.Email != "user@example.com" || len(got.Groups) != 2 || got.Resource != "https://proxy.example/mcp" {
		t.Errorf("identity claims not preserved: %+v", got)
	}
	if strings.Contains(at, idpAT[:32]) {
		t.Error("the IdP access token is visible in the sealed token")
	}
}

func TestIssueWithIdPToken_ExpiryRule(t *testing.T) {
	m := mustNewManager(t, make([]byte, 32))
	const ttl = time.Hour
	cases := []struct {
		name    string
		idpExp  time.Duration // from now; 0 = not stated
		want    time.Duration // expected lifetime from now
		wantErr error
	}{
		{name: "idp_outlives_ttl", idpExp: 2 * time.Hour, want: ttl},
		{name: "idp_shorter_than_ttl", idpExp: 30 * time.Minute, want: 29 * time.Minute},
		{name: "idp_exactly_ttl_plus_skew", idpExp: ttl + time.Minute, want: ttl},
		{name: "idp_expiry_unknown", idpExp: 0, want: ttl},
		{name: "idp_inside_skew", idpExp: 30 * time.Second, wantErr: errIdPTokenLifetime},
		{name: "idp_leaves_under_a_minute", idpExp: 90 * time.Second, wantErr: errIdPTokenLifetime},
		{name: "idp_three_minutes", idpExp: 3 * time.Minute, want: 2 * time.Minute},
		{name: "just_under_the_minimum", idpExp: 115 * time.Second, wantErr: errIdPTokenLifetime},
		{name: "just_over_the_minimum", idpExp: 125 * time.Second, want: 65 * time.Second},
		{name: "idp_already_expired", idpExp: -time.Minute, wantErr: errIdPTokenLifetime},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			idp := IdPToken{AccessToken: fakeIdPAccessToken(256)}
			if tc.idpExp != 0 {
				idp.ExpiresAt = time.Now().Add(tc.idpExp)
			}
			before := time.Now()
			_, claims, err := m.IssueWithIdPToken("https://proxy.example", "sub", "", "cid", nil, ttl, "", idp)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("IssueWithIdPToken: %v", err)
			}
			got := claims.ExpiresAt.Sub(before)
			if d := got - tc.want; d < -2*time.Second || d > 2*time.Second {
				t.Errorf("lifetime = %v, want ~%v", got, tc.want)
			}
		})
	}
}

func TestIssueWithIdPToken_EmptyTokenRejected(t *testing.T) {
	m := mustNewManager(t, make([]byte, 32))
	if _, _, err := m.IssueWithIdPToken("https://proxy.example", "sub", "", "cid", nil, time.Hour, "", IdPToken{}); err == nil {
		t.Fatal("an empty IdP access token must not mint a forwarding token")
	}
}

// The IdP token's length comes off the groups budget, so the sealed
// token stays inside the envelope GROUPS_CLAIM_MAX_BYTES was sized for.
func TestIssueWithIdPToken_GroupsBudgetShrinks(t *testing.T) {
	m := mustNewManager(t, make([]byte, 32))
	m.SetGroupsMaxBytes(4096)
	groups := dnGroups(60) // ~3.8 KB: fits 4096 on its own

	_, plain, err := m.IssueWithIdPToken("https://proxy.example", "sub", "", "cid", groups, time.Hour, "",
		IdPToken{AccessToken: fakeIdPAccessToken(16)})
	if err != nil {
		t.Fatal(err)
	}
	if len(plain.Groups) != len(groups) {
		t.Fatalf("small IdP token: kept %d groups, want all %d", len(plain.Groups), len(groups))
	}

	_, squeezed, err := m.IssueWithIdPToken("https://proxy.example", "sub", "", "cid", groups, time.Hour, "",
		IdPToken{AccessToken: fakeIdPAccessToken(3000)})
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, g := range squeezed.Groups {
		total += len(g) + 1
	}
	if total > 4096-3000 {
		t.Errorf("groups use %d bytes, want <= %d (budget minus IdP token)", total, 4096-3000)
	}
	if len(squeezed.Groups) == 0 || len(squeezed.Groups) >= len(groups) {
		t.Errorf("kept %d of %d groups, want a partial list", len(squeezed.Groups), len(groups))
	}

	_, none, err := m.IssueWithIdPToken("https://proxy.example", "sub", "", "cid", groups, time.Hour, "",
		IdPToken{AccessToken: fakeIdPAccessToken(5000)})
	if err != nil {
		t.Fatal(err)
	}
	if len(none.Groups) != 0 {
		t.Errorf("IdP token larger than the whole budget: kept %d groups, want 0", len(none.Groups))
	}
}

// A token the proxy would refuse on every request must not be minted.
func TestIssueWithIdPToken_RefusesTokenOverAccessCap(t *testing.T) {
	m := mustNewManager(t, make([]byte, 32))
	idp := IdPToken{AccessToken: fakeIdPAccessToken(20 << 10), ExpiresAt: time.Now().Add(time.Hour)}
	if _, _, err := m.IssueWithIdPToken("https://proxy.example", "sub", "", "cid", nil, time.Hour, "", idp); !errors.Is(err, ErrSealedTooLarge) {
		t.Fatalf("default access cap: err = %v, want ErrSealedTooLarge", err)
	}

	m.SetMaxSealedLen(PurposeAccess, ForwardingMaxSealedLen)
	at, _, err := m.IssueWithIdPToken("https://proxy.example", "sub", "", "cid", nil, time.Hour, "", idp)
	if err != nil {
		t.Fatalf("forwarding access cap: %v", err)
	}
	if _, err := m.Validate(at); err != nil {
		t.Fatalf("minted token must validate under the same cap: %v", err)
	}
}

// Worst case the forwarding caps are sized for: a groups claim at the
// default budget plus a large IdP access token must still fit the 64 KB
// header block and open under ForwardingMaxSealedLen.
func TestIssueWithIdPToken_WorstCaseFitsHeaderBudget(t *testing.T) {
	m := mustNewManager(t, make([]byte, 32))
	m.SetMaxSealedLen(PurposeAccess, ForwardingMaxSealedLen)
	const headerBudget = 64 << 10
	for _, atLen := range []int{1 << 10, 8 << 10, 16 << 10, 30 << 10} {
		idp := IdPToken{AccessToken: fakeIdPAccessToken(atLen), ExpiresAt: time.Now().Add(time.Hour)}
		at, claims, err := m.IssueWithIdPToken("https://proxy.example", "sub", "user@example.com", "cid", dnGroups(2000), time.Hour, "https://proxy.example/mcp", idp)
		if err != nil {
			t.Fatalf("IdP token %d B: %v", atLen, err)
		}
		if line := len("Authorization: Bearer ") + len(at); line > headerBudget {
			t.Errorf("IdP token %d B: Authorization header line = %d B, over the %d B budget", atLen, line, headerBudget)
		}
		if _, err := m.Validate(at); err != nil {
			t.Errorf("IdP token %d B: minted token does not validate: %v", atLen, err)
		}
		if claims.IdPAccessToken != idp.AccessToken {
			t.Errorf("IdP token %d B: token not carried intact", atLen)
		}
	}
}

// Default mode must keep the access-token wire format unchanged: the
// new field is omitted when empty.
func TestIssue_DefaultModeOmitsIdPField(t *testing.T) {
	m := mustNewManager(t, make([]byte, 32))
	at, _, err := m.Issue("https://proxy.example", "sub", "user@example.com", "cid", []string{"g"}, time.Hour, "")
	if err != nil {
		t.Fatal(err)
	}
	plain, err := m.open(at, PurposeAccess)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(plain), "idp_at") {
		t.Errorf("default-mode access token carries the forwarding field: %s", plain)
	}
}

func TestFitsOpenCap(t *testing.T) {
	m := mustNewManager(t, make([]byte, 32))
	small, _ := m.SealJSON(map[string]string{"k": "v"}, PurposeRefresh)
	big, _ := m.SealJSON(map[string]string{"k": strings.Repeat("x", maxSealedLen)}, PurposeRefresh)
	if !m.FitsOpenCap(small, PurposeRefresh) {
		t.Error("small payload reported over the cap")
	}
	if m.FitsOpenCap(big, PurposeRefresh) {
		t.Error("payload over maxSealedLen reported as fitting the default cap")
	}
	m.SetMaxSealedLen(PurposeRefresh, ForwardingMaxSealedLen)
	if !m.FitsOpenCap(big, PurposeRefresh) {
		t.Error("payload under the raised cap reported over it")
	}
	var out map[string]string
	if err := m.OpenJSON(big, &out, PurposeRefresh); err != nil {
		t.Errorf("FitsOpenCap and open() disagree: %v", err)
	}
}
