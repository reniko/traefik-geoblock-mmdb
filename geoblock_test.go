package traefik_geoblock_mmdb

import (
	"net"
	"net/http"
	"os"
	"testing"
)

// TestLookup validates the embedded mmdb reader against a real MaxMind
// GeoLite2-Country.mmdb. It is skipped unless GEOBLOCK_TEST_DB points at one.
//
// With local Go:
//
//	GEOBLOCK_TEST_DB=/path/to/GeoLite2-Country.mmdb go test -run TestLookup -v
//
// Without local Go, via a throwaway container (adjust the host paths):
//
//	docker run --rm \
//	  -e GEOBLOCK_TEST_DB=/db/GeoLite2-Country.mmdb \
//	  -v "D:/Git/traefik-geoblock-mmdb:/src" \
//	  -v "D:/Claude/proxy/data/geoip:/db" \
//	  -w /src golang:1.23 go test -run TestLookup -v
func TestLookup(t *testing.T) {
	path := os.Getenv("GEOBLOCK_TEST_DB")
	if path == "" {
		t.Skip("set GEOBLOCK_TEST_DB to a GeoLite2-Country.mmdb path to run this test")
	}
	db, err := openCountryDB(path)
	if err != nil {
		t.Fatalf("openCountryDB: %v", err)
	}
	t.Logf("loaded db: record_size=%d node_count=%d ip_version=%d", db.recordSize, db.nodeCount, db.ipVersion)

	// 8.8.8.8 (Google) resolves to US in every GeoLite2-Country build — a hard assertion.
	mustCountry(t, db, "8.8.8.8", "US")

	// Private addresses are not in the DB -> empty result (allowPrivate handles them).
	mustCountry(t, db, "192.168.1.1", "")

	// Informational lookups — printed, not asserted (values can shift between DB builds).
	for _, ip := range []string{"1.1.1.1", "195.176.0.1", "2a02:1205::1", "2001:4860:4860::8888"} {
		got, err := db.lookupCountry(net.ParseIP(ip))
		if err != nil {
			t.Errorf("lookup %s: unexpected error %v", ip, err)
			continue
		}
		t.Logf("lookup %-22s -> %q", ip, got)
	}
}

func mustCountry(t *testing.T, db *countryDB, ipStr, want string) {
	t.Helper()
	ip := net.ParseIP(ipStr)
	if ip == nil {
		t.Fatalf("bad test IP %q", ipStr)
	}
	got, err := db.lookupCountry(ip)
	if err != nil {
		t.Fatalf("lookup %s: %v", ipStr, err)
	}
	if got != want {
		t.Errorf("lookup %s = %q, want %q", ipStr, got, want)
	} else {
		t.Logf("lookup %-22s -> %q (ok)", ipStr, got)
	}
}

// TestLookupEUCountry guards against a Yaegi-only panic in decode's case 14
// (boolean). MaxMind omits is_in_european_union entirely when it would be
// false, so it only appears - and only exercises the boolean decode path -
// for EU countries. Native Go tolerates `return size != 0, off, nil` typed as
// interface{}, but Yaegi panics assigning a bool into that interface value
// ("reflect: call of reflect.Value.SetBool on interface Value"). This test
// uses MaxMind's public GeoIP2-Country-Test.mmdb (test-data in
// github.com/maxmind/MaxMind-DB), which is small enough to check into the
// repo; it is unrelated to the licensed GeoLite2 database used by TestLookup.
func TestLookupEUCountry(t *testing.T) {
	db, err := openCountryDB("testdata/GeoIP2-Country-Test.mmdb")
	if err != nil {
		t.Fatalf("openCountryDB: %v", err)
	}

	// 2001:220::/128 -> SE (Sweden), an EU country: exercises the boolean
	// decode path via is_in_european_union.
	mustCountry(t, db, "2001:220::", "SE")

	// 214.78.120.0/22 -> US, a non-EU country: no is_in_european_union field
	// present, so the boolean decode path is never hit for this lookup.
	mustCountry(t, db, "214.78.120.1", "US")
}

// TestNoDatabaseFollowsAllowOnError verifies that when the database is
// unavailable the decision falls back to allowOnError (and never panics or
// needs a real .mmdb). This is the "DB missing/unreadable" robustness path.
func TestNoDatabaseFollowsAllowOnError(t *testing.T) {
	// A public IP; with no database loaded the country is "undetermined".
	req := &http.Request{RemoteAddr: "203.0.113.7:443", Header: http.Header{}}

	failOpen := &GeoBlock{allowOnError: true, dbPath: "/does/not/exist.mmdb", allowed: map[string]struct{}{"CH": {}}}
	if !failOpen.decide(req) {
		t.Error("no DB + allowOnError=true: want allow, got deny")
	}

	failClosed := &GeoBlock{allowOnError: false, dbPath: "/does/not/exist.mmdb", allowed: map[string]struct{}{"CH": {}}}
	if failClosed.decide(req) {
		t.Error("no DB + allowOnError=false: want deny, got allow")
	}
}
