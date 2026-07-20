// Package traefik_geoblock_mmdb is a Traefik middleware plugin that allow-lists
// requests by country using a MaxMind GeoLite2-Country .mmdb file.
//
// It has no third-party dependencies (a small, self-contained MaxMind DB reader
// is included below) and makes no external API calls, so it runs under Yaegi
// without vendoring and without network access.
//
// This product includes GeoLite2 data created by MaxMind, available from
// https://www.maxmind.com.
package traefik_geoblock_mmdb

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// dbReloadInterval throttles how often the middleware retries loading the
// database while it is unavailable.
const dbReloadInterval = 30 * time.Second

// Config is the plugin configuration provided via Traefik's dynamic config.
type Config struct {
	// Enabled toggles the middleware. When false the request passes through
	// untouched.
	Enabled bool `json:"enabled,omitempty"`
	// DatabaseFilePath is the path (inside the Traefik container) to the
	// MaxMind GeoLite2-Country .mmdb file, e.g. /geoip/GeoLite2-Country.mmdb
	DatabaseFilePath string `json:"databaseFilePath,omitempty"`
	// AllowedCountries is the ISO 3166-1 alpha-2 allow-list (e.g. CH, LI).
	// A request is allowed only if its source country is in this list.
	AllowedCountries []string `json:"allowedCountries,omitempty"`
	// AllowPrivate allows private / loopback / link-local source IPs without a
	// country lookup.
	AllowPrivate bool `json:"allowPrivate,omitempty"`
	// AllowOnError controls what happens when the source country cannot be
	// determined: the IP is not in the database, the client IP cannot be
	// parsed, the lookup/decoder fails (incl. a recovered panic), OR the
	// database file itself is missing or unreadable. When false (the default)
	// such requests are blocked (fail closed); when true they are ALLOWED
	// (fail open). A request whose country IS determined but is not in
	// AllowedCountries is always blocked, regardless of this setting.
	AllowOnError bool `json:"allowOnError,omitempty"`
	// DisallowedStatusCode is the HTTP status returned for blocked requests
	// (default 403).
	DisallowedStatusCode int `json:"disallowedStatusCode,omitempty"`
	// ClientIPHeader, when set, takes the source IP from this request header
	// (leftmost value for comma-separated headers like X-Forwarded-For) instead
	// of the TCP peer address. LEAVE EMPTY unless Traefik sits behind a TRUSTED
	// upstream proxy/LB (e.g. Cloudflare -> "CF-Connecting-IP"); trusting a
	// client-supplied header on a directly-exposed Traefik allows trivial
	// geo-block bypass via header spoofing.
	ClientIPHeader string `json:"clientIPHeader,omitempty"`
}

// CreateConfig returns the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		// Fail closed by default: if the country can't be determined, block.
		// Set allowOnError: true to allow such requests instead (fail open).
		DisallowedStatusCode: http.StatusForbidden,
	}
}

// GeoBlock is the middleware handler.
type GeoBlock struct {
	next         http.Handler
	name         string
	dbPath       string
	allowed      map[string]struct{}
	allowPriv    bool
	allowOnError bool
	denyCode     int
	ipHeader     string

	// db is loaded lazily/at startup and may be nil while the database file is
	// unavailable. Guarded by mu together with lastTryNs (the last reload
	// attempt, unix nanoseconds).
	mu        sync.RWMutex
	db        *countryDB
	lastTryNs int64
}

// New builds the middleware.
//
// Note: a missing or unreadable database is deliberately NOT a startup error —
// failing here would make the middleware "not exist" and break every router
// that references it. Instead the DB is treated as unavailable and requests are
// handled per allowOnError; database() retries loading it so the plugin
// self-heals once the file appears. Genuine authoring mistakes (no path, empty
// allow-list) still fail fast.
func New(_ context.Context, next http.Handler, cfg *Config, name string) (http.Handler, error) {
	if cfg == nil || !cfg.Enabled {
		// Disabled: transparent pass-through.
		return next, nil
	}
	if cfg.DatabaseFilePath == "" {
		return nil, errors.New("geoblock: databaseFilePath is required")
	}
	if len(cfg.AllowedCountries) == 0 {
		return nil, errors.New("geoblock: allowedCountries is empty (would block everything)")
	}
	allowed := make(map[string]struct{}, len(cfg.AllowedCountries))
	for _, c := range cfg.AllowedCountries {
		c = strings.ToUpper(strings.TrimSpace(c))
		if c != "" {
			allowed[c] = struct{}{}
		}
	}
	code := cfg.DisallowedStatusCode
	if code == 0 {
		code = http.StatusForbidden
	}
	g := &GeoBlock{
		next:         next,
		name:         name,
		dbPath:       cfg.DatabaseFilePath,
		allowed:      allowed,
		allowPriv:    cfg.AllowPrivate,
		allowOnError: cfg.AllowOnError,
		denyCode:     code,
		ipHeader:     strings.TrimSpace(cfg.ClientIPHeader),
	}
	if db, err := openCountryDB(cfg.DatabaseFilePath); err != nil {
		log.Printf("geoblock(%s): WARNING could not load %q at startup; requests handled per allowOnError=%t until it becomes available: %v",
			name, cfg.DatabaseFilePath, cfg.AllowOnError, err)
	} else {
		g.db = db
	}
	return g, nil
}

func (g *GeoBlock) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if g.decide(req) {
		g.next.ServeHTTP(rw, req)
		return
	}
	http.Error(rw, "Forbidden", g.denyCode)
}

// decide returns whether the request is allowed. It performs no I/O on the
// response and never calls next, so it can be wrapped in a panic recover
// without risking a double-serve of the downstream handler. Any panic, lookup
// error, unparseable IP, or unavailable database resolves via allowOnError
// (fail open / fail closed).
func (g *GeoBlock) decide(req *http.Request) (allow bool) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("geoblock(%s): recovered from panic, allowOnError=%t: %v", g.name, g.allowOnError, r)
			allow = g.allowOnError
		}
	}()

	ip := g.clientIP(req)
	if ip == nil {
		// Source IP could not be determined.
		return g.allowOnError
	}
	if g.allowPriv && isPrivate(ip) {
		return true
	}

	db := g.database()
	if db == nil {
		// Database missing/unreadable -> country cannot be determined.
		return g.allowOnError
	}

	country, err := db.lookupCountry(ip)
	if err != nil || country == "" {
		// Lookup error, or the IP is not present in the database.
		return g.allowOnError
	}
	// Country determined: strict allow-list (this case ignores allowOnError).
	_, ok := g.allowed[country]
	return ok
}

// database returns the loaded country DB, or nil if it is currently
// unavailable. If unavailable, it retries loading at most once per
// dbReloadInterval so the plugin recovers automatically once the file appears
// (e.g. after a geoipupdate sidecar's first run) without a Traefik restart.
func (g *GeoBlock) database() *countryDB {
	g.mu.RLock()
	db := g.db
	g.mu.RUnlock()
	if db != nil {
		return db
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	if g.db != nil { // loaded by another goroutine in the meantime
		return g.db
	}
	now := time.Now().UnixNano()
	if g.lastTryNs != 0 && now-g.lastTryNs < int64(dbReloadInterval) {
		return nil // retried too recently
	}
	g.lastTryNs = now
	loaded, err := openCountryDB(g.dbPath)
	if err != nil {
		return nil
	}
	g.db = loaded
	log.Printf("geoblock(%s): database %s is now available and active", g.name, g.dbPath)
	return loaded
}

// clientIP resolves the source IP. Default = TCP peer (req.RemoteAddr), which is
// unspoofable on a directly-exposed Traefik. Only honours a header when the
// operator explicitly opts in via ClientIPHeader.
func (g *GeoBlock) clientIP(req *http.Request) net.IP {
	if g.ipHeader != "" {
		if h := req.Header.Get(g.ipHeader); h != "" {
			if i := strings.IndexByte(h, ','); i >= 0 {
				h = h[:i]
			}
			if ip := net.ParseIP(strings.TrimSpace(h)); ip != nil {
				return ip
			}
		}
	}
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		host = req.RemoteAddr
	}
	return net.ParseIP(strings.TrimSpace(host))
}

func isPrivate(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		switch {
		case v4[0] == 10:
			return true
		case v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31:
			return true
		case v4[0] == 192 && v4[1] == 168:
			return true
		case v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127: // CGNAT 100.64.0.0/10
			return true
		}
		return false
	}
	// IPv6 unique local addresses fc00::/7
	if len(ip) == net.IPv6len && (ip[0]&0xfe) == 0xfc {
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// Minimal MaxMind DB (.mmdb) reader — country lookup only, zero dependencies.
// Format reference: https://maxmind.github.io/MaxMind-DB/
// ---------------------------------------------------------------------------

type countryDB struct {
	data       []byte
	nodeCount  uint32
	recordSize uint32
	nodeSize   uint32 // bytes per node = recordSize * 2 / 8
	dataStart  uint32 // absolute offset of the data section = nodeCount*nodeSize + 16
	ipVersion  int
}

func openCountryDB(path string) (*countryDB, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	db := &countryDB{data: raw}

	marker := []byte("\xab\xcd\xefMaxMind.com")
	idx := bytes.LastIndex(raw, marker)
	if idx < 0 {
		return nil, errors.New("metadata marker not found (not a MaxMind DB?)")
	}
	metaStart := uint32(idx + len(marker))

	// In the metadata section, pointers are relative to the metadata start.
	metaV, _, err := db.decode(metaStart, metaStart, 0)
	if err != nil {
		return nil, fmt.Errorf("metadata: %w", err)
	}
	meta, ok := metaV.(map[string]interface{})
	if !ok {
		return nil, errors.New("metadata is not a map")
	}
	nc, ok1 := toUint(meta["node_count"])
	rs, ok2 := toUint(meta["record_size"])
	iv, _ := toUint(meta["ip_version"])
	if !ok1 || !ok2 || nc == 0 || rs == 0 {
		return nil, errors.New("metadata missing node_count/record_size")
	}
	db.nodeCount = uint32(nc)
	db.recordSize = uint32(rs)
	if db.recordSize != 24 && db.recordSize != 28 && db.recordSize != 32 {
		return nil, fmt.Errorf("unsupported record_size %d", db.recordSize)
	}
	db.nodeSize = db.recordSize * 2 / 8
	db.dataStart = db.nodeCount*db.nodeSize + 16
	db.ipVersion = int(iv)
	return db, nil
}

// lookupCountry walks the search tree for ip and returns its ISO country code
// ("" if the IP is not present in the database).
func (db *countryDB) lookupCountry(ip net.IP) (string, error) {
	var key []byte
	if v4 := ip.To4(); v4 != nil {
		if db.ipVersion == 4 {
			key = v4
		} else {
			// IPv4 lookup in an IPv6 tree: 96 leading zero bits + the 32 address bits.
			key = make([]byte, net.IPv6len)
			copy(key[12:], v4)
		}
	} else {
		key = ip.To16()
		if key == nil {
			return "", errors.New("invalid IP")
		}
	}

	bits := len(key) * 8
	node := uint32(0)
	for i := 0; i < bits; i++ {
		bit := (key[i>>3] >> (7 - uint(i&7))) & 1
		node = db.readNode(node, bit)
		if node >= db.nodeCount {
			break
		}
	}
	if node <= db.nodeCount {
		// node == nodeCount => explicit "not found"; node < nodeCount => no leaf.
		return "", nil
	}
	// node > nodeCount => offset into the data section.
	dataOffset := node - db.nodeCount - 16 + db.dataStart
	val, _, err := db.decode(dataOffset, db.dataStart, 0)
	if err != nil {
		return "", err
	}
	return extractISO(val), nil
}

func (db *countryDB) readNode(node uint32, bit byte) uint32 {
	base := node * db.nodeSize
	b := db.data
	switch db.recordSize {
	case 24:
		if bit == 0 {
			return uint32(b[base])<<16 | uint32(b[base+1])<<8 | uint32(b[base+2])
		}
		return uint32(b[base+3])<<16 | uint32(b[base+4])<<8 | uint32(b[base+5])
	case 28:
		if bit == 0 {
			return ((uint32(b[base+3]) >> 4) << 24) | uint32(b[base])<<16 | uint32(b[base+1])<<8 | uint32(b[base+2])
		}
		return ((uint32(b[base+3]) & 0x0f) << 24) | uint32(b[base+4])<<16 | uint32(b[base+5])<<8 | uint32(b[base+6])
	default: // 32
		if bit == 0 {
			return uint32(b[base])<<24 | uint32(b[base+1])<<16 | uint32(b[base+2])<<8 | uint32(b[base+3])
		}
		return uint32(b[base+4])<<24 | uint32(b[base+5])<<16 | uint32(b[base+6])<<8 | uint32(b[base+7])
	}
}

// decode reads one value at off. base is the pointer base (data-section start,
// or metadata start when decoding metadata). It returns the decoded value and
// the offset immediately after this value's own bytes.
func (db *countryDB) decode(off, base uint32, depth int) (interface{}, uint32, error) {
	if depth > 64 {
		return nil, 0, errors.New("pointer recursion too deep")
	}
	if off >= uint32(len(db.data)) {
		return nil, 0, errors.New("offset out of range")
	}
	ctrl := db.data[off]
	off++
	typ := ctrl >> 5
	if typ == 0 { // extended type
		if off >= uint32(len(db.data)) {
			return nil, 0, errors.New("truncated extended type")
		}
		typ = db.data[off] + 7
		off++
	}

	// Pointer (type 1) has its own size encoding and does not carry a payload.
	if typ == 1 {
		ss := (ctrl >> 3) & 0x3
		var p uint32
		switch ss {
		case 0:
			v, err := db.u(off, 1)
			if err != nil {
				return nil, 0, err
			}
			p = (uint32(ctrl&0x7) << 8) | uint32(v)
			off++
		case 1:
			v, err := db.u(off, 2)
			if err != nil {
				return nil, 0, err
			}
			p = ((uint32(ctrl&0x7) << 16) | uint32(v)) + 2048
			off += 2
		case 2:
			v, err := db.u(off, 3)
			if err != nil {
				return nil, 0, err
			}
			p = ((uint32(ctrl&0x7) << 24) | uint32(v)) + 526336
			off += 3
		default: // 3
			v, err := db.u(off, 4)
			if err != nil {
				return nil, 0, err
			}
			p = uint32(v)
			off += 4
		}
		val, _, err := db.decode(base+p, base, depth+1)
		return val, off, err
	}

	// Size for non-pointer types.
	size := uint32(ctrl & 0x1f)
	switch {
	case size == 29:
		v, err := db.u(off, 1)
		if err != nil {
			return nil, 0, err
		}
		size = 29 + uint32(v)
		off++
	case size == 30:
		v, err := db.u(off, 2)
		if err != nil {
			return nil, 0, err
		}
		size = 285 + uint32(v)
		off += 2
	case size == 31:
		v, err := db.u(off, 3)
		if err != nil {
			return nil, 0, err
		}
		size = 65821 + uint32(v)
		off += 3
	}

	switch typ {
	case 2: // UTF-8 string
		end := off + size
		if end > uint32(len(db.data)) {
			return nil, 0, errors.New("string out of range")
		}
		return string(db.data[off:end]), end, nil
	case 5, 6, 9, 10: // uint16, uint32, uint64, uint128 (low bytes)
		v, err := db.u(off, size)
		if err != nil {
			return nil, 0, err
		}
		return v, off + size, nil
	case 7: // map
		m := make(map[string]interface{}, size)
		cur := off
		for i := uint32(0); i < size; i++ {
			k, next, err := db.decode(cur, base, depth+1)
			if err != nil {
				return nil, 0, err
			}
			ks, _ := k.(string)
			v, next2, err := db.decode(next, base, depth+1)
			if err != nil {
				return nil, 0, err
			}
			if ks != "" {
				m[ks] = v
			}
			cur = next2
		}
		return m, cur, nil
	case 11: // array
		arr := make([]interface{}, 0, size)
		cur := off
		for i := uint32(0); i < size; i++ {
			v, next, err := db.decode(cur, base, depth+1)
			if err != nil {
				return nil, 0, err
			}
			arr = append(arr, v)
			cur = next
		}
		return arr, cur, nil
	case 14: // boolean: size is the value (0/1); no payload bytes
		// Not returned as a bool: under Yaegi, assigning a bool through this
		// interface{} return panics ("reflect: call of reflect.Value.SetBool
		// on interface Value"). A country lookup never needs this value
		// (e.g. is_in_european_union), so skip it like the other unused
		// types below; the offset is unaffected since booleans carry no
		// payload bytes.
		return nil, off, nil
	default:
		// double(3), bytes(4), int32(8), float(15), container(12), end(13), ...
		// We don't need their values for a country lookup; just skip the payload.
		end := off + size
		if end > uint32(len(db.data)) {
			return nil, 0, errors.New("payload out of range")
		}
		return nil, end, nil
	}
}

// u reads n (<=8) big-endian bytes at off as an unsigned integer.
func (db *countryDB) u(off, n uint32) (uint64, error) {
	if n > 8 || off+n > uint32(len(db.data)) {
		return 0, errors.New("integer read out of range")
	}
	var v uint64
	for i := uint32(0); i < n; i++ {
		v = v<<8 | uint64(db.data[off+i])
	}
	return v, nil
}

func toUint(v interface{}) (uint64, bool) {
	u, ok := v.(uint64)
	return u, ok
}

// extractISO pulls country.iso_code from a decoded record, falling back to
// registered_country.iso_code (some IPs only carry the latter).
func extractISO(val interface{}) string {
	m, ok := val.(map[string]interface{})
	if !ok {
		return ""
	}
	if iso := isoFrom(m["country"]); iso != "" {
		return iso
	}
	return isoFrom(m["registered_country"])
}

func isoFrom(v interface{}) string {
	if cm, ok := v.(map[string]interface{}); ok {
		if iso, ok := cm["iso_code"].(string); ok {
			return strings.ToUpper(iso)
		}
	}
	return ""
}
