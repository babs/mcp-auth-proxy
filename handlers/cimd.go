package handlers

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/babs/mcp-auth-proxy/config"
	"github.com/babs/mcp-auth-proxy/metrics"
	"github.com/babs/mcp-auth-proxy/token"
	"go.uber.org/zap"
)

// Client ID Metadata Documents (MCP Authorization 2026-07-28,
// draft-ietf-oauth-client-id-metadata-document-02): an MCP client may
// present an https URL as its client_id; the document at that URL
// supplies client_name and redirect_uris. The URL string is the client
// identity verbatim — no normalisation anywhere, so a document whose
// client_id differs by one byte is a different (and invalid) client.

const (
	// cimdMaxBodyBytes caps the document: a real one is a few hundred
	// bytes, and anything larger is amplification against the fetcher.
	cimdMaxBodyBytes = 5 * 1024
	cimdFetchTimeout = 5 * time.Second
	// cimdMaxHostLen bounds the authority: a 253-byte DNS name plus ":65535".
	cimdMaxHostLen = 253 + 6
	// cimdMaxInFlight caps concurrent fetches: each holds a socket and a TLS
	// session for up to cimdFetchTimeout, and every client_id is caller-chosen.
	cimdMaxInFlight = 16
)

// cimdResult classifies a resolution for metrics.CIMDFetch and the
// recordClientDenial reason.
type cimdResult string

const (
	cimdOK                    cimdResult = "ok"
	cimdURLInvalid            cimdResult = "url_invalid"
	cimdHostNotAllowed        cimdResult = "host_not_allowed"
	cimdSSRFBlocked           cimdResult = "ssrf_blocked"
	cimdFetchError            cimdResult = "fetch_error"
	cimdTooLarge              cimdResult = "too_large"
	cimdDocInvalid            cimdResult = "doc_invalid"
	cimdAuthMethodUnsupported cimdResult = "auth_method_unsupported"
)

// cimdError carries the result class and a static error_description.
// Desc never echoes the document, the upstream body or the URL.
type cimdError struct {
	Result cimdResult
	Desc   string
	Err    error
}

func (e *cimdError) Error() string {
	if e.Err != nil {
		return string(e.Result) + ": " + e.Err.Error()
	}
	return string(e.Result) + ": " + e.Desc
}

func (e *cimdError) Unwrap() error { return e.Err }

// errCIMDBlockedAddress marks a dial refused by the dial guard; it travels
// through net.OpError and url.Error, so errors.Is finds it after Do.
var (
	errCIMDBlockedAddress = errors.New("client_id host resolved to a special-purpose address")
	errCIMDRedirect       = errors.New("client metadata document redirected")
	errCIMDCapacity       = errors.New("client metadata fetch capacity exhausted")
)

// cimdSpecialPurpose lists the IANA special-purpose registries (RFC 6890
// and successors) CIMD draft -02 §8.6 forbids fetching from. Globally
// reachable exceptions inside these blocks (the AS112, AMT and anycast
// entries) stay blocked on purpose: no client metadata host lives there.
var cimdSpecialPurpose = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.31.196.0/24"),
	netip.MustParsePrefix("192.52.193.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("192.175.48.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("100:0:0:1::/64"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2620:4f:8000::/48"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("5f00::/16"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

// IPv6 prefixes that embed an IPv4 address; the embedded address is the
// one that gets judged, so NAT64 or 6to4 cannot smuggle 10.0.0.1 past
// the table.
var (
	cimdNAT64      = netip.MustParsePrefix("64:ff9b::/96")
	cimdNAT64Local = netip.MustParsePrefix("64:ff9b:1::/48")
	cimd6to4       = netip.MustParsePrefix("2002::/16")
)

// cimdRejectSpecialPurpose returns errCIMDBlockedAddress (wrapped, naming
// the matched prefix) when addr, or the IPv4 it embeds, is special-purpose.
func cimdRejectSpecialPurpose(addr netip.Addr) error {
	// Prefix.Contains never matches a zoned address; the zone is routing
	// detail, not identity.
	addr = cimdEmbeddedIPv4(addr.WithZone(""))
	for _, p := range cimdSpecialPurpose {
		if p.Contains(addr) {
			return fmt.Errorf("%w: %s in %s", errCIMDBlockedAddress, addr, p)
		}
	}
	return nil
}

func cimdEmbeddedIPv4(addr netip.Addr) netip.Addr {
	if addr.Is4In6() {
		return addr.Unmap()
	}
	if !addr.Is6() {
		return addr
	}
	b := addr.As16()
	switch {
	case cimdNAT64.Contains(addr), cimdNAT64Local.Contains(addr):
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
	case cimd6to4.Contains(addr):
		return netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]})
	}
	return addr
}

// isCIMDClientID reports whether client_id is a Client ID Metadata
// Document URL. Sealed client_ids are base64url, so the prefix is
// unambiguous.
func isCIMDClientID(clientID string) bool {
	return strings.HasPrefix(clientID, "https://")
}

// validateCIMDClientID applies draft -02 §4.1 to the client_id URL:
// https, a path, no query, fragment or userinfo, no dot-segments, and a
// hostname rather than an IP literal (the dial guard judges what the
// name resolves to). A port is allowed and stays part of the identity.
func validateCIMDClientID(clientID string) (*url.URL, *cimdError) {
	invalid := func(why string) (*url.URL, *cimdError) {
		return nil, &cimdError{Result: cimdURLInvalid, Desc: "client_id must be an https URL with a path and no query, fragment or userinfo", Err: errors.New(why)}
	}
	u, err := url.Parse(clientID)
	if err != nil {
		return invalid("malformed URL")
	}
	switch {
	case u.Scheme != "https":
		return invalid("scheme is not https")
	case u.Opaque != "" || u.Host == "" || u.Hostname() == "":
		return invalid("missing host")
	case len(u.Host) > cimdMaxHostLen:
		return invalid("host too long")
	case u.User != nil:
		return invalid("userinfo present")
	case u.Fragment != "" || strings.Contains(clientID, "#"):
		return invalid("fragment present")
	case u.RawQuery != "" || u.ForceQuery:
		return invalid("query present")
	case u.Path == "":
		return invalid("empty path")
	}
	// Decoded Path, so %2e%2e is caught along with a literal "..".
	for seg := range strings.SplitSeq(u.Path, "/") {
		if seg == "." || seg == ".." {
			return invalid("dot-segment in path")
		}
	}
	if _, err := netip.ParseAddr(u.Hostname()); err == nil {
		return invalid("host is an IP literal")
	}
	// Same rule as CIMD_ALLOWED_HOSTS entries: a host that is not a hostname
	// (`*.example.com`, `<b>x`) could otherwise match a glob or reach a log.
	if err := config.CheckHostname(strings.ToLower(u.Hostname())); err != nil {
		return invalid("host is not a hostname")
	}
	return u, nil
}

// cimdDocument is the subset of RFC 7591 metadata the proxy reads.
// client_secret fields are RawMessage so presence is detected whatever
// their type: a document carrying one describes a confidential client,
// which this public-client-only AS cannot be.
type cimdDocument struct {
	ClientID                string          `json:"client_id"`
	ClientName              string          `json:"client_name"`
	RedirectURIs            []string        `json:"redirect_uris"`
	TokenEndpointAuthMethod string          `json:"token_endpoint_auth_method"`
	GrantTypes              []string        `json:"grant_types"`
	ClientSecret            json.RawMessage `json:"client_secret"`
	ClientSecretExpiresAt   json.RawMessage `json:"client_secret_expires_at"`
}

// CIMDResolver fetches and validates Client ID Metadata Documents.
type CIMDResolver struct {
	client        *http.Client
	logger        *zap.Logger
	redirectExtra config.RedirectAllowlist
	redirectAllow config.WebRedirectAllowlist
	hosts         config.CIMDHostAllowlist
	guard         func(netip.Addr) error
	sem           chan struct{}
}

// CIMDResolverOptions are test-only knobs, scoped to one resolver like
// proxy.Config.ResponseHeaderTimeoutOverride so a test cannot leak them
// into another; production callers pass the zero value.
type CIMDResolverOptions struct {
	// DialGuardOverride replaces cimdRejectSpecialPurpose (httptest servers
	// listen on loopback).
	DialGuardOverride func(netip.Addr) error
	// TLSClientConfigOverride replaces the transport's TLS config (an
	// httptest certificate is self-signed and names example.com).
	TLSClientConfigOverride *tls.Config
}

func NewCIMDResolver(logger *zap.Logger, extra config.RedirectAllowlist, allow config.WebRedirectAllowlist, hosts config.CIMDHostAllowlist, opts CIMDResolverOptions) *CIMDResolver {
	r := &CIMDResolver{
		logger:        logger,
		redirectExtra: extra,
		redirectAllow: allow,
		hosts:         hosts,
		guard:         cimdRejectSpecialPurpose,
		sem:           make(chan struct{}, cimdMaxInFlight),
	}
	if opts.DialGuardOverride != nil {
		r.guard = opts.DialGuardOverride
	}
	dialer := &net.Dialer{
		Timeout: cimdFetchTimeout,
		// Control runs after DNS resolution with the concrete address, so
		// a rebinding name cannot bypass the guard.
		Control: func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil {
				return fmt.Errorf("%w: unparsable dial address", errCIMDBlockedAddress)
			}
			return r.guard(ap.Addr())
		},
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	// No env proxy: the guard must see the real destination.
	tr.Proxy = nil
	tr.DialContext = dialer.DialContext
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if opts.TLSClientConfigOverride != nil {
		tr.TLSClientConfig = opts.TLSClientConfigOverride
	}
	// Transport default is 10 MiB; a hostile host must not make the fetcher buffer that before the body cap applies.
	tr.MaxResponseHeaderBytes = 16 << 10
	r.client = &http.Client{
		Transport: tr,
		Timeout:   cimdFetchTimeout,
		// A redirect would let the guarded host hand the fetch to any other.
		CheckRedirect: func(*http.Request, []*http.Request) error { return errCIMDRedirect },
	}
	return r
}

// Resolve validates the client_id URL, fetches and validates the
// document, and returns the in-memory client: ID is the client_id URL
// verbatim, ExpiresAt zero (the document is the registration; it is
// re-read on every use). The failure is typed so the caller maps its
// Result without an assertion; metrics.CIMDFetch is incremented exactly
// once per call.
func (r *CIMDResolver) Resolve(ctx context.Context, clientID, audience string) (*sealedClient, *cimdError) {
	var host string
	doc, ce := r.resolve(ctx, clientID, &host)
	if ce != nil {
		metrics.CIMDFetch.WithLabelValues(string(ce.Result)).Inc()
		// The cause can carry up to a header's worth of bytes the metadata host chose; clamp it like a description.
		var cause string
		if ce.Err != nil {
			cause = sanitizeErrorDescription(ce.Err.Error())
		}
		// Sanitising the host is dead by construction today (CheckHostname and
		// the authority cap run before it is set); it survives a reordering.
		r.logger.Warn("cimd_resolve_failed", zap.String("client_id_host", sanitizeErrorDescription(host)), zap.String("reason", string(ce.Result)), zap.String("error", cause))
		return nil, ce
	}
	metrics.CIMDFetch.WithLabelValues(string(cimdOK)).Inc()
	return &sealedClient{
		ID:           clientID,
		RedirectURIs: doc.RedirectURIs,
		ClientName:   doc.ClientName,
		Typ:          token.PurposeClient,
		Audience:     audience,
	}, nil
}

// resolve sets *host as soon as the URL parses so the failure log can
// name it on every later step.
func (r *CIMDResolver) resolve(ctx context.Context, clientID string, host *string) (*cimdDocument, *cimdError) {
	u, ce := validateCIMDClientID(clientID)
	if ce != nil {
		return nil, ce
	}
	*host = u.Host
	// Operator policy (draft -02 §8.9) runs before any network activity.
	if !r.hosts.Allows(u.Hostname()) {
		return nil, &cimdError{Result: cimdHostNotAllowed, Desc: "client_id host is not allowed by the operator"}
	}
	body, ce := r.fetch(ctx, u)
	if ce != nil {
		return nil, ce
	}
	return parseCIMDDocument(body, clientID, r.redirectExtra, r.redirectAllow)
}

func (r *CIMDResolver) fetch(ctx context.Context, u *url.URL) ([]byte, *cimdError) {
	fetchErr := func(desc string, err error) ([]byte, *cimdError) {
		return nil, &cimdError{Result: cimdFetchError, Desc: desc, Err: err}
	}
	// Refuse rather than queue: a waiting caller would hold its own request slot too.
	select {
	case r.sem <- struct{}{}:
		defer func() { <-r.sem }()
	default:
		return fetchErr("client metadata fetch capacity exhausted", errCIMDCapacity)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil) //nolint:gosec // G704: fetching the caller-named URL is the feature; validateCIMDClientID bounds it and the dial guard judges the resolved address
	if err != nil {
		return fetchErr("client metadata document could not be fetched", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "mcp-auth-proxy")
	resp, err := r.client.Do(req) //nolint:gosec // G704: same guarded fetch as the request above
	if err != nil {
		// url.Error's message carries the full URL; keep only the cause.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		if errors.Is(err, errCIMDBlockedAddress) {
			return nil, &cimdError{Result: cimdSSRFBlocked, Desc: "client_id host resolves to a non-public address", Err: err}
		}
		return fetchErr("client metadata document could not be fetched", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fetchErr("client metadata document request did not return 200", fmt.Errorf("status %d", resp.StatusCode))
	}
	mt, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || (mt != "application/json" && (!strings.HasPrefix(mt, "application/") || !strings.HasSuffix(mt, "+json"))) {
		return fetchErr("client metadata document is not application/json", fmt.Errorf("content-type %q", mt))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, cimdMaxBodyBytes+1))
	if err != nil {
		return fetchErr("client metadata document could not be fetched", err)
	}
	if len(body) > cimdMaxBodyBytes {
		return nil, &cimdError{Result: cimdTooLarge, Desc: "client metadata document exceeds the size cap"}
	}
	return body, nil
}

// parseCIMDDocument decodes and validates the document for clientID,
// applying the same metadata rules as POST /register.
func parseCIMDDocument(body []byte, clientID string, extra config.RedirectAllowlist, allow config.WebRedirectAllowlist) (*cimdDocument, *cimdError) {
	invalid := func(desc string, err error) (*cimdDocument, *cimdError) {
		return nil, &cimdError{Result: cimdDocInvalid, Desc: desc, Err: err}
	}
	var doc cimdDocument
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(&doc); err != nil {
		return invalid("client metadata document is not a JSON object", err)
	}
	var trailing json.RawMessage
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return invalid("client metadata document has trailing data", nil)
	}
	if doc.ClientID != clientID {
		return invalid("client metadata document client_id does not match the requested client_id", nil)
	}
	switch doc.TokenEndpointAuthMethod {
	case "", "none":
	case "private_key_jwt":
		return nil, &cimdError{Result: cimdAuthMethodUnsupported, Desc: "private_key_jwt not supported, use none"}
	default:
		return invalid("client metadata document token_endpoint_auth_method must be none", nil)
	}
	if cimdMemberPresent(doc.ClientSecret) || cimdMemberPresent(doc.ClientSecretExpiresAt) {
		return invalid("client metadata document must not carry a client_secret", nil)
	}
	if doc.GrantTypes != nil && !slices.Contains(doc.GrantTypes, "authorization_code") {
		return invalid("client metadata document grant_types must include authorization_code", nil)
	}
	if len(doc.ClientName) > maxClientNameLength {
		return invalid("client metadata document client_name exceeds maximum length", nil)
	}
	// Same byte filter as /register: the name is logged and shown on the
	// consent page, and `,` is the X-User-Groups delimiter.
	if strings.ContainsAny(doc.ClientName, ",\r\n\t\x00\x0b\x0c") {
		return invalid("client metadata document client_name must not contain control bytes or commas", nil)
	}
	if len(doc.RedirectURIs) == 0 {
		return invalid("client metadata document redirect_uris is required and must not be empty", nil)
	}
	if len(doc.RedirectURIs) > maxRedirectURIs {
		return invalid("client metadata document redirect_uris exceeds maximum count", nil)
	}
	for _, raw := range doc.RedirectURIs {
		if _, err := checkRegisterRedirectURI(raw, extra, allow); err != nil {
			// url.Error's message carries the document's URI; keep only the cause.
			var ue *url.Error
			if errors.As(err, &ue) {
				err = ue.Err
			}
			return invalid("client metadata document redirect_uri is not allowed", err)
		}
	}
	return &doc, nil
}

// cimdMemberPresent reports a member that is present and not null.
func cimdMemberPresent(raw json.RawMessage) bool {
	return len(raw) > 0 && !bytes.Equal(raw, []byte("null"))
}
