// SPDX-License-Identifier: Apache-2.0
package logshell

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/syslog"
	"maps"
	"math"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const PermitSessionRenewalExtension = "permit-session-renewal@cerberus"

// SessionLease serializes renewal with the irreversible expiry transition.
type SessionLease struct {
	mu       sync.Mutex
	deadline time.Time
	expired  bool
	changed  chan struct{}
	// cert is the certificate that justifies deadline: the original until a
	// renewal is verified, then the latest verified one. It moves with the
	// deadline, under mu, so a watcher never sees one without the other.
	cert *ssh.Certificate
}

func NewSessionLease(deadline time.Time) *SessionLease {
	return &SessionLease{deadline: deadline, changed: make(chan struct{})}
}
func (l *SessionLease) snapshot() (time.Time, <-chan struct{}, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.deadline, l.changed, l.expired
}

// watchSnapshot is snapshot plus the certificate behind the deadline.
func (l *SessionLease) watchSnapshot() (*ssh.Certificate, time.Time, <-chan struct{}, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.cert, l.deadline, l.changed, l.expired
}

// initCert records the certificate behind the current deadline, unless a
// renewal has already replaced it.
func (l *SessionLease) initCert(cert *ssh.Certificate) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.cert == nil {
		l.cert = cert
	}
}
func (l *SessionLease) Deadline() time.Time { d, _, _ := l.snapshot(); return d }
func (l *SessionLease) expire() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.expired {
		return true
	}
	if time.Now().Before(l.deadline) {
		return false
	}
	l.expired = true
	return true
}
func (l *SessionLease) extend(deadline time.Time) error { return l.extendCert(deadline, nil) }

// extendCert moves the deadline and, when cert is non-nil, the certificate
// that justifies it, as one step.
func (l *SessionLease) extendCert(deadline time.Time, cert *ssh.Certificate) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.expired || !time.Now().Before(l.deadline) {
		l.expired = true
		return ErrSessionExpired
	}
	if !deadline.After(l.deadline) {
		return errors.New("renewed certificate must expire later")
	}
	l.deadline = deadline
	if cert != nil {
		l.cert = cert
	}
	close(l.changed)
	l.changed = make(chan struct{})
	return nil
}

// renewalRequest is what a client writes to the session socket. An empty
// object means "renew"; Watch asks the supervisor to stream its current
// certificate and deadline instead.
type renewalRequest struct {
	Challenge []byte `json:"challenge"`
	Serial    uint64 `json:"serial"`
}
type socketRequest struct {
	Watch bool `json:"watch,omitempty"`
}
type renewalResponse struct {
	Certificate string         `json:"certificate,omitempty"`
	Signature   *ssh.Signature `json:"signature,omitempty"`
	Error       string         `json:"error,omitempty"`
	Expiration  time.Time      `json:"expiration,omitzero"`
}

const (
	maxRenewalSlots = 4
	maxWatchSlots   = 32
	watchWriteLimit = 5 * time.Second
	maxMessageBytes = 1 << 20
)

// errNotLater marks a certificate that verified but does not extend the deadline.
var errNotLater = errors.New("renewed certificate must have a later finite expiry")

func renewalEligible(cert *ssh.Certificate) bool {
	if cert == nil || cert.ValidBefore == ssh.CertTimeInfinity {
		return false
	}
	for _, k := range []string{PermitSessionRenewalExtension, TerminateOnCertExpiryExtension} {
		v, ok := cert.Extensions[k]
		if !ok || v != "" {
			return false
		}
	}
	return true
}

func parseRenewedCertificate(certText string) (*ssh.Certificate, error) {
	key, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(certText))
	if err != nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("invalid renewed certificate")
	}
	cert, ok := key.(*ssh.Certificate)
	if !ok || cert.CertType != ssh.UserCert || !renewalEligible(cert) {
		return nil, errors.New("renewed certificate lacks renewal policy")
	}
	return cert, nil
}

// verifyRenewedCertificate performs every check on a renewed certificate
// except proof of key possession: same CA key, same underlying key, same
// KeyId, principals, critical options and extensions, a valid signature and
// time window, and a finite expiry later than current. It returns the new
// deadline.
func verifyRenewedCertificate(original *ssh.Certificate, certText string, current time.Time) (time.Time, error) {
	cert, err := parseRenewedCertificate(certText)
	if err != nil {
		return time.Time{}, err
	}
	oldPrincipals, newPrincipals := slices.Clone(original.ValidPrincipals), slices.Clone(cert.ValidPrincipals)
	slices.Sort(oldPrincipals)
	slices.Sort(newPrincipals)
	if !bytes.Equal(cert.SignatureKey.Marshal(), original.SignatureKey.Marshal()) || !bytes.Equal(cert.Key.Marshal(), original.Key.Marshal()) || cert.KeyId != original.KeyId || !slices.Equal(oldPrincipals, newPrincipals) || !maps.Equal(cert.CriticalOptions, original.CriticalOptions) || !maps.Equal(cert.Extensions, original.Extensions) {
		return time.Time{}, errors.New("renewed certificate changes session identity or restrictions")
	}
	checker := ssh.CertChecker{SupportedCriticalOptions: make([]string, 0, len(cert.CriticalOptions))}
	for option := range cert.CriticalOptions {
		checker.SupportedCriticalOptions = append(checker.SupportedCriticalOptions, option)
	}
	principal := ""
	if len(original.ValidPrincipals) > 0 {
		principal = original.ValidPrincipals[0]
	}
	if err := checker.CheckCert(principal, cert); err != nil {
		return time.Time{}, fmt.Errorf("verify renewed certificate: %w", err)
	}
	auth := AuthInfo{Method: AuthMethodCert, ValidBefore: cert.ValidBefore, Extensions: cert.Extensions}
	next, err := auth.CertificateDeadline(time.Now())
	if err != nil {
		return time.Time{}, err
	}
	if next.IsZero() || !next.After(current) {
		return time.Time{}, errNotLater
	}
	return next, nil
}

func verifyRenewal(original *ssh.Certificate, response renewalResponse, challenge []byte, deadline time.Time) (time.Time, error) {
	if response.Error != "" {
		return time.Time{}, errors.New(response.Error)
	}
	next, err := verifyRenewedCertificate(original, response.Certificate, deadline)
	if err != nil {
		return time.Time{}, err
	}
	if response.Signature == nil {
		return time.Time{}, errors.New("missing key possession proof")
	}
	if err := original.Key.Verify(challenge, response.Signature); err != nil {
		return time.Time{}, fmt.Errorf("verify renewal possession proof: %w", err)
	}
	return next, nil
}

// RequestSessionExtension asks the supervisor of this exact session to renew it.
func RequestSessionExtension(socket string) (time.Time, error) {
	conn, err := net.DialTimeout("unix", socket, 5*time.Second)
	if err != nil {
		return time.Time{}, err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(120 * time.Second))
	if err = json.NewEncoder(conn).Encode(struct{}{}); err != nil {
		return time.Time{}, err
	}
	var response renewalResponse
	if err = json.NewDecoder(io.LimitReader(conn, 1<<20)).Decode(&response); err != nil {
		return time.Time{}, err
	}
	if response.Error != "" {
		return time.Time{}, errors.New(response.Error)
	}
	return response.Expiration, nil
}

// certificateExpired reports whether CertificateDeadline refuses auth ONLY
// because the certificate has expired (not a malformed policy). It mirrors the
// checks in AuthInfo.CertificateDeadline.
func certificateExpired(auth AuthInfo, now time.Time) bool {
	value, enabled := auth.Extensions[TerminateOnCertExpiryExtension]
	if auth.Method != AuthMethodCert || !enabled || value != "" {
		return false
	}
	if auth.ValidBefore == ssh.CertTimeInfinity || auth.ValidBefore > math.MaxInt64 {
		return false
	}
	return !now.Before(time.Unix(int64(auth.ValidBefore), 0))
}

// SessionDeadline is auth.CertificateDeadline with one rescue: a nested logsh
// started from a session whose certificate has since been renewed inherits the
// original, expired, certificate. If the certificate is renewal-eligible and an
// outer supervisor is reachable on LOGSH_RENEW_SOCKET, its current certificate
// is verified against the original and, if still in the future, its deadline
// is returned. A malformed policy is never rescued; any failure returns the
// original error.
func SessionDeadline(auth AuthInfo, now time.Time) (time.Time, error) {
	deadline, err := auth.CertificateDeadline(now)
	if err == nil || !certificateExpired(auth, now) || !renewalEligible(auth.Certificate) {
		return deadline, err
	}
	socket := os.Getenv("LOGSH_RENEW_SOCKET")
	if socket == "" {
		return deadline, err
	}
	next, werr := readWatchOnce(socket, auth.Certificate)
	if werr != nil || !next.After(now) {
		return time.Time{}, err
	}
	return next, nil
}

func readWatchOnce(socket string, original *ssh.Certificate) (time.Time, error) {
	conn, err := net.DialTimeout("unix", socket, 5*time.Second) // #nosec G704 -- Unix-only socket; the reply is verified against the original certificate
	if err != nil {
		return time.Time{}, err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := json.NewEncoder(conn).Encode(socketRequest{Watch: true}); err != nil {
		return time.Time{}, err
	}
	var response renewalResponse
	if err := json.NewDecoder(io.LimitReader(conn, maxMessageBytes)).Decode(&response); err != nil {
		return time.Time{}, err
	}
	return verifyRenewedCertificate(original, response.Certificate, time.Unix(int64(original.ValidBefore), 0))
}

// resettingLimit bounds how much a peer can send between decoded messages.
type resettingLimit struct {
	r io.Reader
	n int64
}

func (l *resettingLimit) Read(p []byte) (int, error) {
	if l.n <= 0 {
		return 0, errors.New("renewal message too large")
	}
	if int64(len(p)) > l.n {
		p = p[:l.n]
	}
	n, err := l.r.Read(p)
	l.n -= int64(n)
	return n, err
}

// followRenewals keeps a nested session's lease in step with the outer
// supervisor's. It returns a stop function.
//
// SECURITY: in a nested session the environment is user-controlled, so the
// socket is untrusted and may be anything. A message is acted on only if it is
// a certificate signed by the SAME CA key over the SAME key, identity and
// restrictions as the original (verifyRenewedCertificate), and only ever to
// extend. Possession is not re-proved here: the outer supervisor did that, and
// a forged socket gains nothing it could not get by presenting a certificate
// the CA already issued for this very key. Anything else ends the follow and
// leaves the current deadline standing.
func (spec *RunSpec) followRenewals(socket string, original *ssh.Certificate) func() {
	lease := spec.Lease
	done := make(chan struct{})
	var mu sync.Mutex
	var conn net.Conn
	stopped := false
	var wg sync.WaitGroup
	wg.Go(func() {
		c, err := net.DialTimeout("unix", socket, 5*time.Second) // #nosec G704 -- Unix-only socket; replies are verified against the original certificate
		if err != nil {
			Alertf(syslog.LOG_WARNING, "session renewal following unavailable, the certificate deadline stands: %v", err)
			return
		}
		mu.Lock()
		if stopped {
			mu.Unlock()
			_ = c.Close()
			return
		}
		conn = c
		mu.Unlock()
		defer func() { _ = c.Close() }()
		_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if err := json.NewEncoder(c).Encode(socketRequest{Watch: true}); err != nil {
			Alertf(syslog.LOG_WARNING, "session renewal following failed, the certificate deadline stands: %v", err)
			return
		}
		limited := &resettingLimit{r: c, n: maxMessageBytes}
		dec := json.NewDecoder(limited)
		for {
			var response renewalResponse
			if err := dec.Decode(&response); err != nil {
				select {
				case <-done:
				default:
					if !errors.Is(err, io.EOF) {
						Alertf(syslog.LOG_WARNING, "session renewal following ended, the certificate deadline stands: %v", err)
					}
				}
				return
			}
			limited.n = maxMessageBytes
			current := lease.Deadline()
			next, err := verifyRenewedCertificate(original, response.Certificate, current)
			if errors.Is(err, errNotLater) {
				continue
			}
			if err != nil {
				Alertf(syslog.LOG_WARNING, "session renewal following stopped, the certificate deadline stands: %v", err)
				return
			}
			cert, err := parseRenewedCertificate(response.Certificate)
			if err == nil {
				err = lease.extendCert(next, cert)
			}
			if err != nil {
				if !errors.Is(err, ErrSessionExpired) {
					Alertf(syslog.LOG_WARNING, "session renewal following stopped, the certificate deadline stands: %v", err)
				}
				return
			}
		}
	})
	return func() {
		mu.Lock()
		stopped = true
		close(done)
		if conn != nil {
			_ = conn.Close()
		}
		mu.Unlock()
		wg.Wait()
	}
}

func (spec *RunSpec) prepareRenewal() (func(), error) {
	if spec.ExpiryDeadline.IsZero() {
		return func() {}, nil
	}
	if spec.Lease == nil {
		spec.Lease = NewSessionLease(spec.ExpiryDeadline)
	}
	cert := spec.Info.Auth.Certificate
	if !renewalEligible(cert) {
		return func() {}, nil
	}
	spec.Lease.initCert(cert)
	bridge := os.Getenv("CERBERUS_RENEW_SOCKET")
	if bridge == "" {
		inherited := os.Getenv("LOGSH_RENEW_SOCKET")
		if inherited == "" {
			return func() {}, nil
		}
		spec.renewSocket = inherited
		return spec.followRenewals(inherited, cert), nil
	}
	// Renewal is an optional convenience: without it the original deadline
	// simply stands, so a failure here must never abort the session.
	dir, err := os.MkdirTemp("", "logsh-renew-")
	if err != nil {
		Alertf(syslog.LOG_WARNING, "session renewal unavailable, the certificate deadline stands: %v", err)
		return func() {}, nil
	}
	listener, err := net.Listen("unix", filepath.Join(dir, "socket"))
	if err != nil {
		_ = os.RemoveAll(dir)
		Alertf(syslog.LOG_WARNING, "session renewal unavailable, the certificate deadline stands: %v", err)
		return func() {}, nil
	}
	spec.renewSocket = filepath.Join(dir, "socket")
	var mu sync.Mutex
	conns := map[net.Conn]struct{}{}
	closed := false
	var wg sync.WaitGroup
	register := func(c net.Conn) bool {
		mu.Lock()
		defer mu.Unlock()
		if closed {
			_ = c.Close()
			return false
		}
		conns[c] = struct{}{}
		return true
	}
	unregister := func(c net.Conn) { _ = c.Close(); mu.Lock(); delete(conns, c); mu.Unlock() }
	total := make(chan struct{}, maxRenewalSlots+maxWatchSlots)
	renewSlots := make(chan struct{}, maxRenewalSlots)
	watchSlots := make(chan struct{}, maxWatchSlots)
	lease := spec.Lease
	renew := func(c net.Conn) {
		next, err := func() (time.Time, error) {
			if err := spec.checkExpiry(); err != nil {
				return time.Time{}, err
			}
			nonce := make([]byte, 32)
			if _, err := rand.Read(nonce); err != nil {
				return time.Time{}, err
			}
			challenge := append([]byte("cerberus-session-renewal-v1\x00"), nonce...)
			b, err := net.DialTimeout("unix", bridge, 5*time.Second) // #nosec G704 -- Unix-only socket; renewal authority comes from the authenticated certificate and possession proof
			if err != nil {
				return time.Time{}, err
			}
			if !register(b) {
				return time.Time{}, errors.New("session ended")
			}
			defer unregister(b)
			_ = b.SetDeadline(time.Now().Add(120 * time.Second))
			if err := json.NewEncoder(b).Encode(renewalRequest{Challenge: challenge, Serial: cert.Serial}); err != nil {
				return time.Time{}, err
			}
			var response renewalResponse
			if err := json.NewDecoder(io.LimitReader(b, maxMessageBytes)).Decode(&response); err != nil {
				return time.Time{}, err
			}
			next, err := verifyRenewal(cert, response, challenge, lease.Deadline())
			if err != nil {
				return time.Time{}, err
			}
			renewed, err := parseRenewedCertificate(response.Certificate)
			if err != nil {
				return time.Time{}, err
			}
			if err := lease.extendCert(next, renewed); err != nil {
				return time.Time{}, err
			}
			return next, nil
		}()
		response := renewalResponse{Expiration: next}
		if err != nil {
			response.Error = err.Error()
			Alertf(syslog.LOG_WARNING, "session_renewal_rejected serial=%d error=%q", cert.Serial, err)
		} else {
			Alertf(syslog.LOG_INFO, "session_renewal_accepted serial=%d expiration=%s", cert.Serial, next.UTC().Format(time.RFC3339))
		}
		_ = json.NewEncoder(c).Encode(response)
	}
	// watch streams the current certificate and deadline now and after every
	// change, ending when the lease expires, the peer leaves, or cleanup runs.
	watch := func(c net.Conn) {
		_ = c.SetDeadline(time.Time{})
		gone := make(chan struct{})
		wg.Go(func() { _, _ = io.Copy(io.Discard, c); close(gone) })
		enc := json.NewEncoder(c)
		for {
			current, d, changed, expired := lease.watchSnapshot()
			if expired {
				return
			}
			_ = c.SetWriteDeadline(time.Now().Add(watchWriteLimit))
			if err := enc.Encode(renewalResponse{Certificate: string(ssh.MarshalAuthorizedKey(current)), Expiration: d}); err != nil {
				return
			}
		wait:
			for {
				timer := time.NewTimer(untilWall(d))
				select {
				case <-gone:
					timer.Stop()
					return
				case <-changed:
					timer.Stop()
					break wait
				case <-timer.C:
					if !time.Now().Before(d) {
						if now, _, _ := lease.snapshot(); now.Equal(d) {
							return
						}
						break wait
					}
				}
			}
		}
	}
	wg.Go(func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			select {
			case total <- struct{}{}:
			default:
				_ = c.Close()
				continue
			}
			if !register(c) {
				<-total
				return
			}
			wg.Go(func() {
				defer func() { <-total }()
				defer unregister(c)
				_ = c.SetDeadline(time.Now().Add(120 * time.Second))
				var request socketRequest
				if err := json.NewDecoder(io.LimitReader(c, 4096)).Decode(&request); err != nil {
					return
				}
				if request.Watch {
					select {
					case watchSlots <- struct{}{}:
						defer func() { <-watchSlots }()
					default:
						return
					}
					watch(c)
					return
				}
				select {
				case renewSlots <- struct{}{}:
					defer func() { <-renewSlots }()
				default:
					_ = json.NewEncoder(c).Encode(renewalResponse{Error: "too many renewals in progress"})
					return
				}
				renew(c)
			})
		}
	})
	return func() {
		mu.Lock()
		closed = true
		_ = listener.Close()
		for c := range conns {
			_ = c.Close()
		}
		mu.Unlock()
		wg.Wait()
		_ = os.RemoveAll(dir)
	}, nil
}

// childEnv strips the renewal variables inherited from the environment.
// CERBERUS_RENEW_SOCKET is the client bridge and never reaches a child.
// LOGSH_RENEW_SOCKET is replaced by this session's own listener or, in a
// nested session, the outer supervisor's socket being followed.
func (spec RunSpec) childEnv(env []string) []string {
	result := make([]string, 0, len(env)+1)
	for _, v := range env {
		if !strings.HasPrefix(v, "LOGSH_RENEW_SOCKET=") && !strings.HasPrefix(v, "CERBERUS_RENEW_SOCKET=") {
			result = append(result, v)
		}
	}
	if spec.renewSocket != "" {
		result = append(result, "LOGSH_RENEW_SOCKET="+spec.renewSocket)
	}
	return result
}
func (spec RunSpec) recordingContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if spec.Lease == nil {
		return ctx, func() {}
	}
	ctx = context.WithValue(context.WithoutCancel(ctx), recordingLifetimeKey{}, true)
	ctx, cancel := context.WithCancel(ctx)
	go func() {
		for {
			d, changed, _ := spec.Lease.snapshot()
			target := d.Add(5 * time.Second)
			timer := time.NewTimer(untilWall(target))
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-changed:
				timer.Stop()
			case <-timer.C:
				// Timers do not advance while the host is suspended, so only
				// the wall clock decides that the deadline has really passed.
				if time.Now().Before(target) {
					continue
				}
				spec.Lease.mu.Lock()
				current := spec.Lease.deadline
				if current.Equal(d) {
					spec.Lease.expired = true
					cancel()
				}
				spec.Lease.mu.Unlock()
				if current.Equal(d) {
					return
				}
			}
		}
	}()
	return ctx, cancel
}

type recordingLifetimeKey struct{}
