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
	"net"
	"os"
	"path/filepath"
	"slices"
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
}

func NewSessionLease(deadline time.Time) *SessionLease {
	return &SessionLease{deadline: deadline, changed: make(chan struct{})}
}
func (l *SessionLease) snapshot() (time.Time, <-chan struct{}, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.deadline, l.changed, l.expired
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
func (l *SessionLease) extend(deadline time.Time) error {
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
	close(l.changed)
	l.changed = make(chan struct{})
	return nil
}

type renewalRequest struct {
	Challenge []byte `json:"challenge"`
	Serial    uint64 `json:"serial"`
}
type renewalResponse struct {
	Certificate string         `json:"certificate,omitempty"`
	Signature   *ssh.Signature `json:"signature,omitempty"`
	Error       string         `json:"error,omitempty"`
	Expiration  time.Time      `json:"expiration,omitzero"`
}

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
func verifyRenewal(original *ssh.Certificate, response renewalResponse, challenge []byte, deadline time.Time) (time.Time, error) {
	if response.Error != "" {
		return time.Time{}, errors.New(response.Error)
	}
	key, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(response.Certificate))
	if err != nil || len(bytes.TrimSpace(rest)) != 0 {
		return time.Time{}, errors.New("invalid renewed certificate")
	}
	cert, ok := key.(*ssh.Certificate)
	if !ok || cert.CertType != ssh.UserCert || !renewalEligible(cert) {
		return time.Time{}, errors.New("renewed certificate lacks renewal policy")
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
	if next.IsZero() || !next.After(deadline) {
		return time.Time{}, errors.New("renewed certificate must have a later finite expiry")
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
func (spec *RunSpec) prepareRenewal() (func(), error) {
	if spec.ExpiryDeadline.IsZero() {
		return func() {}, nil
	}
	if spec.Lease == nil {
		spec.Lease = NewSessionLease(spec.ExpiryDeadline)
	}
	cert := spec.Info.Auth.Certificate
	bridge := os.Getenv("CERBERUS_RENEW_SOCKET")
	if !renewalEligible(cert) || bridge == "" {
		return func() {}, nil
	}
	dir, err := os.MkdirTemp("", "logsh-renew-")
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("unix", filepath.Join(dir, "socket"))
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
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
	slots := make(chan struct{}, 4)
	wg.Go(func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			select {
			case slots <- struct{}{}:
			default:
				_ = c.Close()
				continue
			}
			if !register(c) {
				<-slots
				return
			}
			wg.Go(func() {
				defer func() { <-slots }()
				defer unregister(c)
				_ = c.SetDeadline(time.Now().Add(120 * time.Second))
				var request struct{}
				if err := json.NewDecoder(io.LimitReader(c, 4096)).Decode(&request); err != nil {
					return
				}
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
					if err := json.NewDecoder(io.LimitReader(b, 1<<20)).Decode(&response); err != nil {
						return time.Time{}, err
					}
					next, err := verifyRenewal(cert, response, challenge, spec.Lease.Deadline())
					if err != nil {
						return time.Time{}, err
					}
					if err := spec.Lease.extend(next); err != nil {
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
func (spec RunSpec) childEnv(env []string) []string {
	result := make([]string, 0, len(env)+1)
	for _, v := range env {
		if !bytes.HasPrefix([]byte(v), []byte("LOGSH_RENEW_SOCKET=")) && !bytes.HasPrefix([]byte(v), []byte("CERBERUS_RENEW_SOCKET=")) {
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
			timer := time.NewTimer(time.Until(d.Add(5 * time.Second)))
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-changed:
				timer.Stop()
			case <-timer.C:
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
