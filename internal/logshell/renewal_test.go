package logshell

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"golang.org/x/crypto/ssh"
)

func renewalFixture(t *testing.T) (*ssh.Certificate, *ssh.Certificate, ssh.Signer) {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	_, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	ca, _ := ssh.NewSignerFromKey(caPriv)
	cert := func(exp int64) *ssh.Certificate {
		c := &ssh.Certificate{Key: signer.PublicKey(), Serial: 123, CertType: ssh.UserCert, KeyId: "person", ValidPrincipals: []string{"root"}, ValidAfter: uint64(time.Now().Add(-time.Minute).Unix()), ValidBefore: uint64(exp), Extensions: map[string]string{TerminateOnCertExpiryExtension: "", PermitSessionRenewalExtension: ""}}
		if err := c.SignCert(rand.Reader, ca); err != nil {
			t.Fatal(err)
		}
		return c
	}
	return cert(time.Now().Add(time.Minute).Unix()), cert(time.Now().Add(time.Hour).Unix()), signer
}
func TestRenewalVerificationRejectsReplayAndRestrictionChanges(t *testing.T) {
	original, next, signer := renewalFixture(t)
	challenge := []byte("fresh-session-challenge")
	signature, _ := signer.Sign(rand.Reader, challenge)
	response := renewalResponse{Certificate: string(ssh.MarshalAuthorizedKey(next)), Signature: signature}
	if _, err := verifyRenewal(original, response, challenge, time.Unix(int64(original.ValidBefore), 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyRenewal(original, response, []byte("different-session"), time.Unix(int64(original.ValidBefore), 0)); err == nil {
		t.Fatal("replayed proof accepted")
	}
	next.Extensions["permit-pty"] = ""
	response.Certificate = string(ssh.MarshalAuthorizedKey(next))
	if _, err := verifyRenewal(original, response, challenge, time.Unix(int64(original.ValidBefore), 0)); err == nil {
		t.Fatal("changed restrictions accepted")
	}
}
func TestLeaseExpirationCannotResurrect(t *testing.T) {
	for range 100 {
		lease := NewSessionLease(time.Now().Add(-time.Second))
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); lease.expire() }()
		go func() {
			defer wg.Done()
			if err := lease.extend(time.Now().Add(time.Hour)); err == nil {
				t.Error("expired lease renewed")
			}
		}()
		wg.Wait()
	}
}
func TestRecordingContextFollowsRenewedDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lease := NewSessionLease(time.Now().Add(time.Second))
		spec := RunSpec{Lease: lease}
		ctx, cancel := spec.recordingContext(context.Background())
		defer cancel()
		if err := lease.extend(time.Now().Add(10 * time.Second)); err != nil {
			t.Fatal(err)
		}
		time.Sleep(7 * time.Second)
		synctest.Wait()
		select {
		case <-ctx.Done():
			t.Fatal("recorder canceled at original deadline")
		default:
		}
		time.Sleep(9 * time.Second)
		synctest.Wait()
		select {
		case <-ctx.Done():
		default:
			t.Fatal("recorder did not cancel at renewed deadline")
		}
	})
}

func TestRenewalSocketsIsolateSessionsAndCleanup(t *testing.T) {
	original, next, signer := renewalFixture(t)
	bridgePath := filepath.Join(t.TempDir(), "bridge")
	bridge, err := net.Listen("unix", bridgePath)
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	t.Setenv("CERBERUS_RENEW_SOCKET", bridgePath)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 2 {
			conn, err := bridge.Accept()
			if err != nil {
				return
			}
			var request renewalRequest
			_ = json.NewDecoder(conn).Decode(&request)
			sig, _ := signer.Sign(rand.Reader, request.Challenge)
			_ = json.NewEncoder(conn).Encode(renewalResponse{Certificate: string(ssh.MarshalAuthorizedKey(next)), Signature: sig})
			_ = conn.Close()
		}
	}()
	auth := AuthInfo{Certificate: original}
	deadline := time.Unix(int64(original.ValidBefore), 0)
	first := RunSpec{ExpiryDeadline: deadline, Info: SessionInfo{Auth: auth}}
	second := first
	stop1, err := first.prepareRenewal()
	if err != nil {
		t.Fatal(err)
	}
	defer stop1()
	stop2, err := second.prepareRenewal()
	if err != nil {
		t.Fatal(err)
	}
	defer stop2()
	if first.renewSocket == second.renewSocket {
		t.Fatal("shared socket")
	}
	if _, err := RequestSessionExtension(first.renewSocket); err != nil {
		t.Fatal(err)
	}
	if !second.Lease.Deadline().Equal(deadline) {
		t.Fatal("renewal changed another session")
	}
	if _, err := RequestSessionExtension(second.renewSocket); err != nil {
		t.Fatal(err)
	}
	<-done
	// An incomplete client must not prevent cleanup.
	idle, err := net.Dial("unix", first.renewSocket)
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()
	stopped := make(chan struct{})
	go func() { stop1(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("cleanup blocked")
	}
	if _, err := os.Stat(filepath.Dir(first.renewSocket)); !os.IsNotExist(err) {
		t.Fatalf("socket directory retained: %v", err)
	}
}

func TestRenewalMovesProcessExpiry(t *testing.T) {
	spec := expiryRunSpec(t)
	spec.Lease = NewSessionLease(spec.ExpiryDeadline)
	result := make(chan struct {
		out Outcome
		err error
	}, 1)
	start := time.Now()
	go func() {
		out, err := RunUnrecorded(spec)
		result <- struct {
			out Outcome
			err error
		}{out, err}
	}()
	time.Sleep(100 * time.Millisecond)
	next := start.Add(900 * time.Millisecond)
	if err := spec.Lease.extend(next); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-result:
		t.Fatalf("child ended at original deadline: %+v", got)
	case <-time.After(450 * time.Millisecond):
	}
	got := <-result
	assertExpiryOutcome(t, got.out, got.err, start)
	if time.Now().Before(next) {
		t.Fatal("child ended before renewed deadline")
	}
}

func TestRenewalReschedulesReminders(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.SessionExpirationReminders = "1m"
		lease := NewSessionLease(time.Now().Add(2 * time.Minute))
		spec := RunSpec{Lease: lease, renewSocket: "enrolled"}
		var out expiryNoticeBuffer
		stop := spec.startLeaseExpiryNotice(&out, cfg)
		defer stop()
		time.Sleep(30 * time.Second)
		if err := lease.extend(time.Now().Add(3 * time.Minute)); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if !strings.Contains(out.String(), "Session extended until") {
			t.Fatal("extension confirmation missing")
		}
		time.Sleep(40 * time.Second)
		synctest.Wait()
		if strings.Contains(out.String(), "WARNING") {
			t.Fatal("original reminder fired")
		}
		time.Sleep(81 * time.Second)
		synctest.Wait()
		if !strings.Contains(out.String(), "WARNING") {
			t.Fatal("renewed reminder missing")
		}
	})
}

func TestRenewalSignedVariants(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	key, _ := ssh.NewSignerFromKey(priv)
	_, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	ca, _ := ssh.NewSignerFromKey(caPriv)
	original := &ssh.Certificate{Key: key.PublicKey(), Serial: 7, CertType: ssh.UserCert, KeyId: "person", ValidPrincipals: []string{"root"}, ValidAfter: uint64(time.Now().Add(-time.Hour).Unix()), ValidBefore: uint64(time.Now().Add(time.Minute).Unix()), CriticalOptions: map[string]string{"source-address": "127.0.0.1/32"}, Extensions: map[string]string{PermitSessionRenewalExtension: "", TerminateOnCertExpiryExtension: ""}}
	_ = original.SignCert(rand.Reader, ca)
	challenge := []byte("challenge")
	proof, _ := key.Sign(rand.Reader, challenge)
	for _, name := range []string{"ca", "key", "id", "principal", "critical", "flag", "infinite", "future", "unchanged", "signature"} {
		t.Run(name, func(t *testing.T) {
			next := *original
			next.Extensions = map[string]string{PermitSessionRenewalExtension: "", TerminateOnCertExpiryExtension: ""}
			next.CriticalOptions = map[string]string{"source-address": "127.0.0.1/32"}
			next.ValidBefore += 3600
			signer := ca
			switch name {
			case "ca":
				_, priv, _ := ed25519.GenerateKey(rand.Reader)
				signer, _ = ssh.NewSignerFromKey(priv)
			case "key":
				_, priv, _ := ed25519.GenerateKey(rand.Reader)
				s, _ := ssh.NewSignerFromKey(priv)
				next.Key = s.PublicKey()
			case "id":
				next.KeyId = "another"
			case "principal":
				next.ValidPrincipals = []string{"other"}
			case "critical":
				next.CriticalOptions["source-address"] = "0.0.0.0/0"
			case "flag":
				delete(next.Extensions, PermitSessionRenewalExtension)
			case "infinite":
				next.ValidBefore = ssh.CertTimeInfinity
			case "future":
				next.ValidAfter = uint64(time.Now().Add(time.Hour).Unix())
			case "unchanged":
				next.ValidBefore = original.ValidBefore
			}
			_ = next.SignCert(rand.Reader, signer)
			response := renewalResponse{Certificate: string(ssh.MarshalAuthorizedKey(&next)), Signature: proof}
			if name == "signature" {
				response.Signature = &ssh.Signature{Format: proof.Format, Blob: []byte("forged")}
			}
			if _, err := verifyRenewal(original, response, challenge, time.Unix(int64(original.ValidBefore), 0)); err == nil {
				t.Fatal("invalid renewal accepted")
			}
		})
	}
}

// certFactory signs test certificates for one key under one CA.
type certFactory struct {
	t      *testing.T
	signer ssh.Signer
	ca     ssh.Signer
}

func newCertFactory(t *testing.T) *certFactory {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	return &certFactory{t: t, signer: signer, ca: newTestSigner()}
}
func newTestSigner() ssh.Signer {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, _ := ssh.NewSignerFromKey(priv)
	return s
}

// make returns a certificate expiring at exp, modified by mod and signed by
// signer (the factory's CA when nil).
func (f *certFactory) make(exp time.Time, mod func(*ssh.Certificate), signer ssh.Signer) *ssh.Certificate {
	f.t.Helper()
	c := &ssh.Certificate{Key: f.signer.PublicKey(), Serial: 9, CertType: ssh.UserCert, KeyId: "person", ValidPrincipals: []string{"root"}, ValidAfter: uint64(time.Now().Add(-2 * time.Hour).Unix()), ValidBefore: uint64(exp.Unix()), Extensions: map[string]string{TerminateOnCertExpiryExtension: "", PermitSessionRenewalExtension: ""}}
	if mod != nil {
		mod(c)
	}
	if signer == nil {
		signer = f.ca
	}
	if err := c.SignCert(rand.Reader, signer); err != nil {
		f.t.Fatal(err)
	}
	return c
}
func certText(c *ssh.Certificate) string { return string(ssh.MarshalAuthorizedKey(c)) }

// fakeSupervisor serves one watch connection: it reads the request, runs send,
// then waits for the peer to close and reports that on closed.
func fakeSupervisor(t *testing.T, send func(net.Conn)) (path string, closed <-chan struct{}) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "outer")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	done := make(chan struct{})
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		var req socketRequest
		if err := json.NewDecoder(c).Decode(&req); err != nil || !req.Watch {
			close(done)
			return
		}
		send(c)
		_, _ = io.Copy(io.Discard, c)
		close(done)
	}()
	return path, done
}
func sendCerts(certs ...*ssh.Certificate) func(net.Conn) {
	return func(c net.Conn) {
		for _, cert := range certs {
			_ = json.NewEncoder(c).Encode(renewalResponse{Certificate: certText(cert), Expiration: time.Unix(int64(cert.ValidBefore), 0)})
		}
	}
}
func waitDeadline(t *testing.T, lease *SessionLease, want time.Time) {
	t.Helper()
	for range 200 {
		if lease.Deadline().Equal(want) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("deadline = %v, want %v", lease.Deadline(), want)
}

func TestWatchStreamsCurrentCertificateAndClosesOnCleanup(t *testing.T) {
	original, next, signer := renewalFixture(t)
	bridgePath := filepath.Join(t.TempDir(), "bridge")
	bridge, err := net.Listen("unix", bridgePath)
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	t.Setenv("CERBERUS_RENEW_SOCKET", bridgePath)
	go func() {
		conn, err := bridge.Accept()
		if err != nil {
			return
		}
		var request renewalRequest
		_ = json.NewDecoder(conn).Decode(&request)
		sig, _ := signer.Sign(rand.Reader, request.Challenge)
		_ = json.NewEncoder(conn).Encode(renewalResponse{Certificate: certText(next), Signature: sig})
		_ = conn.Close()
	}()
	deadline := time.Unix(int64(original.ValidBefore), 0)
	spec := RunSpec{ExpiryDeadline: deadline, Info: SessionInfo{Auth: AuthInfo{Certificate: original}}}
	stop, err := spec.prepareRenewal()
	if err != nil {
		t.Fatal(err)
	}
	stopped := false
	defer func() {
		if !stopped {
			stop()
		}
	}()
	conn, err := net.Dial("unix", spec.renewSocket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := json.NewEncoder(conn).Encode(socketRequest{Watch: true}); err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(conn)
	var first, second renewalResponse
	if err := dec.Decode(&first); err != nil {
		t.Fatal(err)
	}
	if first.Certificate != certText(original) || !first.Expiration.Equal(deadline) {
		t.Fatalf("first message = %+v", first)
	}
	if _, err := RequestSessionExtension(spec.renewSocket); err != nil {
		t.Fatal(err)
	}
	if err := dec.Decode(&second); err != nil {
		t.Fatal(err)
	}
	if second.Certificate != certText(next) || !second.Expiration.Equal(time.Unix(int64(next.ValidBefore), 0)) {
		t.Fatalf("second message = %+v", second)
	}
	stop()
	stopped = true
	if err := dec.Decode(&second); err == nil {
		t.Fatal("watch connection survived cleanup")
	}
}

func TestWatchDoesNotConsumeRenewalSlotsAndIsCapped(t *testing.T) {
	original, _, _ := renewalFixture(t)
	t.Setenv("CERBERUS_RENEW_SOCKET", filepath.Join(t.TempDir(), "nobridge"))
	spec := RunSpec{ExpiryDeadline: time.Unix(int64(original.ValidBefore), 0), Info: SessionInfo{Auth: AuthInfo{Certificate: original}}}
	stop, err := spec.prepareRenewal()
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	var conns []net.Conn
	for range maxWatchSlots + 3 {
		c, err := net.Dial("unix", spec.renewSocket)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = json.NewEncoder(c).Encode(socketRequest{Watch: true})
		conns = append(conns, c)
	}
	alive := 0
	for _, c := range conns {
		_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		var r renewalResponse
		if json.NewDecoder(c).Decode(&r) == nil {
			alive++
		}
	}
	if alive != maxWatchSlots {
		t.Fatalf("%d watches served, want %d", alive, maxWatchSlots)
	}
	// Renewal still has its own slots: the bridge is absent, so it fails, but
	// with a bridge error rather than being refused for lack of capacity.
	if _, err := RequestSessionExtension(spec.renewSocket); err == nil || strings.Contains(err.Error(), "too many") {
		t.Fatalf("renewal err = %v", err)
	}
}

func TestFollowerExtendsOnValidRenewalAndIgnoresOthers(t *testing.T) {
	f := newCertFactory(t)
	t.Setenv("CERBERUS_RENEW_SOCKET", "")
	now := time.Now()
	original := f.make(now.Add(time.Minute), nil, nil)
	deadline := time.Unix(int64(original.ValidBefore), 0)
	later := f.make(now.Add(time.Hour), nil, nil)
	laterDeadline := time.Unix(int64(later.ValidBefore), 0)
	otherKey := newCertFactory(t)
	stale := f.make(now.Add(30*time.Second), nil, nil)

	t.Run("valid renewal", func(t *testing.T) {
		path, _ := fakeSupervisor(t, sendCerts(original, stale, later))
		t.Setenv("LOGSH_RENEW_SOCKET", path)
		spec := RunSpec{ExpiryDeadline: deadline, Info: SessionInfo{Auth: AuthInfo{Certificate: original}}}
		stop, err := spec.prepareRenewal()
		if err != nil {
			t.Fatal(err)
		}
		defer stop()
		waitDeadline(t, spec.Lease, laterDeadline)
		if c, _, _, _ := spec.Lease.watchSnapshot(); certText(c) != certText(later) {
			t.Fatal("lease certificate not updated")
		}
	})
	rejects := map[string]*ssh.Certificate{
		"different CA":  f.make(now.Add(time.Hour), nil, newTestSigner()),
		"different key": otherKey.make(now.Add(time.Hour), nil, f.ca),
		"key id":        f.make(now.Add(time.Hour), func(c *ssh.Certificate) { c.KeyId = "other" }, nil),
		"principals":    f.make(now.Add(time.Hour), func(c *ssh.Certificate) { c.ValidPrincipals = []string{"admin"} }, nil),
		"extensions": f.make(now.Add(time.Hour), func(c *ssh.Certificate) {
			c.Extensions["permit-pty"] = ""
		}, nil),
	}
	for name, bad := range rejects {
		t.Run(name, func(t *testing.T) {
			path, closed := fakeSupervisor(t, sendCerts(bad))
			t.Setenv("LOGSH_RENEW_SOCKET", path)
			spec := RunSpec{ExpiryDeadline: deadline, Info: SessionInfo{Auth: AuthInfo{Certificate: original}}}
			stop, err := spec.prepareRenewal()
			if err != nil {
				t.Fatal(err)
			}
			defer stop()
			select {
			case <-closed:
			case <-time.After(3 * time.Second):
				t.Fatal("follower kept listening after a bad certificate")
			}
			if !spec.Lease.Deadline().Equal(deadline) {
				t.Fatalf("deadline changed to %v", spec.Lease.Deadline())
			}
		})
	}
	t.Run("garbage", func(t *testing.T) {
		path, closed := fakeSupervisor(t, func(c net.Conn) { _, _ = c.Write([]byte("{{{ not json\x00\xff")) })
		t.Setenv("LOGSH_RENEW_SOCKET", path)
		spec := RunSpec{ExpiryDeadline: deadline, Info: SessionInfo{Auth: AuthInfo{Certificate: original}}}
		stop, err := spec.prepareRenewal()
		if err != nil {
			t.Fatal(err)
		}
		defer stop()
		select {
		case <-closed:
		case <-time.After(3 * time.Second):
			t.Fatal("follower kept listening after garbage")
		}
		if !spec.Lease.Deadline().Equal(deadline) {
			t.Fatal("deadline changed")
		}
	})
	t.Run("stop", func(t *testing.T) {
		path, closed := fakeSupervisor(t, sendCerts(original))
		t.Setenv("LOGSH_RENEW_SOCKET", path)
		spec := RunSpec{ExpiryDeadline: deadline, Info: SessionInfo{Auth: AuthInfo{Certificate: original}}}
		stop, _ := spec.prepareRenewal()
		stop()
		select {
		case <-closed:
		case <-time.After(3 * time.Second):
			t.Fatal("cleanup did not close the follower")
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("outer socket was removed: %v", err)
		}
	})
}

func TestChildEnvRenewalSockets(t *testing.T) {
	env := []string{"A=1", "LOGSH_RENEW_SOCKET=/inherited", "CERBERUS_RENEW_SOCKET=/bridge"}
	has := func(env []string, prefix string) string {
		for _, v := range env {
			if strings.HasPrefix(v, prefix) {
				return v
			}
		}
		return ""
	}
	got := RunSpec{renewSocket: "/own"}.childEnv(env)
	if has(got, "LOGSH_RENEW_SOCKET=") != "LOGSH_RENEW_SOCKET=/own" || has(got, "CERBERUS_RENEW_SOCKET=") != "" || has(got, "A=1") == "" {
		t.Fatalf("env = %v", got)
	}
	got = RunSpec{}.childEnv(env)
	if has(got, "LOGSH_RENEW_SOCKET=") != "" || has(got, "CERBERUS_RENEW_SOCKET=") != "" {
		t.Fatalf("env = %v", got)
	}
	// Following: the inherited path is passed through.
	original, _, _ := renewalFixture(t)
	t.Setenv("CERBERUS_RENEW_SOCKET", "")
	t.Setenv("LOGSH_RENEW_SOCKET", filepath.Join(t.TempDir(), "gone"))
	spec := RunSpec{ExpiryDeadline: time.Unix(int64(original.ValidBefore), 0), Info: SessionInfo{Auth: AuthInfo{Certificate: original}}}
	stop, err := spec.prepareRenewal()
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	if got := spec.childEnv(env); has(got, "LOGSH_RENEW_SOCKET=") != "LOGSH_RENEW_SOCKET="+os.Getenv("LOGSH_RENEW_SOCKET") {
		t.Fatalf("env = %v", got)
	}
}

func TestPrepareRenewalDegradesWhenTempDirUnusable(t *testing.T) {
	original, _, _ := renewalFixture(t)
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "missing"))
	t.Setenv("CERBERUS_RENEW_SOCKET", "/some/bridge")
	spec := RunSpec{ExpiryDeadline: time.Unix(int64(original.ValidBefore), 0), Info: SessionInfo{Auth: AuthInfo{Certificate: original}}}
	stop, err := spec.prepareRenewal()
	if err != nil {
		t.Fatalf("setup failure aborted the session: %v", err)
	}
	if stop == nil || spec.renewSocket != "" {
		t.Fatal("expected a no-op cleanup and no socket")
	}
	stop()
}

func TestSessionDeadline(t *testing.T) {
	f := newCertFactory(t)
	now := time.Now()
	original := f.make(now.Add(-5*time.Second), nil, nil)
	renewed := f.make(now.Add(time.Hour), nil, nil)
	auth := func(c *ssh.Certificate) AuthInfo {
		return AuthInfo{Method: AuthMethodCert, ValidBefore: c.ValidBefore, Extensions: c.Extensions, Certificate: c}
	}
	t.Run("renewed by outer supervisor", func(t *testing.T) {
		path, _ := fakeSupervisor(t, sendCerts(renewed))
		t.Setenv("LOGSH_RENEW_SOCKET", path)
		got, err := SessionDeadline(auth(original), now)
		if err != nil || !got.Equal(time.Unix(int64(renewed.ValidBefore), 0)) {
			t.Fatalf("got %v, %v", got, err)
		}
	})
	t.Run("no socket", func(t *testing.T) {
		t.Setenv("LOGSH_RENEW_SOCKET", "")
		if _, err := SessionDeadline(auth(original), now); err == nil || !strings.Contains(err.Error(), "expired") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("bad certificate", func(t *testing.T) {
		path, _ := fakeSupervisor(t, sendCerts(f.make(now.Add(time.Hour), nil, newTestSigner())))
		t.Setenv("LOGSH_RENEW_SOCKET", path)
		if _, err := SessionDeadline(auth(original), now); err == nil || !strings.Contains(err.Error(), "expired") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("renewal already past", func(t *testing.T) {
		path, _ := fakeSupervisor(t, sendCerts(f.make(now.Add(-time.Second), nil, nil)))
		t.Setenv("LOGSH_RENEW_SOCKET", path)
		if _, err := SessionDeadline(auth(original), now); err == nil {
			t.Fatal("expired renewal accepted")
		}
	})
	t.Run("malformed policy not rescued", func(t *testing.T) {
		path, _ := fakeSupervisor(t, sendCerts(renewed))
		t.Setenv("LOGSH_RENEW_SOCKET", path)
		a := auth(original)
		a.Extensions = map[string]string{TerminateOnCertExpiryExtension: "true", PermitSessionRenewalExtension: ""}
		if _, err := SessionDeadline(a, now); err == nil || strings.Contains(err.Error(), "expired") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestRecordingContextCancelsAfterDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		spec := RunSpec{Lease: NewSessionLease(time.Now().Add(time.Minute))}
		ctx, cancel := spec.recordingContext(context.Background())
		defer cancel()
		time.Sleep(time.Minute + 4*time.Second)
		synctest.Wait()
		if ctx.Err() != nil {
			t.Fatal("canceled before deadline+5s")
		}
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if ctx.Err() == nil {
			t.Fatal("not canceled after deadline+5s")
		}
	})
}
