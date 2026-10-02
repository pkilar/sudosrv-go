package logshell

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
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
