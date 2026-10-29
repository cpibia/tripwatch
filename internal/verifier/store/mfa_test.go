package store

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func codeAt(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	key, err := b32.DecodeString(secret)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%06d", totp(key, at.Unix()/totpStep))
}

// The RFC 6238 test vector for SHA-1: the computation matches every authenticator app.
func TestTOTPVector(t *testing.T) {
	if got := totp([]byte("12345678901234567890"), 59/totpStep); got != 287082 {
		t.Fatalf("code at 59 s = %06d, want 287082", got)
	}
}

// A second factor turns on with a code from the new secret; sign-ins then wait for a code, which
// works once; a recovery code works once; wrong codes end the waiting session.
func TestSecondFactor(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	const user = "admin@example.net"
	if err := s.SetUser(ctx, user, "a long enough password", t0); err != nil {
		t.Fatal(err)
	}
	secret, err := s.BeginTOTP(ctx, user)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConfirmTOTP(ctx, user, "000000", t0); !errors.Is(err, ErrBadCode) {
		t.Fatalf("wrong confirmation: %v", err)
	}
	codes, err := s.ConfirmTOTP(ctx, user, codeAt(t, secret, t0), t0)
	if err != nil || len(codes) != recoveryCodes {
		t.Fatalf("confirm: %v %d", err, len(codes))
	}

	at := t0.Add(time.Hour)
	token, err := s.Login(ctx, user, "a long enough password", at)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Session(ctx, token, at); !errors.Is(err, ErrSecondFactorRequired) {
		t.Fatalf("session before the code: %v", err)
	}
	code := codeAt(t, secret, at)
	if err := s.CheckSecondFactor(ctx, user, code, at); err != nil {
		t.Fatalf("right code: %v", err)
	}
	if err := s.CheckSecondFactor(ctx, user, code, at); !errors.Is(err, ErrBadCode) {
		t.Fatal("a code worked twice")
	}
	if err := s.CompleteSecondFactor(ctx, token); err != nil {
		t.Fatal(err)
	}
	if email, err := s.Session(ctx, token, at); err != nil || email != user {
		t.Fatalf("session after the code: %q %v", email, err)
	}
	if err := s.CheckSecondFactor(ctx, user, codes[0], at); err != nil {
		t.Fatalf("recovery code: %v", err)
	}
	if err := s.CheckSecondFactor(ctx, user, codes[0], at); !errors.Is(err, ErrBadCode) {
		t.Fatal("a recovery code worked twice")
	}
	if n, _ := s.RecoveryCodesLeft(ctx, user); n != recoveryCodes-1 {
		t.Errorf("%d recovery codes left", n)
	}

	other, _ := s.Login(ctx, user, "a long enough password", at)
	for i := range MaxSecondFactorFailures {
		alive, err := s.FailSecondFactor(ctx, other)
		if err != nil {
			t.Fatal(err)
		}
		if alive != (i < MaxSecondFactorFailures-1) {
			t.Fatalf("after %d failures alive = %v", i+1, alive)
		}
	}
	if _, err := s.Session(ctx, other, at); !errors.Is(err, ErrNotFound) {
		t.Fatalf("session after too many failures: %v", err)
	}

	sessions, err := s.UserSessions(ctx, user, token, at)
	if err != nil || len(sessions) != 1 || !sessions[0].Current {
		t.Fatalf("sessions %+v %v", sessions, err)
	}
	if err := s.EndSession(ctx, user, sessions[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DisableTOTP(ctx, user); err != nil {
		t.Fatal(err)
	}
	if on, _ := s.TOTPEnabled(ctx, user); on {
		t.Error("still on")
	}
	plain, _ := s.Login(ctx, user, "a long enough password", at)
	if _, err := s.Session(ctx, plain, at); err != nil {
		t.Errorf("sign-in without a second factor: %v", err)
	}
}
