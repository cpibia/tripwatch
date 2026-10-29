package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Users before roles are administrators; an invitation makes a user with its role once; the
// last administrator can be neither demoted nor removed; the audit log keeps the newest first.
func TestAccess(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	if err := s.SetUser(ctx, "Admin@example.net", "a long enough password", t0); err != nil {
		t.Fatal(err)
	}
	if role, _ := s.UserRole(ctx, "admin@example.net"); role != RoleAdmin {
		t.Fatalf("first user is %q", role)
	}
	if err := s.SetRole(ctx, "admin@example.net", RoleViewer); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("demoting the last admin: %v", err)
	}
	if err := s.DeleteUser(ctx, "admin@example.net"); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("removing the last admin: %v", err)
	}
	if _, _, err := s.CreateInvite(ctx, "admin@example.net", RoleViewer, "admin@example.net", t0); !errors.Is(err, ErrUserExists) {
		t.Fatalf("inviting an existing user: %v", err)
	}
	token, _, err := s.CreateInvite(ctx, " Ops@Example.net", RoleOperator, "admin@example.net", t0)
	if err != nil {
		t.Fatal(err)
	}
	if email, role, err := s.Invite(ctx, token, t0); err != nil || email != "ops@example.net" || role != RoleOperator {
		t.Fatalf("invite = %q %q %v", email, role, err)
	}
	if _, _, err := s.AcceptInvite(ctx, token, "short", t0); err == nil {
		t.Fatal("short password accepted")
	}
	if _, _, err := s.AcceptInvite(ctx, token, "another long password", t0.Add(InviteLifetime)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired invite: %v", err)
	}
	email, session, err := s.AcceptInvite(ctx, token, "another long password", t0.Add(time.Hour))
	if err != nil || email != "ops@example.net" || session == "" {
		t.Fatalf("accept = %q %v", email, err)
	}
	if _, _, err := s.AcceptInvite(ctx, token, "another long password", t0.Add(time.Hour)); !errors.Is(err, ErrNotFound) {
		t.Fatal("invite used twice")
	}
	if !RoleAtLeast(RoleOperator, RoleViewer) || RoleAtLeast(RoleOperator, RoleAdmin) || RoleAtLeast("root", RoleViewer) {
		t.Error("role order")
	}
	if err := s.SetRole(ctx, "ops@example.net", RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRole(ctx, "admin@example.net", RoleViewer); err != nil {
		t.Fatalf("demoting with another admin: %v", err)
	}
	if err := s.DeleteUser(ctx, "admin@example.net"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Session(ctx, session, t0.Add(time.Hour)); err != nil {
		t.Errorf("the other user's session was ended: %v", err)
	}
	for i, action := range []string{"invite", "role", "remove"} {
		if err := s.Audit(ctx, "ops@example.net", action, "admin@example.net", "", t0.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	if log, _ := s.AuditLog(ctx, 2); len(log) != 2 || log[0].Action != "remove" || log[1].Action != "role" {
		t.Errorf("audit log %+v", log)
	}
}
