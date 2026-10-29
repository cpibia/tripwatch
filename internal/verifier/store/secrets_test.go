package store

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

// Channels' secrets are sealed once a key is set, those stored before included; the database
// alone holds none of them, and a channel sealed with another key is listed as unreadable
// without taking the others with it.
func TestChannelSettingsSealed(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	if _, err := s.AddChannel(ctx, Channel{Kind: ChannelTelegram, Name: "before", Settings: ChannelSettings{BotToken: "bot-token-before", ChatID: "1"}, MinSeverity: "high"}, t0); err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{7}, SecretsKeySize)
	if err := s.SetSecretsKey(ctx, key); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddChannel(ctx, Channel{Kind: ChannelWebhook, Name: "after", Settings: ChannelSettings{URL: "https://hooks.example/x", Secret: "webhook-secret-after"}, MinSeverity: "high"}, t0); err != nil {
		t.Fatal(err)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT settings FROM channels`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var raw string
		_ = rows.Scan(&raw)
		if !strings.HasPrefix(raw, sealedPrefix) || strings.Contains(raw, "bot-token") || strings.Contains(raw, "webhook-secret") {
			t.Errorf("stored in the open: %q", raw)
		}
	}
	_ = rows.Close()
	all, err := s.Channels(ctx)
	if err != nil || len(all) != 2 || all[0].Settings.BotToken != "bot-token-before" || all[1].Settings.Secret != "webhook-secret-after" || all[0].Unreadable {
		t.Fatalf("channels = %+v, %v", all, err)
	}

	other := open(t)
	other.db, other.read = s.db, s.read
	if err := other.SetSecretsKey(ctx, bytes.Repeat([]byte{8}, SecretsKeySize)); err != nil {
		t.Fatal(err)
	}
	all, err = other.Channels(ctx)
	if err != nil || len(all) != 2 || !all[0].Unreadable || all[0].Settings.BotToken != "" || !strings.Contains(all[0].LastError, "another secrets key") {
		t.Fatalf("with another key: %+v, %v", all, err)
	}
	if err := s.SetSecretsKey(ctx, []byte("short")); err == nil {
		t.Error("a short key accepted")
	}
}
