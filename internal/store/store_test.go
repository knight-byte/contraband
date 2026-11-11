package store_test

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/knight-byte/contraband/internal/store"
)

func TestHashChain(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "events.db")
	db, err := store.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	for _, msg := range []string{"one", "two", "three"} {
		if err := db.Append(ctx, store.KindAlert, "session", map[string]string{"msg": msg}); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Verify(ctx); err != nil {
		t.Fatalf("fresh log: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := store.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Append(ctx, store.KindAlert, "session", map[string]string{"msg": "four"}); err != nil {
		t.Fatal(err)
	}
	if err := reopened.Verify(ctx); err != nil {
		t.Fatalf("after reopen: %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}

	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.ExecContext(ctx, `UPDATE log SET body = '{"msg":"edited"}' WHERE seq = 2`); err == nil {
		t.Fatal("update allowed on append-only log")
	}
	for _, stmt := range []string{`DROP TRIGGER log_no_update`, `UPDATE log SET body = '{"msg":"edited"}' WHERE seq = 2`} {
		if _, err := raw.ExecContext(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	tampered, err := store.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer tampered.Close() //nolint:errcheck // test cleanup
	if err := tampered.Verify(ctx); !errors.Is(err, store.ErrBrokenChain) {
		t.Fatalf("tampered log: got %v, want %v", err, store.ErrBrokenChain)
	}
}
