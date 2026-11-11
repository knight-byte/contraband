package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const (
	KindFlow           = "flow"
	KindAlert          = "alert"
	KindHealth         = "health"
	KindSessionStart   = "session_start"
	KindSessionEnd     = "session_end"
	KindPolicyApproved = "policy_approved"
)

var ErrBrokenChain = errors.New("hash chain broken")

const schema = `
CREATE TABLE IF NOT EXISTS log (
	seq     INTEGER PRIMARY KEY,
	time    TEXT NOT NULL,
	kind    TEXT NOT NULL,
	session TEXT NOT NULL,
	body    BLOB NOT NULL,
	prev    BLOB NOT NULL,
	hash    BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS log_session ON log(session, kind);
CREATE TRIGGER IF NOT EXISTS log_no_update BEFORE UPDATE ON log BEGIN SELECT RAISE(ABORT, 'log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS log_no_delete BEFORE DELETE ON log BEGIN SELECT RAISE(ABORT, 'log is append-only'); END;
`

type Record struct {
	Seq     int64           `json:"seq"`
	Time    time.Time       `json:"time"`
	Kind    string          `json:"kind"`
	Session string          `json:"session,omitempty"`
	Body    json.RawMessage `json:"body"`
	Hash    []byte          `json:"hash"`
}

// Store is an append-only, hash-chained log: editing or deleting a
// row breaks every hash after it. Triggers stop casual edits; the chain
// catches anyone who drops them.
type Store struct {
	db       *sql.DB
	mu       sync.Mutex
	lastHash []byte
}

func Open(ctx context.Context, path string) (*Store, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600) //nolint:gosec // path comes from the daemon's own configuration
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, schema); err != nil {
		return nil, errors.Join(fmt.Errorf("init store: %w", err), db.Close())
	}
	opened := &Store{db: db, lastHash: make([]byte, sha256.Size)}
	err = db.QueryRowContext(ctx, `SELECT hash FROM log ORDER BY seq DESC LIMIT 1`).Scan(&opened.lastHash)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, errors.Join(fmt.Errorf("init store: %w", err), db.Close())
	}
	return opened, nil
}

func (store *Store) Close() error { return store.db.Close() }

// chainHash length-prefixes every field so no two records can hash the same.
func chainHash(prevHash []byte, seq int64, timestamp, kind, session string, body []byte) []byte {
	hasher := sha256.New()
	hasher.Write(prevHash)
	hasher.Write(binary.BigEndian.AppendUint64(nil, uint64(seq))) //nolint:gosec // seq is a positive rowid
	for _, field := range [][]byte{[]byte(timestamp), []byte(kind), []byte(session), body} {
		hasher.Write(binary.BigEndian.AppendUint32(nil, uint32(len(field)))) //nolint:gosec // fields are far below 4 GiB
		hasher.Write(field)
	}
	return hasher.Sum(nil)
}

func (store *Store) Append(ctx context.Context, kind, session string, value any) error {
	body, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("append %s: %w", kind, err)
	}
	timestamp := time.Now().UTC().Format(time.RFC3339Nano)

	store.mu.Lock()
	defer store.mu.Unlock()
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("append %s: %w", kind, err)
	}
	var seq int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(seq), 0) + 1 FROM log`).Scan(&seq); err != nil {
		return errors.Join(fmt.Errorf("append %s: %w", kind, err), tx.Rollback())
	}
	hash := chainHash(store.lastHash, seq, timestamp, kind, session, body)
	if _, err := tx.ExecContext(ctx, `INSERT INTO log (seq, time, kind, session, body, prev, hash) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		seq, timestamp, kind, session, body, store.lastHash, hash); err != nil {
		return errors.Join(fmt.Errorf("append %s: %w", kind, err), tx.Rollback())
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("append %s: %w", kind, err)
	}
	store.lastHash = hash
	return nil
}

// Each streams records in order; with verify set it fails on the first record
// whose hash does not follow from the one before.
func (store *Store) Each(ctx context.Context, verify bool, visit func(Record) error) error {
	rows, err := store.db.QueryContext(ctx, `SELECT seq, time, kind, session, body, prev, hash FROM log ORDER BY seq`)
	if err != nil {
		return fmt.Errorf("read log: %w", err)
	}
	defer rows.Close() //nolint:errcheck // read-only cursor
	expectedPrev := make([]byte, sha256.Size)
	for rows.Next() {
		var record Record
		var timestamp string
		var body, prevHash []byte
		if err := rows.Scan(&record.Seq, &timestamp, &record.Kind, &record.Session, &body, &prevHash, &record.Hash); err != nil {
			return fmt.Errorf("read log: %w", err)
		}
		record.Body = body
		if verify {
			want := chainHash(expectedPrev, record.Seq, timestamp, record.Kind, record.Session, record.Body)
			if !bytes.Equal(prevHash, expectedPrev) || !bytes.Equal(want, record.Hash) {
				return fmt.Errorf("seq %d: %w", record.Seq, ErrBrokenChain)
			}
			expectedPrev = record.Hash
		}
		if record.Time, err = time.Parse(time.RFC3339Nano, timestamp); err != nil {
			return fmt.Errorf("read log seq %d: %w", record.Seq, err)
		}
		if err := visit(record); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read log: %w", err)
	}
	return nil
}

func (store *Store) Verify(ctx context.Context) error {
	return store.Each(ctx, true, func(Record) error { return nil })
}

func (store *Store) Bodies(ctx context.Context, session, kind string) ([]json.RawMessage, error) {
	rows, err := store.db.QueryContext(ctx, `SELECT body FROM log WHERE session = ? AND kind = ? ORDER BY seq`, session, kind)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", kind, err)
	}
	defer rows.Close() //nolint:errcheck // read-only cursor
	var bodies []json.RawMessage
	for rows.Next() {
		var body []byte
		if err := rows.Scan(&body); err != nil {
			return nil, fmt.Errorf("read %s: %w", kind, err)
		}
		bodies = append(bodies, body)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", kind, err)
	}
	return bodies, nil
}

// PreviousSession returns the latest earlier session of the same uid that ran
// the same command in the same directory, or "".
func (store *Store) PreviousSession(ctx context.Context, uid uint32, command, cwd, exclude string) (string, error) {
	var id string
	err := store.db.QueryRowContext(ctx, `
		SELECT session FROM log
		WHERE kind = ? AND session <> ?
		  AND json_extract(body, '$.uid') = ? AND json_extract(body, '$.command') = ? AND json_extract(body, '$.cwd') = ?
		ORDER BY seq DESC LIMIT 1`, KindSessionStart, exclude, uid, command, cwd).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("previous session: %w", err)
	}
	return id, nil
}
