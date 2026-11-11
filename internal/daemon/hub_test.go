package daemon

import (
	"testing"

	"github.com/knight-byte/contraband/internal/event"
)

func TestVisibleTo(t *testing.T) {
	owner := peer{UID: 501, ok: true}
	other := peer{UID: 502, ok: true}
	root := peer{UID: 0, ok: true}
	unknown := peer{}

	ownFlow := Message{Flow: &event.Flow{Session: "s1", UID: 501}}
	ownAlert := Message{Alert: &event.Alert{Session: "s1", UID: 501, Level: "alert"}}
	health := Message{Alert: &event.Alert{Level: "health"}}

	tests := []struct {
		name    string
		msg     Message
		caller  peer
		session string
		want    bool
	}{
		{"owner sees own flow", ownFlow, owner, "", true},
		{"owner sees own session flow", ownFlow, owner, "s1", true},
		{"session filter excludes others", ownFlow, owner, "s2", false},
		{"other user cannot see flow", ownFlow, other, "", false},
		{"other user cannot see flow by session id", ownFlow, other, "s1", false},
		{"other user cannot see alert by session id", ownAlert, other, "s1", false},
		{"root sees everything", ownAlert, root, "", true},
		{"health is visible to every user", health, other, "", true},
		{"unauthenticated peer sees nothing", ownFlow, unknown, "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.msg.visibleTo(tc.caller, tc.session); got != tc.want {
				t.Fatalf("visibleTo = %v, want %v", got, tc.want)
			}
		})
	}
}
