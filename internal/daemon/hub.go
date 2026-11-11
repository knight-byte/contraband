package daemon

import (
	"sync"

	"github.com/knight-byte/contraband/internal/event"
)

type Message struct {
	Flow  *event.Flow  `json:"flow,omitempty"`
	Alert *event.Alert `json:"alert,omitempty"`
}

// visibleTo shows a user their own traffic and alerts plus system health
// alerts; root sees everything.
func (msg Message) visibleTo(caller peer, session string) bool {
	switch {
	case msg.Flow != nil:
		return (session == "" || msg.Flow.Session == session) && caller.canAccess(msg.Flow.UID)
	case msg.Alert != nil && msg.Alert.Session == "":
		return msg.Alert.Level == "health" || caller.isRoot()
	case msg.Alert != nil:
		return (session == "" || msg.Alert.Session == session) && caller.canAccess(msg.Alert.UID)
	}
	return false
}

const subscriberBuffer = 256

// hub fans messages out to stream clients. A client that falls behind loses
// messages rather than stalling the event pipeline; the log keeps everything.
type hub struct {
	mu          sync.Mutex
	subscribers map[chan Message]struct{}
}

func newHub() hub { return hub{subscribers: map[chan Message]struct{}{}} }

func (broadcast *hub) subscribe() chan Message {
	subscription := make(chan Message, subscriberBuffer)
	broadcast.mu.Lock()
	broadcast.subscribers[subscription] = struct{}{}
	broadcast.mu.Unlock()
	return subscription
}

func (broadcast *hub) unsubscribe(subscription chan Message) {
	broadcast.mu.Lock()
	delete(broadcast.subscribers, subscription)
	broadcast.mu.Unlock()
}

func (broadcast *hub) publish(msg Message) {
	broadcast.mu.Lock()
	defer broadcast.mu.Unlock()
	for subscription := range broadcast.subscribers {
		select {
		case subscription <- msg:
		default:
		}
	}
}
