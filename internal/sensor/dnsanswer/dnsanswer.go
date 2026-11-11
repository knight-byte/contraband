package dnsanswer

import (
	"net/netip"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/knight-byte/contraband/internal/event"
)

// Parse turns a DNS response payload into a DNS event naming the queried host
// and its A/AAAA addresses, with the shortest answer TTL.
func Parse(when time.Time, payload []byte) (event.Event, bool) {
	var parser dnsmessage.Parser
	header, err := parser.Start(payload)
	if err != nil || !header.Response || header.RCode != dnsmessage.RCodeSuccess {
		return event.Event{}, false
	}
	question, err := parser.Question()
	if err != nil || parser.SkipAllQuestions() != nil {
		return event.Event{}, false
	}
	evt := event.Event{Time: when, Kind: event.DNS, Name: question.Name.String()}
	for {
		answer, err := parser.AnswerHeader()
		if err != nil {
			break
		}
		switch answer.Type {
		case dnsmessage.TypeA:
			record, err := parser.AResource()
			if err != nil {
				return event.Event{}, false
			}
			evt.Addrs = append(evt.Addrs, netip.AddrFrom4(record.A))
		case dnsmessage.TypeAAAA:
			record, err := parser.AAAAResource()
			if err != nil {
				return event.Event{}, false
			}
			evt.Addrs = append(evt.Addrs, netip.AddrFrom16(record.AAAA))
		default:
			if parser.SkipAnswer() != nil {
				return event.Event{}, false
			}
			continue
		}
		if evt.TTL == 0 || answer.TTL < evt.TTL {
			evt.TTL = answer.TTL
		}
	}
	return evt, len(evt.Addrs) > 0
}
