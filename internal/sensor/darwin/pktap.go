package darwin

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/knight-byte/contraband/internal/event"
	"github.com/knight-byte/contraband/internal/sensor/dnsanswer"
)

const (
	protoTCP = 6
	protoUDP = 17
	dnsPort  = 53

	// A connection's SYN shows up once per pktap interface and again on
	// retransmit, and QUIC sends several Initial packets.
	duplicateWindow = 5 * time.Second
	maxRecentFlows  = 4096
)

type flowKey struct {
	pid     uint32
	proto   byte
	srcPort uint16
	dst     netip.AddrPort
}

// header matches tcpdump's pktap metadata, e.g.
// "1794365423.660683 (proc mDNSResponder:493, eproc curl:16331, in) IP6 ...".
// Process names may contain spaces and parentheses and are truncated, so the
// pid is anchored on the ":<digits>," that follows each name.
var header = regexp.MustCompile(`^(\d+)\.(\d+) \(proc (.*?):(\d+), (?:eproc (.*?):(\d+), )?(in|out)\)`)

type packet struct {
	when      time.Time
	name      string
	pid       uint32
	outbound  bool
	ipPayload []byte
}

// parsePktap reads tcpdump text output and calls emit for every packet that
// becomes an event. Malformed packets are skipped.
func parsePktap(reader io.Reader, emit func(event.Event) bool) error {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	var current *packet
	recent := map[flowKey]time.Time{}
	flush := func() bool {
		if current == nil {
			return true
		}
		evt, key, ok := current.toEvent()
		current = nil
		if !ok {
			return true
		}
		if evt.Kind == event.Connect {
			if last, seen := recent[key]; seen && evt.Time.Sub(last) < duplicateWindow {
				return true
			}
			if len(recent) >= maxRecentFlows {
				for oldKey, when := range recent {
					if evt.Time.Sub(when) >= duplicateWindow {
						delete(recent, oldKey)
					}
				}
			}
			recent[key] = evt.Time
		}
		return emit(evt)
	}
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "\t") || strings.HasPrefix(line, " ") {
			if current != nil {
				current.appendHex(line)
				// Emit as soon as the packet is whole; waiting for the next
				// header would hold it until other traffic arrives.
				if current.complete() && !flush() {
					return nil
				}
			}
			continue
		}
		if !flush() {
			return nil
		}
		current = parseHeader(line)
	}
	flush()
	return scanner.Err()
}

func parseHeader(line string) *packet {
	match := header.FindStringSubmatch(line)
	if match == nil {
		return nil
	}
	seconds, _ := strconv.ParseInt(match[1], 10, 64)
	micros, _ := strconv.ParseInt(match[2], 10, 64)
	name, pidText := match[3], match[4]
	// eproc is the process the traffic is for when another process carried it,
	// such as mDNSResponder resolving a name on curl's behalf.
	if match[5] != "" {
		name, pidText = match[5], match[6]
	}
	pid, err := strconv.ParseUint(pidText, 10, 32)
	if err != nil {
		return nil
	}
	return &packet{
		when:     time.Unix(seconds, micros*int64(time.Microsecond)),
		name:     name,
		pid:      uint32(pid),
		outbound: match[7] == "out",
	}
}

// appendHex decodes one "\t0x0010:  0000 0000 ..." line of tcpdump -x output.
func (pkt *packet) appendHex(line string) {
	_, data, found := strings.Cut(strings.TrimSpace(line), ":")
	if !found {
		return
	}
	decoded, err := hex.DecodeString(strings.ReplaceAll(strings.TrimSpace(data), " ", ""))
	if err != nil {
		pkt.ipPayload = nil
		return
	}
	pkt.ipPayload = append(pkt.ipPayload, decoded...)
}

// complete reports whether every byte announced by the IP header has been read.
func (pkt *packet) complete() bool {
	data := pkt.ipPayload
	if len(data) < 1 {
		return false
	}
	switch data[0] >> 4 {
	case 4:
		return len(data) >= 4 && len(data) >= int(binary.BigEndian.Uint16(data[2:4]))
	case 6:
		return len(data) >= 6 && len(data) >= 40+int(binary.BigEndian.Uint16(data[4:6]))
	}
	return false
}

func (pkt *packet) toEvent() (event.Event, flowKey, bool) {
	src, dst, proto, transport, ok := splitIP(pkt.ipPayload)
	if !ok || len(transport) < 8 {
		return event.Event{}, flowKey{}, false
	}
	srcPort := binary.BigEndian.Uint16(transport[0:2])
	dstPort := binary.BigEndian.Uint16(transport[2:4])

	if !pkt.outbound && proto == protoUDP && srcPort == dnsPort {
		evt, parsed := dnsanswer.Parse(pkt.when, transport[8:])
		evt.PID = pkt.pid
		return evt, flowKey{}, parsed
	}
	if !pkt.outbound || src == dst {
		return event.Event{}, flowKey{}, false
	}
	evt := event.Event{
		Time: pkt.when, Kind: event.Connect, PID: pkt.pid, Exe: pkt.name, Proto: "tcp",
		Dst: netip.AddrPortFrom(dst, dstPort),
	}
	if proto == protoUDP {
		evt.Proto = "udp"
	}
	key := flowKey{pid: pkt.pid, proto: proto, srcPort: srcPort, dst: evt.Dst}
	return evt, key, proto == protoTCP || proto == protoUDP
}

func splitIP(packetBytes []byte) (src, dst netip.Addr, proto byte, transport []byte, ok bool) {
	if len(packetBytes) < 1 {
		return src, dst, 0, nil, false
	}
	switch packetBytes[0] >> 4 {
	case 4:
		headerLen := int(packetBytes[0]&0x0f) * 4
		if headerLen < 20 || len(packetBytes) < headerLen {
			return src, dst, 0, nil, false
		}
		src = netip.AddrFrom4([4]byte(packetBytes[12:16]))
		dst = netip.AddrFrom4([4]byte(packetBytes[16:20]))
		return src, dst, packetBytes[9], packetBytes[headerLen:], true
	case 6:
		if len(packetBytes) < 40 {
			return src, dst, 0, nil, false
		}
		src = netip.AddrFrom16([16]byte(packetBytes[8:24]))
		dst = netip.AddrFrom16([16]byte(packetBytes[24:40]))
		return src, dst, packetBytes[6], packetBytes[40:], true
	}
	return src, dst, 0, nil, false
}
