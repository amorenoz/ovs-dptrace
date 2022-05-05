package ovstrace

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
)

const DevNameMaxSize = 64

// Event from eBPF program.
type EventBytes struct {
	Timestamp uint64
	Type      uint8
	SubAction uint8
	DevName   [DevNameMaxSize]byte
	Hash      uint32
	Sport     uint16
	Dport     uint16
	Seq       uint32
	AckSeq    uint32
	TCPFlags  uint8
	Protocol  uint8
	IPVersion uint8
}

type TCPInfo struct {
	Sport  uint16   `json:"sport,omitempty"`
	Dport  uint16   `json:"dport,omitempty"`
	Seq    uint32   `json:"seq,omitempty"`
	AckSeq uint32   `json:"ack_seq,omitempty"`
	Flags  TCPFlags `json:"flags,omitempty"`
}

func (t *TCPInfo) String() string {
	return fmt.Sprintf("TCP(%d -> %d [seq=%d seq_ack=%d] [%s])",
		t.Sport,
		t.Dport,
		t.Seq,
		t.AckSeq,
		t.Flags.String())
}

type UDPInfo struct {
	Sport uint16 `json:"sport,omitempty"`
	Dport uint16 `json:"dport,omitempty"`
}

func (u *UDPInfo) String() string {
	return fmt.Sprintf("UDP(%d -> %d)", u.Sport, u.Dport)
}

type EventType uint8

const (
	EventUpcall EventType = iota
	EventAction
)

type ActionType uint8

const (
	Unspec ActionType = iota
	Output
	Userspace
	Set
	PushVlan
	PopVlan
	Sample
	Recirc
	Hash
	PushMpls
	PopMpls
	SetMasked
	Ct
	Trunc
	PushEth
	PopEth
	CtClear
	PushNsh
	PopNsh
	Meter
	Clone
	CheckPktLen
	AddMpls
	DecTTL
	Max
	SetToMasked
)

func (a ActionType) String() string {
	switch a {
	case Unspec:
		return "Unspec"
	case Output:
		return "OUTPUT"
	case Userspace:
		return "USERSPACE"
	case Set:
		return "SET"
	case PushVlan:
		return "PUSH_VLAN"
	case PopVlan:
		return "POP_VLAN"
	case Sample:
		return "SAMPLE"
	case Recirc:
		return "RECIRC"
	case Hash:
		return "HASH"
	case PushMpls:
		return "PUSH_MPLS"
	case PopMpls:
		return "POP_MPLS"
	case SetMasked:
		return "SET_MASKED"
	case Ct:
		return "CT"
	case Trunc:
		return "TRUNC"
	case PushEth:
		return "PUSH_ETH"
	case PopEth:
		return "POP_ETH"
	case CtClear:
		return "CT_CLEAR"
	case PushNsh:
		return "PUSH_NSH"
	case PopNsh:
		return "POP_NSH"
	case Meter:
		return "METER"
	case Clone:
		return "CLONE"
	case CheckPktLen:
		return "CHK_PKT_LEN"
	case AddMpls:
		return "ADD_MPLS"
	case DecTTL:
		return "DEC_TTL"
	case Max:
		return "MAX"
	case SetToMasked:
		return "SET_TO_MASKED"
	default:
		return fmt.Sprintf("unknown(%d)", a)
	}
}

const (
	IPPROTO_TCP = 6
	IPPROTO_UDP = 17
)

const (
	TCPHDR_FIN = 0x01
	TCPHDR_SYN = 0x02
	TCPHDR_RST = 0x04
	TCPHDR_PSH = 0x08
	TCPHDR_ACK = 0x10
	TCPHDR_URG = 0x20
	TCPHDR_ECE = 0x40
	TCPHDR_CWR = 0x80
)

type TCPFlags uint8

func (f TCPFlags) String() string {
	flag_str := make([]string, 0)
	if f&TCPHDR_FIN != 0 {
		flag_str = append(flag_str, "FIN")
	}
	if f&TCPHDR_SYN != 0 {
		flag_str = append(flag_str, "SYN")
	}
	if f&TCPHDR_RST != 0 {
		flag_str = append(flag_str, "RST")
	}
	if f&TCPHDR_PSH != 0 {
		flag_str = append(flag_str, "PSH")
	}
	if f&TCPHDR_ACK != 0 {
		flag_str = append(flag_str, "ACK")
	}
	if f&TCPHDR_URG != 0 {
		flag_str = append(flag_str, "URG")
	}
	if f&TCPHDR_ECE != 0 {
		flag_str = append(flag_str, "ECE")
	}
	if f&TCPHDR_CWR != 0 {
		flag_str = append(flag_str, "CWR")
	}
	return strings.Join(flag_str, "|")
}

type Event struct {
	Timestamp uint64     `json:"timestamp"`
	Type      EventType  `json:"type"`
	SubAction ActionType `json:"subaction,omitempty"`
	DevName   string     `json:"devname,omitempty"`
	Hash      uint32     `json:"hash,omitempty"`
	TCP       *TCPInfo   `json:"tcp,omitempty"`
	UDP       *UDPInfo   `json:"udp,omitempty"`
	Protocol  uint8      `json:"protocol,omitempty"`
}

func (e *Event) String() string {
	eventStr := fmt.Sprintf("%d | %s ", e.Timestamp, e.DevName)
	switch EventType(e.Type) {
	case EventUpcall:
		eventStr += "UPCALL: "
	case EventAction:
		eventStr += fmt.Sprintf("ACTION (%s): ", ActionType(e.SubAction).String())
	default:
		return "unknown"
	}
	switch e.Protocol {
	case IPPROTO_TCP:
		eventStr += e.TCP.String()
	case IPPROTO_UDP:
		eventStr += e.UDP.String()
	}
	eventStr += fmt.Sprintf(" hash 0x%x", e.Hash)
	return eventStr
}

func EventFromBytes(buffer *bytes.Buffer) (*Event, error) {

	//log.Printf("EventFromBytes: %v", *buffer)
	var eventBytes EventBytes
	if err := binary.Read(buffer, binary.LittleEndian, &eventBytes); err != nil {
		return nil, err
	}

	event := Event{
		Timestamp: eventBytes.Timestamp,
		Type:      EventType(eventBytes.Type),
		SubAction: ActionType(eventBytes.SubAction),
		DevName:   string(eventBytes.DevName[:]),
		Hash:      eventBytes.Hash,
		Protocol:  eventBytes.Protocol,
	}
	switch event.Protocol {
	case IPPROTO_TCP:
		event.TCP = &TCPInfo{
			Sport:  eventBytes.Sport,
			Dport:  eventBytes.Dport,
			Seq:    eventBytes.Seq,
			AckSeq: eventBytes.AckSeq,
			Flags:  TCPFlags(eventBytes.TCPFlags),
		}
	case IPPROTO_UDP:
		event.UDP = &UDPInfo{
			Sport: eventBytes.Sport,
			Dport: eventBytes.Dport,
		}
	}
	return &event, nil
}

func HandleEvent(event *Event) error {
	return nil
}
