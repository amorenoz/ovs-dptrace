package ovstrace

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

type Filter struct {
	//Mark     uint32
	Eth      Ethhdr
	EthMask  Ethhdr
	IPv4     IPv4hdr
	IPv4Mask IPv4hdr
	IPv6     IPv6hdr
	IPv6Mask IPv6hdr
	Tcp      Tcphdr
	TcpMask  Tcphdr
	Udp      Udphdr
	UdpMask  Udphdr
	DevName  [DevNameMaxSize]byte
}

type Ethhdr struct {
	Dest   [6]byte
	Source [6]byte
	Proto  [2]byte
}

type IPv4hdr struct {
	IhlVersion byte
	Tos        byte
	TotLen     [2]byte
	Id         [2]byte
	FragOff    [2]byte
	Ttl        byte
	Protocol   byte
	Check      [2]byte
	Saddr      [4]byte
	Daddr      [4]byte
}

type IPv6hdr struct {
	PrioVersion byte
	FlowLbl     [3]byte
	PayloadLen  [2]byte
	NextHdr     byte
	HopLimit    byte
	Saddr       [16]byte
	Daddr       [16]byte
}

type Tcphdr struct {
	Source [2]byte
	Dest   [2]byte
	Seq    [4]byte
	AckSeq [4]byte
	Flags  [2]byte
	Window [2]byte
	Check  [2]byte
	UrgPtr [2]byte
}

type Udphdr struct {
	Source [2]byte
	Dest   [2]byte
	Len    [2]byte
	Check  [2]byte
}

var (
	mask16 = [2]byte{0xff, 0xff}
	mask32 = [4]byte{0xff, 0xff, 0xff, 0xff}
)

func ParseFilter(expr string) (*Filter, error) {
	tokens := strings.Split(expr, " ")
	f := &Filter{}

	// Keep empty filter support only for dev.
	if len(expr) == 0 {
		return f, nil
	}

	var flags uint8 = 0
	i, max := 0, len(tokens)
	for i < max {
		// All tokens have an argument
		if i == max-1 {
			return nil, fmt.Errorf("No value after '%s'", tokens[i])
		}

		key, val := tokens[i], tokens[i+1]
		i += 2

		// TODO: improve error handling when a parameter is already set.
		// (But really, we should rewrite all this).
		switch key {
		case "iface":
			if len(val) > DevNameMaxSize-1 {
				return nil, fmt.Errorf("device name too long. Max size = %d",
					DevNameMaxSize-1)
			}
			copy(f.DevName[:], []byte(val))
		case "etype":
			data, err := getUint16BE(val)
			if err != nil {
				return nil, err
			}

			copy(f.Eth.Proto[:], data)
			f.EthMask.Proto = mask16
		case "proto":
			data, err := translateProtocol(val)
			if err != nil {
				return nil, err
			}

			f.IPv4.Protocol = data
			f.IPv4Mask.Protocol = 0xff
			f.IPv6.NextHdr = data
			f.IPv6Mask.NextHdr = 0xff
		case "dst":
			data, err := getUint16BE(val)
			if err != nil {
				return nil, err
			}

			copy(f.Tcp.Dest[:], data)
			f.TcpMask.Dest = mask16
			f.Udp.Dest = f.Tcp.Dest
			f.UdpMask.Dest = mask16
		case "src":
			data, err := getUint16BE(val)
			if err != nil {
				return nil, err
			}

			copy(f.Tcp.Source[:], data)
			f.TcpMask.Source = mask16
			copy(f.Udp.Source[:], data)
			f.UdpMask.Source = mask16
		case "tcpflag":
			flag, err := getTCPFlag(val)
			if err != nil {
				return nil, err
			}
			flags |= flag
		default:
			return nil, fmt.Errorf("Unknow key '%s'", key)
		}
	}

	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, uint16(flags))
	copy(f.Tcp.Flags[:], data)
	copy(f.TcpMask.Flags[:], data)

	return f, nil
}

func getUint16(token string) (uint16, error) {
	i, err := strconv.ParseUint(token, 10, 16)
	if err != nil {
		return 0, err
	}

	return uint16(i), nil
}

func getUint16BE(token string) ([]byte, error) {
	val, err := getUint16(token)
	if err != nil {
		return []byte{}, err
	}

	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, val)

	return data, nil
}

func getString(token string, maxSize int) {
}

func getUint32(token string) (uint32, error) {
	i, err := strconv.ParseUint(token, 10, 32)
	if err != nil {
		return 0, err
	}

	return uint32(i), nil
}

func getUint32BE(token string) ([]byte, error) {
	val, err := getUint32(token)
	if err != nil {
		return []byte{}, err
	}

	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, val)

	return data, nil
}

func translateProtocol(protocol string) (byte, error) {
	switch protocol {
	case "tcp":
		return 6, nil
	case "udp":
		return 17, nil
	default:
		return 0, fmt.Errorf("Unknow protocol")
	}
}

func getTCPFlag(token string) (uint8, error) {
	var offset uint8
	switch token {
	case "cwr":
		offset = 0
	case "ece":
		offset = 1
	case "urg":
		offset = 2
	case "ack":
		offset = 3
	case "psh":
		offset = 4
	case "rst":
		offset = 5
	case "syn":
		offset = 6
	case "fin":
		offset = 7
	default:
		return 0, fmt.Errorf("Unknow TCP flag '%s'", token)
	}
	return (1 << offset), nil
}
