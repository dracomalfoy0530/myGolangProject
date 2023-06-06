package main

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	icmpv4EchoRequest = 8
	icmpv4EchoReply   = 0
	icmpv6EchoRequest = 128
	icmpv6EchoReply   = 129
)

type icmpMessage struct {
	Type     int             // type
	Code     int             // code
	Checksum int             // checksum
	Body     icmpMessageBody // body
}

type icmpMessageBody interface {
	Len() int
	Marshal() ([]byte, error)
}

var mutex chan bool
var pingResult map[string]int
var mapLock sync.Mutex

// Marshal returns the binary enconding of the ICMP echo request or
// reply message m.
func (m *icmpMessage) Marshal() ([]byte, error) {
	b := []byte{byte(m.Type), byte(m.Code), 0, 0}
	if m.Body != nil && m.Body.Len() != 0 {
		mb, err := m.Body.Marshal()
		if err != nil {
			return nil, err
		}
		b = append(b, mb...)
	}
	switch m.Type {
	case icmpv6EchoRequest, icmpv6EchoReply:
		return b, nil
	}
	csumcv := len(b) - 1 // checksum coverage
	s := uint32(0)
	for i := 0; i < csumcv; i += 2 {
		s += uint32(b[i+1])<<8 | uint32(b[i])
	}
	if csumcv&1 == 0 {
		s += uint32(b[csumcv])
	}
	s = s>>16 + s&0xffff
	s = s + s>>16
	// Place checksum back in header; using ^= avoids the
	// assumption the checksum bytes are zero.
	b[2] ^= byte(^s & 0xff)
	b[3] ^= byte(^s >> 8)
	return b, nil
}

// parseICMPMessage parses b as an ICMP message.
func parseICMPMessage(b []byte) (*icmpMessage, error) {
	msglen := len(b)
	if msglen < 4 {
		return nil, errors.New("message too short")
	}
	m := &icmpMessage{Type: int(b[0]), Code: int(b[1]), Checksum: int(b[2])<<8 | int(b[3])}
	if msglen > 4 {
		var err error
		switch m.Type {
		case icmpv4EchoRequest, icmpv4EchoReply, icmpv6EchoRequest, icmpv6EchoReply:
			m.Body, err = parseICMPEcho(b[4:])
			if err != nil {
				return nil, err
			}
		}
	}
	return m, nil
}

// imcpEcho represenets an ICMP echo request or reply message body.
type icmpEcho struct {
	ID   int    // identifier
	Seq  int    // sequence number
	Data []byte // data
}

func (p *icmpEcho) Len() int {
	if p == nil {
		return 0
	}
	return 4 + len(p.Data)
}

// Marshal returns the binary enconding of the ICMP echo request or
// reply message body p.
func (p *icmpEcho) Marshal() ([]byte, error) {
	b := make([]byte, 4+len(p.Data))
	b[0], b[1] = byte(p.ID>>8), byte(p.ID&0xff)
	b[2], b[3] = byte(p.Seq>>8), byte(p.Seq&0xff)
	copy(b[4:], p.Data)
	return b, nil
}

// parseICMPEcho parses b as an ICMP echo request or reply message body.
func parseICMPEcho(b []byte) (*icmpEcho, error) {
	bodylen := len(b)
	p := &icmpEcho{ID: int(b[0])<<8 | int(b[1]), Seq: int(b[2])<<8 | int(b[3])}
	if bodylen > 4 {
		p.Data = make([]byte, bodylen-4)
		copy(p.Data, b[4:])
	}
	return p, nil
}

func Ping(network string, address string, timeout int) bool {

	var pingDelay int
	var err error

	// 选择不同的探测类型
	switch network {
	case "icmp":
		pingDelay, err = Pinger(address, timeout)
	case "tcp":
		pingDelay, err = TcpPinger(address, 80, timeout) // 默认探测80端口
	default:
		LogInfo("Ping error : unknown network type : " + network)
		return false
	}

	if err != nil {
		fmt.Println(err)
		LogInfo(fmt.Sprintf("Ping error : %s", err))
		mutex <- false

		mapLock.Lock()
		pingResult[address] = 9999999 // ping不可达
		mapLock.Unlock()

		return false
	} else {
		mutex <- true

		mapLock.Lock()
		pingResult[address] = pingDelay
		mapLock.Unlock()

		return err == nil
	}
}

func Pinger(address string, timeout int) (int, error) {
	c, err := net.Dial("ip4:icmp", address)
	if err != nil {
		return 0, err
	}
	c.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
	defer c.Close()

	typ := icmpv4EchoRequest
	xid, xseq := os.Getpid()&0xffff, 1
	wb, err := (&icmpMessage{
		Type: typ, Code: 0,
		Body: &icmpEcho{
			ID: xid, Seq: xseq,
			Data: bytes.Repeat([]byte("Go Go Gadget Ping!!!"), 3),
		},
	}).Marshal()
	if err != nil {
		return 0, err
	}

	var timeTotal int64
	for i := 0; i < 3; i++ {
		pingBegin := time.Now().UnixNano()

		if _, err = c.Write(wb); err != nil {
			return 0, err
		}
		var m *icmpMessage
		rb := make([]byte, 20+len(wb))
		for {
			if _, err = c.Read(rb); err != nil {
				return 0, err
			}
			rb = ipv4Payload(rb)
			if m, err = parseICMPMessage(rb); err != nil {
				return 0, err
			}
			switch m.Type {
			case icmpv4EchoRequest, icmpv6EchoRequest:
				continue
			}
			break
		}

		pingEnd := time.Now().UnixNano()
		pingDuration := pingEnd - pingBegin

		timeTotal += pingDuration
		time.Sleep(time.Duration(200) * time.Millisecond)
	}
	pingDelay := (timeTotal / 3) / 1000

	return int(pingDelay), nil
}

func TcpPinger(address string, port int, timeout int) (int, error) {

	// 拼接ip:port格式的地址
	server := fmt.Sprintf("%s:%d", address, port)

	// dial并计时
	var timeTotal int64
	for i := 0; i < 3; i++ {

		start := time.Now().UnixNano()
		_, err := net.DialTimeout("tcp", server, time.Duration(timeout)*time.Second)
		end := time.Now().UnixNano()
		duration := end - start

		if err != nil {
			return 0, err
		}

		timeTotal += duration
		time.Sleep(time.Duration(200) * time.Millisecond)
	}
	pingDelay := (timeTotal / 3) / 1000

	return int(pingDelay), nil
}

func ipv4Payload(b []byte) []byte {
	if len(b) < 20 {
		return b
	}
	hdrlen := int(b[0]&0x0f) << 2
	return b[hdrlen:]
}

func concurrentPing(ipList []string) *ValSorter {
	mutex = make(chan bool)
	pingResult = make(map[string]int)

	// root用户则使用icmp
	var network string
	euid := os.Geteuid()
	if 0 == euid {
		network = "icmp"
	} else {
		network = "tcp"
	}

	for i := 0; i < len(ipList); i++ {
		ip := ipList[i]
		go Ping(network, ip, 3)
	}

	// 等待协程处理完毕
	for i := 0; i < len(ipList); i++ {
		<-mutex
	}

	vs := NewValSorter(pingResult)
	vs.Sort()

	return vs
}

func wxpayPing() *ValSorter {
	vipList := strings.Split(mchConf.Vip, ";")
	vs := concurrentPing(vipList)
	return vs
}
