package main

import (
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"log"
	"net"
	"os"
	"time"
)

type ICMPEchoResponse struct {
	Message        *icmp.Message
	Source         net.Addr
	Rtt            time.Duration
	ControlMessage *ipv4.ControlMessage
}

func SendICMPEchoMessage(c net.PacketConn, destination net.IPAddr, seq, ttl int) (ICMPEchoResponse, error) {
	messageId := os.Getpid() & 0xffff

	echoMessage := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   messageId,
			Data: []byte("CYBER-PATH-FINDER"),
			Seq:  seq,
		},
	}

	var response ICMPEchoResponse

	p := ipv4.NewPacketConn(c)
	controlFlags := ipv4.FlagTTL | ipv4.FlagSrc | ipv4.FlagDst | ipv4.FlagInterface
	if err := p.SetControlMessage(controlFlags, true); err != nil {
		log.Fatal(err)
	}

	readBuffer := make([]byte, 1500)

	writeBuffer, err := echoMessage.Marshal(nil)
	if err != nil {
		log.Fatal(err)
	}
	if err := p.SetTTL(ttl); err != nil {
		log.Fatal(err)
	}

	writeBufferLen := len(writeBuffer)

	// In the real world usually there are several
	// multiple traffic-engineered paths for each hop.
	// You may need to probe a few times to each hop.
	begin := time.Now()
	if _, err := p.WriteTo(writeBuffer, nil, &destination); err != nil {
		log.Fatal(err)
	}
	if err := p.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		log.Fatal(err)
	}

	// determine whether the received message is ours
	gotResponse := false
	for gotResponse == false {
		// Read until we find the response to our message
		numberOfBytesRead, controlMessage, peer, err := p.ReadFrom(readBuffer)
		if err != nil {
			return response, err
		}

		readMessage, err := icmp.ParseMessage(1, readBuffer[:numberOfBytesRead])
		if err != nil {
			return response, err
		}

		// TODO: Refactor
		// TODO: Catch all ICMP message types
		switch readMessage.Type {
		case ipv4.ICMPTypeTimeExceeded:
			messageBody := readMessage.Body.(*icmp.TimeExceeded)

			// get original message
			originalMessageBuffer := messageBody.Data[len(messageBody.Data)-writeBufferLen:]
			originalMessage, err := icmp.ParseMessage(1, originalMessageBuffer)
			if err != nil {
				// must not be our message!
				continue
			}
			originalMessageBody := originalMessage.Body.(*icmp.Echo)

			if originalMessageBody.ID == messageId && originalMessageBody.Seq == seq {
				response.Message = readMessage
				response.Source = peer
				response.ControlMessage = controlMessage
				gotResponse = true
			}
		case ipv4.ICMPTypeEchoReply:
			messageBody := readMessage.Body.(*icmp.Echo)
			if messageBody.ID == messageId && messageBody.Seq == seq {
				response.Message = readMessage
				response.Source = peer
				response.ControlMessage = controlMessage
				gotResponse = true
			}
		default:
			log.Fatal("unknown ICMP message: %+v\n", readMessage)
		}

	}

	rtt := time.Since(begin)
	response.Rtt = rtt

	return response, err
}

func main() {
	if len(os.Args) != 2 {
		log.Fatal("Just a host please")
	}
	remoteHost := os.Args[1]
	log.Println("I will Cyber Path Find", remoteHost)
	remoteIPs, remoteIPLookupErr := net.LookupIP(remoteHost)
	if remoteIPLookupErr != nil {
		log.Fatal("DNS LOOKUP FAILED", remoteIPLookupErr)
	}
	log.Println("Remote host has IPs", remoteIPs)
	var remoteIP4 net.IPAddr
	for _, ip := range remoteIPs {
		ip4 := ip.To4()
		if ip4 != nil {
			remoteIP4.IP = ip4
		}
	}
	if remoteIP4.IP == nil {
		log.Fatal("No IP4 address found")
	}
	log.Println("Remote host has IP4 IP", remoteIP4.IP)

	c, err := net.ListenPacket("ip4:1", "0.0.0.0")
	if err != nil {
		log.Fatal(err, "\n🤔  Try sudo")
	}
	defer c.Close()

	for i := 1; i <= 64; i++ { // up to 64 hops
		echoResponse, echoErr := SendICMPEchoMessage(c, remoteIP4, i, i)
		if echoErr != nil {
			if echoErr, ok := echoErr.(net.Error); ok && echoErr.Timeout() {
				log.Println("*")
				continue
			}
		}
		names, _ := net.LookupAddr(echoResponse.Source.String())
		log.Printf("%d\t%v %+v %v", i, echoResponse.Source, names, echoResponse.Rtt)
		if echoResponse.Message.Type == ipv4.ICMPTypeEchoReply {
			return
		}
	}
}
