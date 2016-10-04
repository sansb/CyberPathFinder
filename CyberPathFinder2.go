package main

import (
	"golang.org/x/net/ipv4"
)

func main() {
	c, err := net.ListenPacket("ip4:1", "0.0.0.0")
	conn := ipv4.NewPacketConn(c)
	if err != nil {
		log.Fatal("Failed to get connection")
	}

	//make header
	hdr := new(ipv4.Header)
	hdr.Version = 4
	hdr.Len = 0
	hdr.TOS = 0
	hdr.TotalLen = XXX
	hdr.ID = 0
}
