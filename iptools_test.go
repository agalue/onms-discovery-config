package main

import (
	"log"
	"net"
	"testing"
)

func TestIPConversion(t *testing.T) {
	ipv4 := net.ParseIP("192.168.0.1")
	ipv4Int := IP2Int(ipv4)
	log.Printf("Length of %s is %d; integer => %d", ipv4.String(), len(ipv4), ipv4Int.Int64())
	ipv4FromInt := Int2IP(ipv4Int)
	log.Printf("%s", ipv4FromInt.String())
	if ipv4.String() != ipv4FromInt.String() {
		t.Errorf("IPv4 conversion failed")
	}

	ipv6 := net.ParseIP("2001:db8::1")
	ipv6Int := IP2Int(ipv6)
	log.Printf("Length of %s is %d; integer => %d", ipv6.String(), len(ipv6), ipv6Int)
	ipv6FromInt := Int2IP(ipv6Int)
	log.Printf("%s", ipv6FromInt.String())
	if ipv6.String() != ipv6FromInt.String() {
		t.Errorf("IPv6 conversion failed")
	}
}
