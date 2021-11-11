// Author: Alejandro galue <agalue@opennms.org>

package main

import (
	"math/big"
	"net"
)

func Mask2Int(ipmask net.IPMask) *big.Int {
	ip := big.NewInt(0)
	ip.SetBytes(ipmask)
	return ip
}

func IP2Int(ipaddr net.IP) *big.Int {
	ip := big.NewInt(0)
	if ipaddr.To4() == nil { // Ipv6
		ip.SetBytes(ipaddr.To16())
	} else {
		ip.SetBytes(ipaddr.To4())
	}
	return ip
}

func Int2IP(ipaddr *big.Int) net.IP {
	return net.IP(ipaddr.Bytes())
}
