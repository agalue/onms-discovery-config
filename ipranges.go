// Author: Alejandro galue <agalue@opennms.org>

// Code inspired by:
// https://github.com/OpenNMS/opennms/blob/master/core/api/src/main/java/org/opennms/core/network/IPAddressRangeSet.java
// https://github.com/OpenNMS/opennms/blob/master/core/api/src/main/java/org/opennms/core/network/IPAddressRange.java

package main

import (
	"fmt"
	"math/big"
	"net"
)

type IPAddressRangeSet struct {
	ipRanges []IPAddressRange
}

func (r *IPAddressRangeSet) Add(ipr IPAddressRange) {
	for i, n := range r.ipRanges {
		if ipr.ComesBefore(n) && !ipr.AdjacentJoins(n) {
			idx := i - 1
			if idx < 0 {
				idx = 0
			}
			r.ipRanges = append(r.ipRanges[:idx+1], r.ipRanges[idx:]...)
			r.ipRanges[idx] = ipr
			return
		} else if n.Combinable(ipr) {
			r.ipRanges = append(r.ipRanges[:i], r.ipRanges[i+1:]...)
			ipr = n.Combine(ipr)
		}
	}
	r.ipRanges = append(r.ipRanges, ipr)
}

func (r *IPAddressRangeSet) Get() []IPAddressRange {
	return r.ipRanges
}

type IPAddressRange struct {
	Begin         net.IP
	End           net.IP
	Location      string
	Retries       int
	Timeout       int
	ForeignSource string
}

func (r *IPAddressRange) Combine(ipr IPAddressRange) IPAddressRange {
	src_a := IP2Int(r.Begin)
	src_b := IP2Int(r.End)
	dst_a := IP2Int(ipr.Begin)
	dst_b := IP2Int(ipr.End)

	minIP := r.Begin
	if dst_a.Cmp(src_a) < 0 {
		minIP = ipr.Begin
	}

	maxIP := r.End
	if dst_b.Cmp(src_b) > 0 {
		maxIP = ipr.End
	}

	return IPAddressRange{
		Begin:         minIP,
		End:           maxIP,
		Location:      r.Location,
		Timeout:       r.Timeout,
		Retries:       r.Retries,
		ForeignSource: r.ForeignSource,
	}
}

func (r *IPAddressRange) Combinable(ipr IPAddressRange) bool {
	return r.Overlaps(ipr) || r.AdjacentJoins(ipr)
}

func (r *IPAddressRange) Contains(ip net.IP) bool {
	an := IP2Int(r.Begin)
	bn := IP2Int(r.End)
	n := IP2Int(ip)
	return n.Cmp(an) >= 0 && n.Cmp(bn) <= 0
}

func (r *IPAddressRange) Overlaps(ipr IPAddressRange) bool {
	return r.Contains(ipr.Begin) || r.Contains(ipr.End) || ipr.Contains(r.Begin) || ipr.Contains(r.End)
}

func (r *IPAddressRange) ComesBefore(ipr IPAddressRange) bool {
	an := IP2Int(r.End)
	bn := IP2Int(ipr.Begin)
	return an.Cmp(bn) < 0
}

func (r *IPAddressRange) ComesAfter(ipr IPAddressRange) bool {
	an := IP2Int(r.Begin)
	bn := IP2Int(ipr.End)
	return an.Cmp(bn) > 0
}

func (r *IPAddressRange) AdjacentJoins(ipr IPAddressRange) bool {
	return r.comesImmediatelyBefore(ipr) || r.comesImmediatelyAfter(ipr)
}

func (r *IPAddressRange) IsSingleton() bool {
	return r.Begin.Equal(r.End)
}

func (r *IPAddressRange) Equal(ipr IPAddressRange) bool {
	return r.Begin.Equal(ipr.Begin) && r.End.Equal(ipr.End)
}

func (r *IPAddressRange) String() string {
	return fmt.Sprintf("%s -> %s", r.Begin, r.End)
}

func (r *IPAddressRange) comesImmediatelyAfter(ipr IPAddressRange) bool {
	return r.ComesAfter(ipr) && r.isSuccessorOf(r.Begin, ipr.End)
}

func (r *IPAddressRange) comesImmediatelyBefore(ipr IPAddressRange) bool {
	return r.ComesBefore(ipr) && r.isPredecessorOf(r.End, ipr.Begin)
}

func (r *IPAddressRange) isSuccessorOf(a, b net.IP) bool {
	an := IP2Int(a)
	bn := IP2Int(b)
	return an.Cmp(bn.Add(bn, big.NewInt(1))) == 0
}

func (r *IPAddressRange) isPredecessorOf(a, b net.IP) bool {
	an := IP2Int(a)
	bn := IP2Int(b)
	return an.Cmp(bn.Sub(bn, big.NewInt(1))) == 0
}
