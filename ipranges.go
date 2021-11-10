// Code inspired by:
// https://github.com/OpenNMS/opennms/blob/master/core/api/src/main/java/org/opennms/core/network/IPAddressRangeSet.java
// https://github.com/OpenNMS/opennms/blob/master/core/api/src/main/java/org/opennms/core/network/IPAddressRange.java
// Warning: Tested only with IPv4 addresses (IPv6 not supported)

package main

import (
	"encoding/binary"
	"net"
)

type IPAddressRangeSet struct {
	ipRanges []IPAddressRange
}

func (r *IPAddressRangeSet) Add(ipr IPAddressRange) {
	for i, n := range r.ipRanges {
		if ipr.ComesBefore(n) && !ipr.AdjacentJoins(n) {
			idx := i - 1
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
	src_a := binary.BigEndian.Uint32(r.Begin.To4())
	src_b := binary.BigEndian.Uint32(r.End.To4())
	dst_a := binary.BigEndian.Uint32(ipr.Begin.To4())
	dst_b := binary.BigEndian.Uint32(ipr.End.To4())

	minIP := r.Begin
	if dst_a < src_a {
		minIP = ipr.Begin
	}

	maxIP := r.End
	if dst_b > src_b {
		maxIP = ipr.End
	}

	return IPAddressRange{
		Begin:         minIP,
		End:           maxIP,
		Location:      ipr.Location,
		Timeout:       ipr.Timeout,
		Retries:       ipr.Retries,
		ForeignSource: ipr.ForeignSource,
	}
}

func (r *IPAddressRange) Combinable(ipr IPAddressRange) bool {
	return r.Overlaps(ipr) || r.AdjacentJoins(ipr)
}

func (r *IPAddressRange) Contains(ip net.IP) bool {
	an := binary.BigEndian.Uint32(r.Begin.To4())
	bn := binary.BigEndian.Uint32(r.End.To4())
	n := binary.BigEndian.Uint32(ip.To4())
	return n >= an && n <= bn
}

func (r *IPAddressRange) Overlaps(ipr IPAddressRange) bool {
	return r.Contains(ipr.Begin) || r.Contains(ipr.End) || ipr.Contains(r.Begin) || ipr.Contains(r.End)
}

func (r *IPAddressRange) ComesBefore(ipr IPAddressRange) bool {
	an := binary.BigEndian.Uint32(r.End.To4())
	bn := binary.BigEndian.Uint32(ipr.Begin.To4())
	return an < bn
}

func (r *IPAddressRange) ComesAfter(ipr IPAddressRange) bool {
	an := binary.BigEndian.Uint32(r.Begin.To4())
	bn := binary.BigEndian.Uint32(ipr.End.To4())
	return an > bn
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

func (r *IPAddressRange) comesImmediatelyAfter(ipr IPAddressRange) bool {
	return r.ComesAfter(ipr) && r.isSuccessorOf(r.Begin, ipr.End)
}

func (r *IPAddressRange) comesImmediatelyBefore(ipr IPAddressRange) bool {
	return r.ComesBefore(ipr) && r.isPredecessorOf(r.End, ipr.Begin)
}

func (r *IPAddressRange) isSuccessorOf(a, b net.IP) bool {
	an := binary.BigEndian.Uint32(a.To4())
	bn := binary.BigEndian.Uint32(b.To4())
	return an == bn+1
}

func (r *IPAddressRange) isPredecessorOf(a, b net.IP) bool {
	an := binary.BigEndian.Uint32(a.To4())
	bn := binary.BigEndian.Uint32(b.To4())
	return an == bn-1
}
