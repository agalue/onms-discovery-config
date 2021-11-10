package main

import (
	"net"
	"testing"
)

func TestIPAddressRangeSet(t *testing.T) {
	r := new(IPAddressRangeSet)
	// Add first range
	r.Add(IPAddressRange{Begin: net.ParseIP("192.168.0.1"), End: net.ParseIP("192.168.0.10")})
	// Add non-overlapping second range
	r.Add(IPAddressRange{Begin: net.ParseIP("192.168.10.1"), End: net.ParseIP("192.168.10.10")})
	// Expand second range
	r.Add(IPAddressRange{Begin: net.ParseIP("192.168.10.1"), End: net.ParseIP("192.168.10.25")})
	// Add specific from first range
	r.Add(IPAddressRange{Begin: net.ParseIP("192.168.0.5"), End: net.ParseIP("192.168.0.5")})
	// Add specific from second range
	r.Add(IPAddressRange{Begin: net.ParseIP("192.168.10.5"), End: net.ParseIP("192.168.10.5")})
	// We should get two ranges
	ranges := r.Get()
	if len(ranges) != 2 {
		t.Errorf("we got an invalid number of ranges: %v", ranges)
	}
	if !ranges[0].Equal(IPAddressRange{Begin: net.ParseIP("192.168.0.1"), End: net.ParseIP("192.168.0.10")}) {
		t.Errorf("invaid first range: %v", ranges[0])
	}
	if !ranges[1].Equal(IPAddressRange{Begin: net.ParseIP("192.168.10.1"), End: net.ParseIP("192.168.10.25")}) {
		t.Errorf("invaid first range: %v", ranges[1])
	}
}

func TestContains(t *testing.T) {
	r := IPAddressRange{Begin: net.ParseIP("192.168.0.1"), End: net.ParseIP("192.168.0.10")}
	if !r.Contains(net.ParseIP("192.168.0.5")) {
		t.Errorf("range should contain 192.168.0.5")
	}
	if r.Contains(net.ParseIP("192.168.10.5")) {
		t.Errorf("range should not contain 192.168.10.5")
	}
}

func TestComesAfter(t *testing.T) {
	a := IPAddressRange{Begin: net.ParseIP("192.168.1.1"), End: net.ParseIP("192.168.1.2")}
	b := IPAddressRange{Begin: net.ParseIP("192.168.1.3"), End: net.ParseIP("192.168.1.4")}
	c := IPAddressRange{Begin: net.ParseIP("192.168.1.5"), End: net.ParseIP("192.168.1.6")}
	if !b.ComesAfter(a) {
		t.Errorf("range b should come after a")
	}
	if b.ComesAfter(c) {
		t.Errorf("range b should come before c")
	}
}

func TestComesBefore(t *testing.T) {
	a := IPAddressRange{Begin: net.ParseIP("192.168.1.1"), End: net.ParseIP("192.168.1.2")}
	b := IPAddressRange{Begin: net.ParseIP("192.168.1.3"), End: net.ParseIP("192.168.1.4")}
	c := IPAddressRange{Begin: net.ParseIP("192.168.1.5"), End: net.ParseIP("192.168.1.6")}
	if b.ComesBefore(a) {
		t.Errorf("range b should come after a")
	}
	if !b.ComesBefore(c) {
		t.Errorf("range b should come before c")
	}
}

func TestOverlaps(t *testing.T) {
	a := IPAddressRange{Begin: net.ParseIP("192.168.1.10"), End: net.ParseIP("192.168.1.20")}
	b := IPAddressRange{Begin: net.ParseIP("192.168.1.10"), End: net.ParseIP("192.168.1.10")}
	c := IPAddressRange{Begin: net.ParseIP("192.168.1.9"), End: net.ParseIP("192.168.1.22")}
	d := IPAddressRange{Begin: net.ParseIP("192.168.1.21"), End: net.ParseIP("192.168.1.22")}
	if !a.Overlaps(b) {
		t.Errorf("range b should overlaps a")
	}
	if !a.Overlaps(c) {
		t.Errorf("range c should overlaps a")
	}
	if a.Overlaps(d) {
		t.Errorf("range d should not overlaps a")
	}
}
