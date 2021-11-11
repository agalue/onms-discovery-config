// Author: Alejandro galue <agalue@opennms.org>

package main

import (
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"testing"
)

func TestParseDiscoveryConfiguration(t *testing.T) {
	// https://github.com/OpenNMS/opennms/blob/master/opennms-base-assembly/src/main/filtered/etc/examples/discovery-configuration.xml
	referenceConfig := `
	<discovery-configuration xmlns="http://xmlns.opennms.org/xsd/config/discovery" packets-per-second="1" initial-sleep-time="30000" restart-sleep-time="86400000" retries="1" timeout="2000">
		<definition location="MINION" foreign-source="ApexOffice">
			<detectors>
				<detector name="reverse-dns-lookup" class-name="org.opennms.netmgt.provision.detector.rdns.ReverseDNSLookupDetector"/>
				<detector name="SNMP" class-name="org.opennms.netmgt.provision.detector.snmp.SnmpDetector">
					<parameter key="timeout" value="5000"/>
					<parameter key="ttl" value="120000"/>
					<!-- use snmp profiles when detecting, defaults to false -->
					<parameter key="useSnmpProfiles" value="true"/>
				</detector>
			</detectors>
			<specific>10.0.0.5</specific>
			<include-range>
				<begin>192.168.0.1</begin>
				<end>192.168.0.254</end>
			</include-range>
			<exclude-range>
				<begin>192.168.0.120</begin>
				<end>192.168.0.125</end>
			</exclude-range>
			<include-url>file:/opt/opennms/etc/include.txt</include-url>
		</definition>
	</discovery-configuration>
	`
	cfg := new(DiscoveryConfiguration)
	if err := xml.Unmarshal([]byte(referenceConfig), cfg); err != nil {
		t.Errorf("cannot parse configuration: %v", err)
	}
	output, _ := xml.MarshalIndent(cfg, "", "  ")
	fmt.Println(string(output))

	// Validating content
	if cfg.InitialSleepTime != 30000 {
		t.Errorf("the initial-sleep-time is incorrect")
	}
	if len(cfg.Definitions) != 1 {
		t.Errorf("the config should have one definition")
	}
	def := cfg.Definitions[0]
	if def.ForeignSource != "ApexOffice" {
		t.Errorf("the definition has an incorrect foreign-source")
	}
	if len(def.Detectors) != 2 {
		t.Errorf("the definition should have two detectors")
	}
	if def.Detectors[1].Name != "SNMP" {
		t.Errorf("the definition has a wrong detector")
	}
	if len(def.Detectors[1].Parameters) != 3 {
		t.Errorf("the SNMP detector should have 3 parameters")
	}
	if def.Detectors[1].Parameters[0].Key != "timeout" {
		t.Errorf("the SNMP detector has a wrong parameter")
	}
	if len(def.Specifics) != 1 {
		t.Errorf("the definition should have 1 specific")
	}
	if len(def.IncludeRanges) != 1 {
		t.Errorf("the definition should have 1 include-range")
	}
	if len(def.ExcludeRanges) != 1 {
		t.Errorf("the definition should have 1 exclude-range")
	}
	if len(def.IncludeURLs) != 1 {
		t.Errorf("the definition should have 1 include-url")
	}
}

func TestGetIPv4Range(t *testing.T) {
	def := new(Definition)
	src, dst, err := def.getRange("172.16.0.0/24")
	if err != nil {
		t.Errorf("cannot get range: %v", err)
	}
	if src.String() != "172.16.0.1" {
		t.Errorf("invalid source address")
	}
	if dst.String() != "172.16.0.254" {
		t.Errorf("invalid dst address")
	}
}

func TestGetIPv6Range(t *testing.T) {
	def := new(Definition)
	src, dst, err := def.getRange("2001::0/64")
	if err != nil {
		t.Errorf("cannot get range: %v", err)
	}
	if src.String() != "2001::1" {
		t.Errorf("invalid source address")
	}
	if dst.String() != "2001::ffff:ffff:ffff:fffe" {
		t.Errorf("invalid dst address")
	}
}

func TestIncludeCIDR(t *testing.T) {
	def := new(Definition)
	def.IncludeCIDR("192.168.0.0/24")
	if len(def.IncludeRanges) != 1 {
		t.Errorf("the definition should have one include-range")
	}
	if def.IncludeRanges[0].Begin.String() != "192.168.0.1" {
		t.Errorf("the include range has a wrong begin address: %s", def.IncludeRanges[0].Begin)
	}
	if def.IncludeRanges[0].End.String() != "192.168.0.254" {
		t.Errorf("the include range has a wrong end address")
	}
}

func TestExcludeRangesContain(t *testing.T) {
	def := new(Definition)
	def.ExcludeCIDR("192.168.0.0/24")
	def.ExcludeCIDR("192.168.1.0/24")
	if def.ExcludeRangesContain("192.168.0.1") == false {
		t.Errorf("address 192.168.0.1 should be in one of the excluded ranges")
	}
	if def.ExcludeRangesContain("192.168.1.10") == false {
		t.Errorf("address 192.168.1.10 should be in one of the excluded ranges")
	}
	if def.ExcludeRangesContain("172.16.1.1") == true {
		t.Errorf("address 172.16.1.1 should not be in any of the excluded ranges")
	}
}

func TestExcludeRangesContainInt(t *testing.T) {
	def := new(Definition)
	def.ExcludeCIDR("192.168.0.0/24")
	def.ExcludeCIDR("192.168.1.0/24")
	if def.excludeRangesContain(IP2Int(net.ParseIP("192.168.0.1"))) == false {
		t.Errorf("address 192.168.0.1 should be in one of the excluded ranges")
	}
	if def.excludeRangesContain(IP2Int(net.ParseIP("192.168.1.10"))) == false {
		t.Errorf("address 192.168.1.10 should be in one of the excluded ranges")
	}
	if def.excludeRangesContain(IP2Int(net.ParseIP("172.16.1.1"))) == true {
		t.Errorf("address 172.16.1.1 should not be in any of the excluded ranges")
	}
}

func TestIncludeRangesContain(t *testing.T) {
	def := new(Definition)
	def.IncludeCIDR("192.168.0.0/24")
	def.IncludeCIDR("192.168.1.0/24")
	if def.IncludeRangesContain("192.168.0.1") == false {
		t.Errorf("address 192.168.0.1 should be in one of the included ranges")
	}
	if def.IncludeRangesContain("192.168.1.10") == false {
		t.Errorf("address 192.168.1.10 should be in one of the included ranges")
	}
	if def.IncludeRangesContain("172.16.1.1") == true {
		t.Errorf("address 172.16.1.1 should not be in any of the included ranges")
	}
}

func TestAddSpecific(t *testing.T) {
	def := new(Definition)
	def.AddSpecific("192.168.0.1")
	def.AddSpecific("192.168.0.2")
	if len(def.Specifics) != 2 {
		t.Errorf("the definition should have 2 specific")
	}
	def.AddSpecific("192.400.0.1") // Wrong IP
	if len(def.Specifics) != 2 {
		t.Errorf("the definition should have 2 specific")
	}
}

func TestAddIncludeURL(t *testing.T) {
	def := new(Definition)
	def.AddIncludeURL("file:/tmp/ip-list.txt")
	if len(def.IncludeURLs) != 1 {
		t.Errorf("the definition should 1 include-url")
	}
}

func TestAddIncludeRange(t *testing.T) {
	def := new(Definition)
	def.AddIncludeRange("192.168.0.10", "192.168.0.20")
	if len(def.IncludeRanges) != 1 {
		t.Errorf("the definition should 1 include-range")
	}
}

func TestAddExcludeRange(t *testing.T) {
	def := new(Definition)
	def.AddExcludeRange("192.168.0.10", "192.168.0.20")
	if len(def.ExcludeRanges) != 1 {
		t.Errorf("the definition should 1 exclude-range")
	}
}

func TestGetTotalEstimatedAddresses(t *testing.T) {
	d := Definition{}
	d.AddSpecific("192.168.0.1")
	d.AddSpecific("192.168.0.2")
	d.IncludeCIDR("172.20.0.0/16")
	d.IncludeCIDR("10.10.0.0/16")
	d.ExcludeCIDR("172.20.10.0/24")
	d.ExcludeCIDR("192.169.0.0/24")
	cfg := DiscoveryConfiguration{
		Definitions: []Definition{d},
	}
	var expected uint32 = 130816 // 2 * ClassB - ClassA + 2 = 2 * 65533 - 253 + 2
	total := cfg.GetTotalEstimatedAddresses()
	if total != expected {
		t.Errorf("the total estimated addresses was %d and it should be %d", total, expected)
	}
}

func TestSort(t *testing.T) {
	d := Definition{}
	d.AddSpecific("192.168.0.10")
	d.AddSpecific("192.168.0.2")
	d.AddSpecific("172.16.20.2")
	d.AddSpecific("172.16.16.2")
	d.Sort()
	if d.Specifics[0].IP.String() != "172.16.16.2" {
		t.Errorf("invalid sort for position 0: %s", d.Specifics[0].IP.String())
	}
	if d.Specifics[3].IP.String() != "192.168.0.10" {
		t.Errorf("invalid sort for position 3: %s", d.Specifics[3].IP.String())
	}
}

func TestMerge(t *testing.T) {
	d := Definition{}
	d.IncludeCIDR("192.168.0.0/24")
	d.IncludeCIDR("172.16.0.0/16")
	d.IncludeCIDR("10.0.0.0/8")
	d.ExcludeCIDR("10.0.1.0/24")
	d.AddIncludeRange("192.168.0.1", "192.168.2.254") // Overlaps CIDR #1
	d.AddExcludeRange("10.0.1.10", "10.0.2.254")      // Overlaps CIDR #4
	d.AddSpecific("192.168.0.10")                     // Part of CIDR #1
	// The following 5 must be collapsed
	d.AddSpecific("200.10.0.15")
	d.AddSpecific("200.10.0.16")
	d.AddSpecific("200.10.0.17")
	d.AddSpecific("200.10.0.18")
	d.AddSpecific("200.10.0.19")
	d.AddSpecific("200.10.0.20")
	// The following 4 must be collapsed
	d.AddSpecific("200.10.0.25")
	d.AddSpecific("200.10.0.26")
	d.AddSpecific("200.10.0.27")
	d.AddSpecific("200.10.0.28")
	// A few disperse specifics
	d.AddSpecific("30.0.0.2")
	d.AddSpecific("40.0.0.2")
	d.AddSpecific("50.0.0.2")
	// Verify configuration
	cfg := &DiscoveryConfiguration{
		PacketsPerSecond: 10,
		InitialSleepTime: 300000,
		RestartSleepTime: 86400000,
		Retries:          1,
		Timeout:          2000,
		Definitions:      []Definition{d},
	}
	cfg.Merge()
	fmt.Println(cfg.String())
	out := cfg.Definitions[0]
	if len(out.Specifics) != 3 {
		t.Errorf("incorrect number of specifics: %d", len(out.Specifics))
	}
	if len(out.IncludeRanges) != 5 {
		t.Errorf("incorrect number of include-ranges: %d", len(out.IncludeRanges))
	}
	if len(out.ExcludeRanges) != 1 {
		t.Errorf("incorrect number of exclude-ranges: %d", len(out.ExcludeRanges))
	}
	r := out.IncludeRanges[2]
	if r.Begin.String() != "192.168.0.1" || r.End.String() != "192.168.2.254" {
		t.Errorf("incorrect merged range: %v", r)
	}
	r = out.IncludeRanges[3]
	if r.Begin.String() != "200.10.0.15" || r.End.String() != "200.10.0.20" {
		t.Errorf("incorrect merged range: %v", r)
	}
	e := out.ExcludeRanges[0]
	if e.Begin.String() != "10.0.1.1" || e.End.String() != "10.0.2.254" {
		t.Errorf("incorrect merged range: %v", e)
	}
}

func TestUpateOpenNMS(t *testing.T) {
	dir, err := ioutil.TempDir(os.TempDir(), "_discovery")
	if err != nil {
		t.Errorf("cannot create temp directory: %v", err)
	}
	os.Mkdir(dir+"/etc", 0755)
	defer os.RemoveAll(dir)

	if err := os.WriteFile(dir+"/etc/discovery-configuration.xml", []byte{}, 0644); err != nil {
		t.Errorf("cannot create empty discovery configuration")
	}

	go func() {
		if err := baseConfig.UpdateOpenNMS(dir, 50817); err != nil {
			t.Errorf("cannot send event to OpenNMS: %v", err)
		}
	}()

	ln, err := net.Listen("tcp", "127.0.0.1:50817")
	if err != nil {
		t.Errorf("cannot create TCP server: %v", err)
	}
	defer ln.Close()

	conn, err := ln.Accept()
	if err != nil {
		t.Errorf("cannot accept connections: %v", err)
	}
	defer conn.Close()

	buf, err := ioutil.ReadAll(conn)
	if err != nil {
		t.Errorf("cannot read content: %v", err)
	}
	received := new(Log)
	xml.Unmarshal(buf, received)
	if received.Events[0].UEI != "uei.opennms.org/internal/reloadDaemonConfig" {
		t.Errorf("incorrect message received: %s", string(buf))
	}
}
