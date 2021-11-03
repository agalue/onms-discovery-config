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
	<discovery-configuration packets-per-second="1" initial-sleep-time="30000" restart-sleep-time="86400000" retries="1" timeout="2000">
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

func TestIncludeCIDR(t *testing.T) {
	def := new(Definition)
	def.IncludeCIDR("192.168.0.0/24")
	if len(def.IncludeRanges) != 1 {
		t.Errorf("the definition should have one include-range")
	}
	if def.IncludeRanges[0].Begin != "192.168.0.1" {
		t.Errorf("the include range has a wrong begin address: %s", def.IncludeRanges[0].Begin)
	}
	if def.IncludeRanges[0].End != "192.168.0.254" {
		t.Errorf("the include range has a wrong end address")
	}
}

func TestExcludeContains(t *testing.T) {
	def := new(Definition)
	def.ExcludeCIDR("192.168.0.0/24")
	def.ExcludeCIDR("192.168.1.0/24")
	if def.ExcludeContains("192.168.0.1") == false {
		t.Errorf("address 192.168.0.1 should be in one of the excluded ranges")
	}
	if def.ExcludeContains("192.168.1.10") == false {
		t.Errorf("address 192.168.1.10 should be in one of the excluded ranges")
	}
	if def.ExcludeContains("172.16.1.1") == true {
		t.Errorf("address 172.16.1.1 should not be in any of the excluded ranges")
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
