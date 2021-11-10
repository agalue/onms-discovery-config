// Representation and helper functions for discovery-configuration.xml
// https://github.com/OpenNMS/opennms/blob/master/opennms-config-model/src/main/resources/xsds/discovery-configuration.xsd
//
// Warning: Tested only with IPv4 addresses (IPv6 not supported)

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"sort"
	"time"
)

type Parameter struct {
	XMLName xml.Name `xml:"parameter"`
	Key     string   `xml:"key,attr"`
	Value   string   `xml:"value,attr"`
}

type Detector struct {
	XMLName    xml.Name    `xml:"detector"`
	Name       string      `xml:"name,attr"`
	Class      string      `xml:"class-name,attr"`
	Parameters []Parameter `xml:"parameter,omitempty"`
}

type Specific struct {
	XMLName       xml.Name `xml:"specific"`
	IP            net.IP   `xml:",chardata"`
	Location      string   `xml:"location,attr,omitempty"`
	Retries       int      `xml:"retries,attr,omitempty"`
	Timeout       int      `xml:"timeout,attr,omitempty"`
	ForeignSource string   `xml:"foreign-source,attr,omitempty"`
}

func (s *Specific) ToIPAddressRange() IPAddressRange {
	return IPAddressRange{
		Location:      s.Location,
		Retries:       s.Retries,
		Timeout:       s.Timeout,
		ForeignSource: s.ForeignSource,
		Begin:         s.IP,
		End:           s.IP,
	}
}

type IncludeRange struct {
	XMLName       xml.Name `xml:"include-range"`
	Location      string   `xml:"location,attr,omitempty"`
	Retries       int      `xml:"retries,attr,omitempty"`
	Timeout       int      `xml:"timeout,attr,omitempty"`
	ForeignSource string   `xml:"foreign-source,attr,omitempty"`
	Begin         net.IP   `xml:"begin"`
	End           net.IP   `xml:"end"`
}

func (r *IncludeRange) ToIPAddressRange() IPAddressRange {
	return IPAddressRange{
		Location:      r.Location,
		Retries:       r.Retries,
		Timeout:       r.Timeout,
		ForeignSource: r.ForeignSource,
		Begin:         r.Begin,
		End:           r.End,
	}
}

type ExcludeRange struct {
	XMLName  xml.Name `xml:"exclude-range"`
	Location string   `xml:"location,attr,omitempty"`
	Begin    net.IP   `xml:"begin"`
	End      net.IP   `xml:"end"`
}

type IncludeURL struct {
	XMLName       xml.Name `xml:"include-url"`
	Content       string   `xml:",chardata"`
	Location      string   `xml:"location,attr,omitempty"`
	Retries       int      `xml:"retries,attr,omitempty"`
	Timeout       int      `xml:"timeout,attr,omitempty"`
	ForeignSource string   `xml:"foreign-source,attr,omitempty"`
}

type Definition struct {
	XMLName       xml.Name       `xml:"definition"`
	Location      string         `xml:"location,attr,omitempty"`
	Retries       int            `xml:"retries,attr,omitempty"`
	Timeout       int            `xml:"timeout,attr,omitempty"`
	ForeignSource string         `xml:"foreign-source,attr,omitempty"`
	ChunkSize     int            `xml:"chunkSize,attr,omitempty"`
	Detectors     []Detector     `xml:"detectors>detector,omitempty"`
	Specifics     []Specific     `xml:"specific,omitempty"`
	IncludeRanges []IncludeRange `xml:"include-range,omitempty"`
	ExcludeRanges []ExcludeRange `xml:"exclude-range,omitempty"`
	IncludeURLs   []IncludeURL   `xml:"include-url,omitempty"`
}

func (def *Definition) AddSpecific(specific string) {
	if ip := net.ParseIP(specific); ip == nil {
		return
	} else {
		def.Specifics = append(def.Specifics, Specific{IP: ip})
	}
}

func (def *Definition) AddIncludeURL(url string) {
	def.IncludeURLs = append(def.IncludeURLs, IncludeURL{
		Content: url,
	})
}

func (def *Definition) AddIncludeRange(begin, end string) {
	beginIP := net.ParseIP(begin)
	endIP := net.ParseIP(end)
	if beginIP == nil || endIP == nil {
		return
	}
	if def.ipToInt(endIP) > def.ipToInt(beginIP) {
		def.IncludeRanges = append(def.IncludeRanges, IncludeRange{
			Begin: beginIP,
			End:   endIP,
		})
	}
}

func (def *Definition) AddExcludeRange(begin, end string) {
	beginIP := net.ParseIP(begin)
	endIP := net.ParseIP(end)
	if beginIP == nil || endIP == nil {
		return
	}
	if def.ipToInt(endIP) > def.ipToInt(beginIP) {
		def.ExcludeRanges = append(def.ExcludeRanges, ExcludeRange{
			Begin: beginIP,
			End:   endIP,
		})
	}
}

func (def *Definition) IncludeCIDR(cidr string) {
	if ipBegin, ipEnd, err := def.getRange(cidr); err == nil {
		def.AddIncludeRange(ipBegin.String(), ipEnd.String())
	}
}

func (def *Definition) ExcludeCIDR(cidr string) {
	if ipBegin, ipEnd, err := def.getRange(cidr); err == nil {
		def.AddExcludeRange(ipBegin.String(), ipEnd.String())
	}
}

func (def *Definition) IncludeRangesContain(ipaddr string) bool {
	ip := net.ParseIP(ipaddr)
	if ip == nil {
		return false
	}
	for _, r := range def.IncludeRanges {
		if bytes.Compare(ip, r.Begin) >= 0 && bytes.Compare(ip, r.End) <= 0 {
			return true
		}
	}
	return false
}

func (def *Definition) ExcludeRangesContain(ipaddr string) bool {
	ip := net.ParseIP(ipaddr)
	if ip == nil {
		return false
	}
	for _, r := range def.ExcludeRanges {
		if bytes.Compare(ip, r.Begin) >= 0 && bytes.Compare(ip, r.End) <= 0 {
			return true
		}
	}
	return false
}

func (def *Definition) Sort() {
	sort.SliceStable(def.Specifics, func(i, j int) bool {
		a := def.ipToInt(def.Specifics[i].IP)
		b := def.ipToInt(def.Specifics[j].IP)
		return a < b
	})

	sort.SliceStable(def.IncludeRanges, func(i, j int) bool {
		a := def.ipToInt(def.IncludeRanges[i].Begin)
		b := def.ipToInt(def.IncludeRanges[j].End)
		return a < b
	})

	sort.SliceStable(def.ExcludeRanges, func(i, j int) bool {
		a := def.ipToInt(def.ExcludeRanges[i].Begin)
		b := def.ipToInt(def.ExcludeRanges[j].End)
		return a < b
	})
}

func (def *Definition) Merge() {
	def.Sort()
	rangeSet := new(IPAddressRangeSet)
	for _, r := range def.IncludeRanges {
		rangeSet.Add(r.ToIPAddressRange())
	}
	for _, s := range def.Specifics {
		rangeSet.Add(s.ToIPAddressRange())
	}
	def.Specifics = make([]Specific, 0)
	def.IncludeRanges = make([]IncludeRange, 0)
	for _, r := range rangeSet.Get() {
		if r.IsSingleton() {
			def.Specifics = append(def.Specifics, Specific{
				Location:      r.Location,
				Retries:       r.Retries,
				Timeout:       r.Timeout,
				ForeignSource: r.ForeignSource,
				IP:            r.Begin,
			})
		} else {
			def.IncludeRanges = append(def.IncludeRanges, IncludeRange{
				Location:      r.Location,
				Retries:       r.Retries,
				Timeout:       r.Timeout,
				ForeignSource: r.ForeignSource,
				Begin:         r.Begin,
				End:           r.End,
			})
		}
	}
}

// GetTotalEstimatedAddresses offers an estimate about the potential total number of IP addresses to consider for discovery.
// It ignores the external files.
func (def *Definition) GetTotalEstimatedAddresses() uint32 {
	var total uint32 = 0
	for _, r := range def.IncludeRanges {
		a := def.ipToInt(r.Begin)
		b := def.ipToInt(r.End)
		for i := a; i <= b; i++ {
			if !def.excludeRangesContain(i) {
				total++
			}
		}
	}
	for _, ip := range def.Specifics {
		i := def.ipToInt(ip.IP)
		if !def.excludeRangesContain(i) {
			total++
		}
	}
	return total
}

func (def *Definition) String() string {
	data, _ := xml.MarshalIndent(def, "", "   ")
	return string(data)
}

func (def *Definition) getRange(cidr string) (net.IP, net.IP, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, nil, err
	}
	mask := binary.BigEndian.Uint32(ipNet.Mask)
	start := binary.BigEndian.Uint32(ipNet.IP)
	finish := (start & mask) | (mask ^ 0xffffffff)
	return def.intToIp(start + 1), def.intToIp(finish - 1), nil
}

// Convert an IPv4 address to integer
func (def *Definition) ipToInt(ip net.IP) uint32 {
	if ip == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip.To4())
}

// Convert an integer to IPv4 address
func (def *Definition) intToIp(ipaddr uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipaddr)
	return ip
}

func (def *Definition) excludeRangesContain(ipaddr uint32) bool {
	for _, r := range def.ExcludeRanges {
		if ipaddr >= def.ipToInt(r.Begin) && ipaddr <= def.ipToInt(r.End) {
			return true
		}
	}
	return false
}

type DiscoveryConfiguration struct {
	XMLName          xml.Name     `xml:"http://xmlns.opennms.org/xsd/config/discovery discovery-configuration"`
	PacketsPerSecond int          `xml:"packets-per-second,attr,omitempty"`
	InitialSleepTime int          `xml:"initial-sleep-time,attr,omitempty"`
	RestartSleepTime int          `xml:"restart-sleep-time,attr,omitempty"`
	Retries          int          `xml:"retries,attr,omitempty"`
	Timeout          int          `xml:"timeout,attr,omitempty"`
	ChunkSize        int          `xml:"chunk-size,attr,omitempty"`
	Definitions      []Definition `xml:"definition,omitempty"`
}

func (cfg *DiscoveryConfiguration) AddDefinition(d Definition) {
	cfg.Definitions = append(cfg.Definitions, d)
}

func (cfg *DiscoveryConfiguration) Sort() {
	for i := range cfg.Definitions {
		d := &cfg.Definitions[i]
		d.Sort()
	}
}

func (cfg *DiscoveryConfiguration) Merge() {
	for i := range cfg.Definitions {
		d := &cfg.Definitions[i]
		d.Merge()
	}
}

func (cfg *DiscoveryConfiguration) GetTotalEstimatedAddresses() uint32 {
	var total uint32 = 0
	for _, d := range cfg.Definitions {
		total += d.GetTotalEstimatedAddresses()
	}
	return total
}

func (cfg *DiscoveryConfiguration) UpdateOpenNMS(onmsHomePath string, onmsPort int) error {
	dest := onmsHomePath + "/etc/discovery-configuration.xml"
	if _, err := os.Stat(dest); errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("discovery configuration file not found at %s", dest)
	}
	current := new(DiscoveryConfiguration)
	if current_bytes, err := ioutil.ReadFile(dest); err == nil {
		xml.Unmarshal(current_bytes, current)
	} else {
		return fmt.Errorf("cannot read discovery configuration: %v", err)
	}
	if cfg.String() == current.String() {
		return fmt.Errorf("there are no differences between the generated and the current configuration; no changes applied")
	}
	if err := os.WriteFile(dest, []byte(cfg.String()), 0644); err != nil {
		return fmt.Errorf("cannot write discovery configuration: %v", err)
	}
	hostname, _ := os.Hostname()
	event := Event{
		UEI:    "uei.opennms.org/internal/reloadDaemonConfig",
		Source: "DiscoverConfigGenerator",
		Time:   time.Now().Format(time.RFC3339),
		Host:   hostname,
		Parameters: []Parm{
			{
				Name: "daemonName",
				Value: ParmValue{
					Type:     "string",
					Encoding: "text",
					Content:  "Discovery",
				},
			},
		},
	}
	log := new(Log)
	log.Add(event)
	return log.Send("127.0.0.1", onmsPort)
}

func (cfg *DiscoveryConfiguration) String() string {
	data, _ := xml.MarshalIndent(cfg, "", "   ")
	return string(data)
}
