// Author: Alejandro galue <agalue@opennms.org>

// Representation and helper functions for discovery-configuration.xml
// https://github.com/OpenNMS/opennms/blob/master/opennms-config-model/src/main/resources/xsds/discovery-configuration.xsd

package main

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
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

func (r *ExcludeRange) ToIPAddressRange() IPAddressRange {
	return IPAddressRange{
		Location: r.Location,
		Begin:    r.Begin,
		End:      r.End,
	}
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
	if IP2Int(endIP).Cmp(IP2Int(beginIP)) >= 0 {
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
	if IP2Int(endIP).Cmp(IP2Int(beginIP)) >= 0 {
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
		a := IP2Int(def.Specifics[i].IP)
		b := IP2Int(def.Specifics[j].IP)
		return a.Cmp(b) < 0
	})

	sort.SliceStable(def.IncludeRanges, func(i, j int) bool {
		a := IP2Int(def.IncludeRanges[i].Begin)
		b := IP2Int(def.IncludeRanges[j].End)
		return a.Cmp(b) < 0
	})

	sort.SliceStable(def.ExcludeRanges, func(i, j int) bool {
		a := IP2Int(def.ExcludeRanges[i].Begin)
		b := IP2Int(def.ExcludeRanges[j].End)
		return a.Cmp(b) < 0
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

	excludeSet := new(IPAddressRangeSet)
	for _, r := range def.ExcludeRanges {
		excludeSet.Add(r.ToIPAddressRange())
	}
	def.ExcludeRanges = make([]ExcludeRange, 0)
	for _, r := range excludeSet.Get() {
		def.ExcludeRanges = append(def.ExcludeRanges, ExcludeRange{
			Location: r.Location,
			Begin:    r.Begin,
			End:      r.End,
		})
	}

}

// GetTotalEstimatedAddresses offers an estimate about the potential total number of IP addresses to consider for discovery.
// It ignores the external files.
func (def *Definition) GetTotalEstimatedAddresses() uint32 {
	var total uint32 = 0
	for _, r := range def.IncludeRanges {
		a := IP2Int(r.Begin)
		b := IP2Int(r.End)
		for i := a; i.Int64() <= b.Int64(); i.Add(i, big.NewInt(1)) {
			if !def.excludeRangesContain(i) {
				total++
			}
		}
	}
	for _, ip := range def.Specifics {
		i := IP2Int(ip.IP)
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
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, nil, err
	}

	firstIP := network.IP
	prefixLen, bits := network.Mask.Size()
	firstIPInt := IP2Int(firstIP)
	hostLen := uint(bits) - uint(prefixLen)
	lastIPInt := big.NewInt(1)
	lastIPInt.Lsh(lastIPInt, hostLen)
	lastIPInt.Sub(lastIPInt, big.NewInt(1))
	lastIPInt.Or(lastIPInt, firstIPInt)
	lastIP := Int2IP(lastIPInt)
	firstIP[len(firstIP)-1]++
	lastIP[len(lastIP)-1]--
	return firstIP, lastIP, nil
}

func (def *Definition) excludeRangesContain(ipaddr *big.Int) bool {
	for _, r := range def.ExcludeRanges {
		if ipaddr.Cmp(IP2Int(r.Begin)) >= 0 && ipaddr.Cmp(IP2Int(r.End)) <= 0 {
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
