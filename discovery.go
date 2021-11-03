package main

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"os"
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
	Content       string   `xml:",chardata"`
	Location      string   `xml:"location,attr,omitempty"`
	Retries       int      `xml:"retries,attr,omitempty"`
	Timeout       int      `xml:"timeout,attr,omitempty"`
	ForeignSource string   `xml:"foreign-source,attr,omitempty"`
}

type IncludeRange struct {
	XMLName       xml.Name `xml:"include-range"`
	Location      string   `xml:"location,attr,omitempty"`
	Retries       int      `xml:"retries,attr,omitempty"`
	Timeout       int      `xml:"timeout,attr,omitempty"`
	ForeignSource string   `xml:"foreign-source,attr,omitempty"`
	Begin         string   `xml:"begin"`
	End           string   `xml:"end"`
}

type ExcludeRange struct {
	XMLName xml.Name `xml:"exclude-range"`
	Begin   string   `xml:"begin"`
	End     string   `xml:"end"`
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
	if net.ParseIP(specific) == nil {
		return
	}
	def.Specifics = append(def.Specifics, Specific{
		Content: specific,
	})
}

func (def *Definition) AddIncludeURL(url string) {
	def.IncludeURLs = append(def.IncludeURLs, IncludeURL{
		Content: url,
	})
}

func (def *Definition) AddIncludeRange(begin, end string) {
	if net.ParseIP(begin) == nil || net.ParseIP(end) == nil {
		return
	}
	def.IncludeRanges = append(def.IncludeRanges, IncludeRange{
		Begin: begin,
		End:   end,
	})
}

func (def *Definition) AddExcludeRange(begin, end string) {
	if net.ParseIP(begin) == nil || net.ParseIP(end) == nil {
		return
	}
	def.ExcludeRanges = append(def.ExcludeRanges, ExcludeRange{
		Begin: begin,
		End:   end,
	})
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

func (def *Definition) getRange(cidr string) (net.IP, net.IP, error) {
	ipBegin, ipv4Net, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, nil, err
	}
	mask := binary.BigEndian.Uint32(ipv4Net.Mask)
	start := binary.BigEndian.Uint32(ipv4Net.IP)
	finish := (start & mask) | (mask ^ 0xffffffff)
	ipEnd := make(net.IP, 4)
	binary.BigEndian.PutUint32(ipEnd, finish-1)
	return ipBegin, ipEnd, nil
}

func (def *Definition) ExcludeContains(ipaddr string) bool {
	ip := net.ParseIP(ipaddr)
	if ip == nil {
		return false
	}
	for _, r := range def.ExcludeRanges {
		if bytes.Compare(ip, net.ParseIP(r.Begin)) >= 0 && bytes.Compare(ip, net.ParseIP(r.End)) <= 0 {
			return true
		}
	}
	return false
}

type DiscoveryConfiguration struct {
	XMLName          xml.Name     `xml:"discovery-configuration"`
	PacketsPerSecond int          `xml:"packets-per-second,attr,omitempty"`
	InitialSleepTime int          `xml:"initial-sleep-time,attr,omitempty"`
	RestartSleepTime int          `xml:"restart-sleep-time,attr,omitempty"`
	Retries          int          `xml:"retries,attr,omitempty"`
	Timeout          int          `xml:"timeout,attr,omitempty"`
	Definitions      []Definition `xml:"definition,omitempty"`
}

func (cfg *DiscoveryConfiguration) AddDefinition(d Definition) {
	cfg.Definitions = append(cfg.Definitions, d)
}

func (cfg *DiscoveryConfiguration) UpdateOpenNMS(onmsHomePath string) error {
	dest := onmsHomePath + "/etc/discovery-configuration.xml"
	if _, err := os.Stat(dest); errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("discovery configuration file not found at %s", dest)
	}
	data, _ := xml.MarshalIndent(cfg, "", "   ")
	if err := os.WriteFile(dest, data, 0644); err != nil {
		return err
	}
	hostname, _ := os.Hostname()
	event := Event{
		UEI:    "uei.opennms.org/intertal/reloadDaemonConfig",
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
	return log.Send("127.0.0.1", 5817)
}
