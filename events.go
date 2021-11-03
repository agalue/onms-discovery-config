package main

import (
	"encoding/xml"
	"fmt"
	"net"
)

type ParmValue struct {
	XMLName  xml.Name `xml:"value"`
	Type     string   `xml:"type,attr"`
	Encoding string   `xml:"encoding,attr"`
	Content  string   `xml:",chardata"`
}

type Parm struct {
	XMLName xml.Name  `xml:"parm"`
	Name    string    `xml:"parmName"`
	Value   ParmValue `xml:"value"`
}

type Event struct {
	XMLName     xml.Name `xml:"event"`
	UEI         string   `xml:"parmName"`
	Source      string   `xml:"source,omitempty"`
	NodeID      int      `xml:"nodeid,omitempty"`
	Time        string   `xml:"time,omitempty"`
	Host        string   `xml:"host,omitempty"`
	Interface   string   `xml:"interface,omitempty"`
	Service     string   `xml:"service,omitempty"`
	IfIndex     int      `xml:"ifIndex,omitempty"`
	Parameters  []Parm   `xml:"parms>parm"`
	Description string   `xml:"descr,omitempty"`
	LogMsg      string   `xml:"logmsg,omitempty"`
	Severity    string   `xml:"severity,omitempty"`
}

type Log struct {
	XMLName xml.Name `xml:"log"`
	Events  []Event  `xml:"events>event"`
}

func (log *Log) Add(e Event) {
	log.Events = append(log.Events, e)
}

func (log *Log) Send(target string, port int) error {
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", target, port))
	if err != nil {
		return err
	}
	defer conn.Close()
	bytes, _ := xml.Marshal(log)
	_, err = conn.Write(bytes)
	return err
}
