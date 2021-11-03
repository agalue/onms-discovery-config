package main

import (
	"bufio"
	"encoding/xml"
	"flag"
	"log"
	"net"
	"os"
	"os/exec"
	"regexp"
)

var addressBlackList = make(map[string]bool)

var baseConfig = &DiscoveryConfiguration{
	InitialSleepTime: 30000,
	RestartSleepTime: 86400000,
	Retries:          1,
	Timeout:          2000,
	PacketsPerSecond: 1,
	Definitions: []Definition{
		{
			Detectors: []Detector{
				{
					Name:  "ReverseDNS",
					Class: "org.opennms.netmgt.provision.detector.rdns.ReverseDNSLookupDetector",
				},
				{
					Name:  "SNMP",
					Class: "org.opennms.netmgt.provision.detector.snmp.SnmpDetector",
					Parameters: []Parameter{
						{
							Key:   "useSnmpProfiles",
							Value: "true",
						},
					},
				},
			},
		},
	},
}

func addSpecific(def *Definition, ip string) {
	if net.ParseIP(ip) == nil { // Not an IP Address
		return
	}
	if _, ok := addressBlackList[ip]; ok {
		log.Printf("ignore: IP %s is blacklisted", ip)
		return
	}
	if def.ExcludeContains(ip) {
		log.Printf("ignore: IP %s is part of exclude ranges", ip)
		return
	}
	log.Printf("adding IP %s", ip)
	def.AddSpecific(ip)
}

func getScanner(fileName string) *bufio.Scanner {
	file, err := os.Open(fileName)
	if err != nil {
		log.Fatalf("failed opening file: %s", err)
	}
	return bufio.NewScanner(file)
}

func main() {
	def := &baseConfig.Definitions[0] // Keep a reference to the main definition

	var onmsPort int
	var onmsHome, includeCIDR, excludeCIDR, includeList, excludeList, includeDNS, includeNNMiHex string
	flag.StringVar(&includeCIDR, "inc-cidr", "", "Path to a file with a list of CIDRs to include in the configuration")
	flag.StringVar(&excludeCIDR, "exc-cidr", "", "Path to a file with a list of CIDRs to exclude in the configuration")
	flag.StringVar(&includeList, "inc-list", "", "Path to a file with a list of IP addresses to include in the configuration (excluding 'exc-list')")
	flag.StringVar(&excludeList, "exc-list", "", "Path to a file with a list of IP addresses to exclude; affects 'inc-list', 'inc-dns' and 'inc-hexnnmi'")
	flag.StringVar(&includeDNS, "inc-dns", "", "Path to a file with a list of IP addresses to include in the configuration; e.x. ipv4addr=10.0.0.1")
	flag.StringVar(&includeNNMiHex, "inc-hexnnmi", "", "Path to a file with a list of IP addresses in Hex format from NNMi")
	flag.StringVar(&onmsHome, "onms-home", "/opt/opennms", "Home path to OpenNMS")
	flag.IntVar(&onmsPort, "onms-port", 5817, "The TCP Port to send events to OpenNMS")
	flag.Parse()

	if includeCIDR != "" {
		log.Printf("processing Include CIDR %s", includeCIDR)
		s := getScanner(includeCIDR)
		for s.Scan() {
			log.Printf("including CIDR %s", s.Text())
			def.IncludeCIDR(s.Text())
		}
	}

	if excludeCIDR != "" {
		log.Printf("processing Exclude CIDR %s", excludeCIDR)
		s := getScanner(excludeCIDR)
		for s.Scan() {
			log.Printf("excluding CIDR %s", s.Text())
			def.ExcludeCIDR(s.Text())
		}
	}

	if excludeList != "" {
		log.Printf("processing Exclude List %s", excludeList)
		s := getScanner(excludeList)
		for s.Scan() {
			log.Printf("excluding IP %s", s.Text())
			addressBlackList[s.Text()] = true
		}
	}

	if includeList != "" {
		log.Printf("processing Include List %s", includeList)
		s := getScanner(includeList)
		for s.Scan() {
			addSpecific(def, s.Text())
		}
	}

	if includeDNS != "" {
		log.Printf("processing DNS File %s", includeDNS)
		re := regexp.MustCompile(`ipv4addr: (\d+\.\d+\.\d+\.\d+)`)
		s := getScanner(includeDNS)
		for s.Scan() {
			if match := re.FindStringSubmatch(s.Text()); len(match) == 2 {
				addSpecific(def, match[1])
			}
		}

	}

	if includeNNMiHex != "" {
		log.Printf("processing NNMi Hex File %s", includeNNMiHex)
		command := `open HEX, $ARGV[0]; while (<HEX>) { chomp; print join(".", map { hex($_) } unpack ("(A2)*", substr($_, -8))), "\n"; } close HEX;`
		cmd := exec.Command("/usr/bin/perl", "-e", command, includeNNMiHex)
		r, _ := cmd.StdoutPipe()
		if err := cmd.Start(); err != nil {
			log.Printf("cannot execute command: %v", err)
		}
		s := bufio.NewScanner(r)
		for s.Scan() {
			addSpecific(def, s.Text())
		}
		cmd.Wait()
	}

	data, _ := xml.MarshalIndent(baseConfig, "", "   ")
	log.Printf("generated configuration: %s", string(data))
	log.Printf("saving discovery configuration and notifying OpenNMS")
	if err := baseConfig.UpdateOpenNMS(onmsHome, onmsPort); err != nil {
		log.Fatal(err)
	}
}
