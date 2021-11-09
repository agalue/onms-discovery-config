package main

import (
	"bufio"
	"flag"
	"log"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

var addressWhiteList = make(map[string]bool) // Temporary map to avoid duplicates
var addressBlackList = make(map[string]bool) // Temporary map to facilitate excluding addresses

var baseConfig = &DiscoveryConfiguration{
	InitialSleepTime: 30000,
	RestartSleepTime: 86400000,
	Retries:          1,
	Timeout:          2000,
	PacketsPerSecond: 10, // Rate limit how many ICMP requests are going out when pinging (large) ranges
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

// Warning: ensure CIDRs and black-lists are loaded and processed before using this method
func addSpecific(def *Definition, ip string) {
	if net.ParseIP(ip) == nil { // Not an IP Address
		log.Printf("ignore: '%s' is not a valid IP address", ip)
		return
	}
	if _, ok := addressBlackList[ip]; ok {
		log.Printf("ignore: IP %s is blacklisted", ip)
		return
	}
	if def.ExcludeRangesContain(ip) {
		log.Printf("ignore: IP %s is part of exclude ranges", ip)
		return
	}
	if def.IncludeRangesContain(ip) {
		log.Printf("ignore: IP %s is part of include ranges", ip)
		return
	}
	if _, ok := addressWhiteList[ip]; !ok {
		log.Printf("adding sepcific IP %s", ip)
		def.AddSpecific(ip)
		addressWhiteList[ip] = true
	} else {
		log.Printf("ignore: IP %s already included", ip)
	}
}

func getScanner(fileName string) *bufio.Scanner {
	file, err := os.Open(fileName)
	if err != nil {
		log.Fatalf("failed opening file: %s", err)
	}
	return bufio.NewScanner(file)
}

func main() {
	log.SetOutput(os.Stdout)
	def := &baseConfig.Definitions[0] // Keep a reference to the main definition

	var dryRun bool
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

	flag.IntVar(&baseConfig.InitialSleepTime, "disc-initial-sleep-time", baseConfig.InitialSleepTime, "Discoverd Initial Sleep/Pause Time after discovery starts up (in milliseconds)")
	flag.IntVar(&baseConfig.RestartSleepTime, "disc-restart-sleep-time", baseConfig.RestartSleepTime, "Discoverd Restart Sleep/Pause Time between discovery passes (in milliseconds)")
	flag.IntVar(&baseConfig.Retries, "disc-retries", baseConfig.Retries, "Discoverd Ping Retries")
	flag.IntVar(&baseConfig.Timeout, "disc-timeout", baseConfig.Timeout, "Discoverd Ping Timeout")
	flag.IntVar(&baseConfig.PacketsPerSecond, "disc-packets-per-second", baseConfig.PacketsPerSecond, "Discoverd Packets Per Second (rate limit how many ICMP requests are going out)")

	flag.BoolVar(&dryRun, "dry-run", false, "Whether or not to update OpenNMS configuration")

	flag.Parse()

	if includeCIDR != "" {
		log.Printf("processing Include CIDR %s", includeCIDR)
		s := getScanner(includeCIDR)
		for s.Scan() {
			cidr := strings.TrimSpace(s.Text())
			log.Printf("including CIDR %s", cidr)
			def.IncludeCIDR(cidr)
		}
	}

	if excludeCIDR != "" {
		log.Printf("processing Exclude CIDR %s", excludeCIDR)
		s := getScanner(excludeCIDR)
		for s.Scan() {
			cidr := strings.TrimSpace(s.Text())
			log.Printf("excluding CIDR %s", cidr)
			def.ExcludeCIDR(cidr)
		}
	}

	if excludeList != "" {
		log.Printf("processing Exclude List %s", excludeList)
		s := getScanner(excludeList)
		for s.Scan() {
			ip := strings.TrimSpace(s.Text())
			if net.ParseIP(ip) == nil { // Not an IP Address
				log.Printf("ignore: %s is not a valid IP address", ip)
			} else {
				log.Printf("excluding IP %s", s.Text())
				addressBlackList[s.Text()] = true
			}
		}
	}

	if includeList != "" {
		log.Printf("processing Include List %s", includeList)
		s := getScanner(includeList)
		for s.Scan() {
			ip := strings.TrimSpace(s.Text())
			addSpecific(def, ip)
		}
	}

	if includeDNS != "" {
		log.Printf("processing DNS File %s", includeDNS)
		re := regexp.MustCompile(`ipv4addr: (\d+\.\d+\.\d+\.\d+)`)
		s := getScanner(includeDNS)
		for s.Scan() {
			line := strings.TrimSpace(s.Text())
			if match := re.FindStringSubmatch(line); len(match) == 2 {
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
			ip := strings.TrimSpace(s.Text())
			addSpecific(def, ip)
		}
		cmd.Wait()
	}

	baseConfig.Sort()
	log.Printf("generated configuration:\n%s", baseConfig.String())
	log.Printf("the estimated number of IP addresses to check is about %d", baseConfig.GetTotalEstimatedAddresses())
	if !dryRun {
		log.Printf("saving discovery configuration and notifying OpenNMS")
		if err := baseConfig.UpdateOpenNMS(onmsHome, onmsPort); err != nil {
			log.Fatal(err)
		}
	}
}
