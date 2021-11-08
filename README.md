# onms-discovery-config

This is a tool to generate Discoverd's configuration for OpenNMS for a specific use case. Unfortunately, we cannot change some vital elements from the Discovery configuration via the ReST API. For that reason, the tool should run within the OpenNMS server, and when this happens, it will replace the `discovery-configuration.xml` file and send an event via TCP 5817 to request a reload. If not, it will display the generated config, but it won't update OpenNMS.

The use case involves having external files with the following information:

* A black list of IP addresses to ignore.
* A black list of CIRDs to exclude from the discovery process.
* A white list of CIRDs to include in the discovery process.
* A white list of IP addresses to include, as long as they are not part of the black lists.
* A white list of IP addresses in a binary format based on NNMi.
* A white-list of IP addresses from a DNS record dump where each IP has a prefix `ipv4addr=`.

The logic to parse the NNMi addresses in Hex format was originally written in Perl. Due to the lack of documentation, I decided to use Perl only for those addresses, meaning Perl should be installed and accessible via `/usr/bin/perl` (there is no need for other libraries).

## Compilation (Optional)

If you have Go 1.17 installed on your system:

```bash
go build .
```

If you're not running Linux and you want to generate a Linux binary:

```bash
GOOS=linux GOARCH=amd64 go build .
```

> Please note that you don't have to compile the tool to use it. You can download the pre-compiled binary from the releases. There is no need to have Go installed on your system, and the binary contains everything it needs to run (zero dependencies required).

## Usage

If you have the compiled binary:

```bash
onms-discovery-config \
  -exc-cidr /tmp/ignore_cidrs.txt \
  -exc-list /tmp/ignore_ips.txt \
  -inc-cidr /tmp/cidr_only.txt \
  -inc-list /tmp/specific_ips.txt \
  -inc-dns /tmp/dns_a_hosts_records.txt \
  -inc-hexnnmi /tmp/nnmi_hex_ips
```

If not:

```bash
go run . \
  -exc-cidr /tmp/ignore_cidrs.txt \
  -exc-list /tmp/ignore_ips.txt \
  -inc-cidr /tmp/cidr_only.txt \
  -inc-list /tmp/specific_ips.txt \
  -inc-dns /tmp/dns_a_hosts_records.txt \
  -inc-hexnnmi /tmp/nnmi_hex_ips
```

You can pass `-dry-run`, and it will just display the generated XML in standard output without touching or modifying OpenNMS.

Passing `-h` or `--help` will show a short description of how to use the program.

Enjoy!