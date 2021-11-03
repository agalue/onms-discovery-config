# onms-discovery-config

This is a tool to generate Discoverd's configuration for OpenNMS for a specific use case.

The use case involves having external files with the following information:

* A black list of IP addresses to ignore.
* A black list of CIRDs to exclude from the discovery process.
* A white list of CIRDs to include in the discovery process.
* A white list of IP addresses to include, as long as they are not part of the black lists.
* A white list of IP addresses in a binary format based on NNMi.
* A white-list of IP addresses from a DNS record dump where each IP has a prefix `ipv4addr=`.

The logic to parse the NNMi addresses in Hex format was originally written in Perl. Due to the lack of documentation, I decided to use Perl only for those addresses, meaning Perl should be installed and accessible via `/usr/bin/perl` (there is no need for other libraries).

## Compilation

If you have Go 1.17 installed on your system:

```bash
go build .
```

If you're not running Linux and you want to generate a Linux binary:

```bash
GOOS=linux GOARCH=amd64 go build .
```

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

Passing `-h` or `--help` will show a short description of how to use the program.

Only when it is executed from the OpenNMS server, it will override the configuration at `$OPENNMS_HOME/etc/discovery-configuration.xml` and will use the listener on port TCP 5817 to send an event to OpenNMS to reload the configuration (similar to how `send-event.pl` works).

Enjoy!