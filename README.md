# iptables_exporter

Prometheus exporter for iptables packet and byte counters, written in Go.

## Usage

### Required Permissions

Unfortunately, `iptables-save` (which this exporter uses) doesn't work without special permissions.

Including the following systemd `[Service]` options will allow this exporter to work without running it as root:

    CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_NET_ADMIN CAP_NET_RAW
    AmbientCapabilities=CAP_DAC_READ_SEARCH CAP_NET_ADMIN CAP_NET_RAW

### Exported Metrics

This exporter is best used in conjunction with iptables rules that cause interesting traffic flows to be counted.

For example, on a Cassandra server, the following rules will record CQL, Thrift, and inter-node traffic:

    $ cat /etc/iptables.rules
    *mangle
    :PREROUTING ACCEPT [0:0]
    :INPUT ACCEPT [0:0]
    :FORWARD ACCEPT [0:0]
    :OUTPUT ACCEPT [0:0]
    :POSTROUTING ACCEPT [0:0]
    COMMIT
    *filter
    :INPUT ACCEPT [0:0]
    :FORWARD ACCEPT [0:0]
    :OUTPUT ACCEPT [0:0]
    -A INPUT -p tcp -m tcp --dport 7000 -j ACCEPT
    -A INPUT -p tcp -m tcp --dport 9160 -j ACCEPT
    -A INPUT -p tcp -m tcp --dport 7199 -j ACCEPT
    -A INPUT -p tcp -m tcp --dport 9042 -j ACCEPT
    -A OUTPUT -p tcp -m tcp --sport 7000 -j ACCEPT
    -A OUTPUT -p tcp -m tcp --sport 9160 -j ACCEPT
    -A OUTPUT -p tcp -m tcp --sport 7199 -j ACCEPT
    -A OUTPUT -p tcp -m tcp --sport 9042 -j ACCEPT
    COMMIT

Using this exporter, you can then collect packet and byte counts for each of those categories of traffic:

    # HELP iptables_default_bytes_total iptables_exporter: Total bytes matching a chain's default policy.
    # TYPE iptables_default_bytes_total counter
    iptables_default_bytes_total{chain="FORWARD",policy="ACCEPT",table="filter"} 0
    iptables_default_bytes_total{chain="FORWARD",policy="ACCEPT",table="mangle"} 0
    iptables_default_bytes_total{chain="INPUT",policy="ACCEPT",table="filter"} 3.995502612e+09
    iptables_default_bytes_total{chain="INPUT",policy="ACCEPT",table="mangle"} 3.0249135048e+10
    iptables_default_bytes_total{chain="OUTPUT",policy="ACCEPT",table="filter"} 1.5769783643e+10
    iptables_default_bytes_total{chain="OUTPUT",policy="ACCEPT",table="mangle"} 2.1481729166e+10
    iptables_default_bytes_total{chain="POSTROUTING",policy="ACCEPT",table="mangle"} 2.1481729166e+10
    iptables_default_bytes_total{chain="PREROUTING",policy="ACCEPT",table="mangle"} 3.0249135756e+10
    # HELP iptables_default_packets_total iptables_exporter: Total packets matching a chain's default policy.
    # TYPE iptables_default_packets_total counter
    iptables_default_packets_total{chain="FORWARD",policy="ACCEPT",table="filter"} 0
    iptables_default_packets_total{chain="FORWARD",policy="ACCEPT",table="mangle"} 0
    iptables_default_packets_total{chain="INPUT",policy="ACCEPT",table="filter"} 5.5426298e+07
    iptables_default_packets_total{chain="INPUT",policy="ACCEPT",table="mangle"} 1.48795042e+08
    iptables_default_packets_total{chain="OUTPUT",policy="ACCEPT",table="filter"} 5.6437034e+07
    iptables_default_packets_total{chain="OUTPUT",policy="ACCEPT",table="mangle"} 1.46199076e+08
    iptables_default_packets_total{chain="POSTROUTING",policy="ACCEPT",table="mangle"} 1.46199076e+08
    iptables_default_packets_total{chain="PREROUTING",policy="ACCEPT",table="mangle"} 1.48795045e+08
    # HELP iptables_rule_bytes_total iptables_exporter: Total bytes matching a rule.
    # TYPE iptables_rule_bytes_total counter
    iptables_rule_bytes_total{chain="INPUT",rule="-p tcp -m tcp --dport 7000 -j ACCEPT",table="filter"} 1.5726563828e+10
    iptables_rule_bytes_total{chain="INPUT",rule="-p tcp -m tcp --dport 7199 -j ACCEPT",table="filter"} 968212
    iptables_rule_bytes_total{chain="INPUT",rule="-p tcp -m tcp --dport 9042 -j ACCEPT",table="filter"} 1.0526099958e+10
    iptables_rule_bytes_total{chain="INPUT",rule="-p tcp -m tcp --dport 9160 -j ACCEPT",table="filter"} 0
    iptables_rule_bytes_total{chain="OUTPUT",rule="-p tcp -m tcp --sport 7000 -j ACCEPT",table="filter"} 3.944347161e+09
    iptables_rule_bytes_total{chain="OUTPUT",rule="-p tcp -m tcp --sport 7199 -j ACCEPT",table="filter"} 1.922188e+06
    iptables_rule_bytes_total{chain="OUTPUT",rule="-p tcp -m tcp --sport 9042 -j ACCEPT",table="filter"} 1.765671261e+09
    iptables_rule_bytes_total{chain="OUTPUT",rule="-p tcp -m tcp --sport 9160 -j ACCEPT",table="filter"} 0
    # HELP iptables_rule_packets_total iptables_exporter: Total packets matching a rule.
    # TYPE iptables_rule_packets_total counter
    iptables_rule_packets_total{chain="INPUT",rule="-p tcp -m tcp --dport 7000 -j ACCEPT",table="filter"} 5.6296722e+07
    iptables_rule_packets_total{chain="INPUT",rule="-p tcp -m tcp --dport 7199 -j ACCEPT",table="filter"} 10582
    iptables_rule_packets_total{chain="INPUT",rule="-p tcp -m tcp --dport 9042 -j ACCEPT",table="filter"} 3.7061438e+07
    iptables_rule_packets_total{chain="INPUT",rule="-p tcp -m tcp --dport 9160 -j ACCEPT",table="filter"} 0
    iptables_rule_packets_total{chain="OUTPUT",rule="-p tcp -m tcp --sport 7000 -j ACCEPT",table="filter"} 5.5426875e+07
    iptables_rule_packets_total{chain="OUTPUT",rule="-p tcp -m tcp --sport 7199 -j ACCEPT",table="filter"} 8351
    iptables_rule_packets_total{chain="OUTPUT",rule="-p tcp -m tcp --sport 9042 -j ACCEPT",table="filter"} 3.4326805e+07
    iptables_rule_packets_total{chain="OUTPUT",rule="-p tcp -m tcp --sport 9160 -j ACCEPT",table="filter"} 0
    # HELP iptables_scrape_duration_seconds iptables_exporter: Duration of scraping iptables.
    # TYPE iptables_scrape_duration_seconds gauge
    iptables_scrape_duration_seconds 0.001509662
    # HELP iptables_scrape_success iptables_exporter: Whether scraping iptables succeeded.
    # TYPE iptables_scrape_success gauge
    iptables_scrape_success 1
