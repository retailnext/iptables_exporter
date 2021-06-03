// Copyright 2018 RetailNext, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/log"
	"github.com/prometheus/common/version"
	"github.com/retailnext/iptables_exporter/iptables"
	"gopkg.in/alecthomas/kingpin.v2"
)

type collector struct{}

var (
	scrapeDurationDesc = prometheus.NewDesc(
		"iptables_scrape_duration_seconds",
		"iptables_exporter: Duration of scraping iptables.",
		nil,
		nil,
	)

	scrapeSuccessDesc = prometheus.NewDesc(
		"iptables_scrape_success",
		"iptables_exporter: Whether scraping iptables succeeded.",
		nil,
		nil,
	)

	defaultBytesDesc = prometheus.NewDesc(
		"iptables_default_bytes_total",
		"iptables_exporter: Total bytes matching a chain's default policy.",
		[]string{"command", "table", "chain", "policy"},
		nil,
	)

	defaultPacketsDesc = prometheus.NewDesc(
		"iptables_default_packets_total",
		"iptables_exporter: Total packets matching a chain's default policy.",
		[]string{"command", "table", "chain", "policy"},
		nil,
	)

	ruleBytesDesc = prometheus.NewDesc(
		"iptables_rule_bytes_total",
		"iptables_exporter: Total bytes matching a rule.",
		[]string{"command", "table", "chain", "rule"},
		nil,
	)

	rulePacketsDesc = prometheus.NewDesc(
		"iptables_rule_packets_total",
		"iptables_exporter: Total packets matching a rule.",
		[]string{"command", "table", "chain", "rule"},
		nil,
	)
)

func (c *collector) Describe(descChan chan<- *prometheus.Desc) {
	descChan <- scrapeDurationDesc
	descChan <- scrapeSuccessDesc
	descChan <- defaultBytesDesc
	descChan <- defaultPacketsDesc
	descChan <- ruleBytesDesc
	descChan <- rulePacketsDesc
}

func (c *collector) Collect(metricChan chan<- prometheus.Metric) {
	commands := []string{"iptables-save", "ip6tables-save"}
	start := time.Now()

	duration := time.Since(start)
	metricChan <- prometheus.MustNewConstMetric(scrapeDurationDesc, prometheus.GaugeValue, duration.Seconds())
	metricChan <- prometheus.MustNewConstMetric(scrapeSuccessDesc, prometheus.GaugeValue, 1)

	for _, command := range commands {
		tables, err := iptables.GetTables(command)
		if err != nil {
			metricChan <- prometheus.MustNewConstMetric(scrapeSuccessDesc, prometheus.GaugeValue, 0)
			log.Error(err)
			return
		}

		for tableName, table := range tables {
			for chainName, chain := range table {
				metricChan <- prometheus.MustNewConstMetric(
					defaultPacketsDesc,
					prometheus.CounterValue,
					float64(chain.Packets),
					command,
					tableName,
					chainName,
					chain.Policy,
				)
				metricChan <- prometheus.MustNewConstMetric(
					defaultBytesDesc,
					prometheus.CounterValue,
					float64(chain.Bytes),
					command,
					tableName,
					chainName,
					chain.Policy,
				)
				for _, rule := range chain.Rules {
					metricChan <- prometheus.MustNewConstMetric(
						rulePacketsDesc,
						prometheus.CounterValue,
						float64(rule.Packets),
						command,
						tableName,
						chainName,
						rule.Rule,
					)
					metricChan <- prometheus.MustNewConstMetric(
						ruleBytesDesc,
						prometheus.CounterValue,
						float64(rule.Bytes),
						command,
						tableName,
						chainName,
						rule.Rule,
					)
				}
			}
		}
	}
}

func main() {
	// Adapted from github.com/prometheus/node_exporter

	var (
		listenAddress = kingpin.Flag(
			"web.listen-address",
			"Address on which to expose metrics and web interface.",
		).Default(
			":9455",
		).String()
		metricsPath = kingpin.Flag(
			"web.telemetry-path",
			"Path under which to expose metrics.",
		).Default(
			"/metrics",
		).String()
	)

	log.AddFlags(kingpin.CommandLine)
	kingpin.Version(version.Print("iptables_exporter"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()

	log.Infoln("Starting iptables_exporter", version.Info())
	log.Infoln("Build context", version.BuildContext())

	var c collector
	prometheus.MustRegister(&c)

	http.Handle(*metricsPath, promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
			<head><title>iptables exporter</title></head>
			<body>
			<h1>iptables exporter</h1>
			<p><a href="` + *metricsPath + `">Metrics</a></p>
			</body>
			</html>`))
	})

	log.Infoln("Listening on", *listenAddress)
	err := http.ListenAndServe(*listenAddress, nil)
	if err != nil {
		log.Fatal(err)
	}
}
