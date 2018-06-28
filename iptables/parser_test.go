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

package iptables

import (
	"os"
	"testing"

	"github.com/go-test/deep"
)

type parserTestCase struct {
	name     string
	expected Tables
}

func (c parserTestCase) run() ([]string, error) {
	f, err := os.Open(c.name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	result, err := ParseIptablesSave(f)
	if err != nil {
		return nil, err
	}
	return deep.Equal(c.expected, result), nil
}

var parserTestCases = []parserTestCase{
	{
		name: "server.iptables-save",
		expected: Tables{
			"filter": {
				"INPUT": {
					Policy:  "ACCEPT",
					Packets: 8202915326,
					Bytes:   443356185985,
					Rules: []Rule{
						{
							Packets: 7981319024,
							Bytes:   1536987862973,
							Rule:    "-p tcp -m tcp --dport 7000 -j ACCEPT",
						},
						{
							Packets: 1335166082,
							Bytes:   279365222746,
							Rule:    "-p tcp -m tcp --dport 9160 -j ACCEPT",
						},
						{
							Packets: 27438740,
							Bytes:   6089401408,
							Rule:    "-p tcp -m tcp --dport 7199 -j ACCEPT",
						},
						{
							Packets: 1285509559,
							Bytes:   346897300390,
							Rule:    "-p tcp -m tcp --dport 9042 -j ACCEPT",
						},
					},
				},
				"FORWARD": {
					Policy: "ACCEPT",
				},
				"OUTPUT": {
					Policy:  "ACCEPT",
					Packets: 8189941891,
					Bytes:   1885661899958,
					Rules: []Rule{
						{
							Packets: 7903596488,
							Bytes:   341918393697,
							Rule:    "-p tcp -m tcp --sport 7000 -j ACCEPT",
						},
						{
							Packets: 973128122,
							Bytes:   70345269557,
							Rule:    "-p tcp -m tcp --sport 9160 -j ACCEPT",
						},
						{
							Packets: 26463368,
							Bytes:   3097440049,
							Rule:    "-p tcp -m tcp --sport 7199 -j ACCEPT",
						},
						{
							Packets: 813815825,
							Bytes:   429136005552,
							Rule:    "-p tcp -m tcp --sport 9042 -j ACCEPT",
						},
					},
				},
			},
			"mangle": {
				"PREROUTING": {
					Policy:  "ACCEPT",
					Packets: 18832348733,
					Bytes:   2612695974158,
				},
				"INPUT": {
					Policy:  "ACCEPT",
					Packets: 18832348731,
					Bytes:   2612695973502,
				},
				"FORWARD": {
					Policy: "ACCEPT",
				},
				"OUTPUT": {
					Policy:  "ACCEPT",
					Packets: 17906945694,
					Bytes:   2730159008813,
				},
				"POSTROUTING": {
					Policy:  "ACCEPT",
					Packets: 17906945694,
					Bytes:   2730159008813,
				},
			},
		},
	},
	{
		name: "router.iptables-save",
		expected: Tables{
			"mangle": {
				"PREROUTING": {
					Packets: 1272180553,
					Bytes:   130550152431,
					Policy:  "ACCEPT",
				},
				"INPUT": {
					Packets: 1271409426,
					Bytes:   130462825907,
					Policy:  "ACCEPT",
				},
				"FORWARD": {
					Packets: 523179,
					Bytes:   34974614,
					Policy:  "ACCEPT",
				},
				"OUTPUT": {
					Packets: 1108541965,
					Bytes:   107984977885,
					Policy:  "ACCEPT",
				},
				"POSTROUTING": {
					Packets: 1109064944,
					Bytes:   108019914043,
					Policy:  "ACCEPT",
				},
			},
			"nat": {
				"PREROUTING": {
					Policy:  "ACCEPT",
					Packets: 240804686,
					Bytes:   11146768693,
				},
				"INPUT": {
					Policy:  "ACCEPT",
					Packets: 240306627,
					Bytes:   11072470495,
				},
				"OUTPUT": {
					Policy:  "ACCEPT",
					Packets: 1796395,
					Bytes:   128538425,
				},
				"POSTROUTING": {
					Policy:  "ACCEPT",
					Packets: 1986134,
					Bytes:   143755614,
				},
			},
			"filter": {
				"INPUT": {
					Policy:  "ACCEPT",
					Packets: 1254093501,
					Bytes:   128176385346,
					Rules: []Rule{
						{
							Packets: 12,
							Bytes:   720,
							Rule:    "-s 10.10.10.0/24 -d 10.10.10.1/32 -p icmp -j ACCEPT",
						},
						{
							Packets: 17256030,
							Bytes:   2279773210,
							Rule:    "-s 10.10.10.0/24 -d 10.10.10.1/32 -p tcp -m tcp --dport 80 -j ACCEPT",
						},
						{
							Packets: 60372,
							Bytes:   6729099,
							Rule:    "-s 10.10.10.0/24 -j DROP",
						},
					},
				},
				"FORWARD": {
					Policy:  "ACCEPT",
					Packets: 523179,
					Bytes:   34974614,
				},
				"OUTPUT": {
					Policy:  "ACCEPT",
					Packets: 1108542302,
					Bytes:   107984977359,
				},
			},
		},
	},
}

func TestParseIptablesSave(t *testing.T) {
	for _, tc := range parserTestCases {
		mismatch, err := tc.run()
		if err != nil {
			t.Fatalf("%s: %+v", tc.name, err)
		}
		if mismatch != nil {
			t.Fatalf("%s: %+v", tc.name, mismatch)
		}
	}
}
