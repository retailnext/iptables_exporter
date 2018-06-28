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

import "strings"

type ruleParser struct {
	packets       uint64
	bytes         uint64
	countersOk    bool
	current       string
	currentValues []string
	chain         string
	flags         []string
}

func (p *ruleParser) flush() {
	switch p.current {
	case "":
		// Ignore
	case "-A", "--append":
		if len(p.currentValues) > 0 {
			p.chain = p.currentValues[0]
		}
	default:
		p.flags = append(p.flags, p.current)
		p.flags = append(p.flags, p.currentValues...)
	}
	p.current = ""
	p.currentValues = nil
}

func (p *ruleParser) handleToken(token string) {
	if strings.HasPrefix(token, "[") {
		p.packets, p.bytes, p.countersOk = parseCounters(token)
		return
	}
	if strings.HasPrefix(token, "-") {
		p.flush()
		p.current = token
		return
	}
	p.currentValues = append(p.currentValues, token)
}
