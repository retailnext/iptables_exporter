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
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

func ParseIptablesSave(r io.Reader) (Tables, error) {
	scanner := bufio.NewScanner(r)
	var parser parser
	for scanner.Scan() {
		parser.handleLine(scanner.Text())
	}
	parser.flush()
	err := scanner.Err()
	if err != nil {
		return nil, err
	}
	if len(parser.errors) > 0 {
		return nil, parser.errors[0]
	}
	return parser.result, nil
}

type ParseError struct {
	Message    string
	LineNumber int
	LineText   string
}

func (e ParseError) Error() string {
	return fmt.Sprintf("%s at line %d: %+v", e.Message, e.LineNumber, e.LineText)
}

type parser struct {
	result           Tables
	currentTableName string
	currentTable     Table
	line             int
	errors           []error
}

func (p *parser) flush() {
	if p.currentTableName != "" {
		if p.result == nil {
			p.result = make(Tables)
		}
		p.result[p.currentTableName] = p.currentTable
		p.currentTableName = ""
		p.currentTable = nil
	}
}

func (p *parser) handleNewChain(line string) {
	fields := strings.Fields(line)
	if len(fields) != 3 {
		p.errors = append(p.errors, ParseError{"expected 3 fields", p.line, line})
		return
	}
	name := strings.TrimPrefix(fields[0], ":")
	packets, bytes, ok := parseCounters(fields[2])
	if !ok {
		p.errors = append(p.errors, ParseError{"expected [packets:bytes]", p.line, line})
		return
	}
	if p.currentTable == nil {
		p.currentTable = make(map[string]Chain)
	}
	chain := Chain{
		Policy:  fields[1],
		Packets: packets,
		Bytes:   bytes,
	}
	p.currentTable[name] = chain
}

func (p *parser) handleRule(line string) {
	fields := strings.Fields(line)
	var subParser ruleParser
	for _, token := range fields {
		subParser.handleToken(token)
	}
	subParser.flush()
	if !subParser.countersOk {
		p.errors = append(p.errors, ParseError{"expected [packets:bytes]", p.line, line})
		return
	}
	if subParser.chain == "" {
		p.errors = append(p.errors, ParseError{"expected -A chain ...", p.line, line})
		return
	}
	r := Rule{
		Packets: subParser.packets,
		Bytes:   subParser.bytes,
		Rule:    strings.Join(subParser.flags, " "),
	}
	chain := p.currentTable[subParser.chain]
	chain.Rules = append(chain.Rules, r)
	p.currentTable[subParser.chain] = chain
}

func (p *parser) handleLine(line string) {
	p.line++
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return
	}
	if line == "COMMIT" {
		p.flush()
		return
	}
	if name := strings.TrimPrefix(line, "*"); name != line {
		p.flush()
		p.currentTableName = name
		return
	}
	if strings.HasPrefix(line, ":") {
		p.handleNewChain(line)
		return
	}
	if strings.HasPrefix(line, "[") {
		p.handleRule(line)
		return
	}
	p.errors = append(p.errors, ParseError{"unhandled line", p.line, line})
}

var countersRegexp = regexp.MustCompile(`^\[(\d+):(\d+)]$`)

func parseCounters(field string) (packets, bytes uint64, ok bool) {
	parts := countersRegexp.FindStringSubmatch(field)
	if len(parts) != 3 {
		return
	}
	var packetsErr, bytesErr error
	packets, packetsErr = strconv.ParseUint(parts[1], 10, 64)
	bytes, bytesErr = strconv.ParseUint(parts[2], 10, 64)
	ok = packetsErr == nil && bytesErr == nil
	return
}
