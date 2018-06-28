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

import "os/exec"

func GetTables() (Tables, error) {
	cmd := exec.Command("iptables-save", "-c")
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	resultCh := make(chan struct {
		Tables
		error
	})
	go func() {
		result, parseErr := ParseIptablesSave(pipe)
		resultCh <- struct {
			Tables
			error
		}{result, parseErr}
	}()

	err = cmd.Start()
	if err != nil {
		return nil, err
	}

	r := <-resultCh
	err = cmd.Wait()
	if err != nil {
		return nil, err
	}

	return r.Tables, r.error
}
