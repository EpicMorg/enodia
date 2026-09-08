// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import "errors"

// ExitError carries the process exit code a command wants, so "the tool
// crashed" (1), "you asked for something the tool can't do" (2) and "the
// tool worked but found a problem" (3+, see docs/ROADMAP.md) never collapse
// into the same code the way a bare returned error would.
type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string {
	if e.Err == nil {
		return ""
	}
	return e.Err.Error()
}

func (e *ExitError) Unwrap() error { return e.Err }

// exitCode maps whatever rootCmd.Execute() returned onto a process exit
// code. A plain error (not *ExitError) only ever comes from cobra itself —
// an unknown command or a bad flag — which is a bad-arguments situation.
func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *ExitError
	if errors.As(err, &ee) {
		return ee.Code
	}
	return 2
}
