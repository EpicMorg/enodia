// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration parses YAML string durations like "10s" or "500ms", giving a
// clear error instead of the default yaml behaviour of requiring an integer
// number of nanoseconds.
type Duration time.Duration

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return fmt.Errorf("duration must be a string like \"10s\": %w", err)
	}
	if s == "" {
		*d = 0
		return nil
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}

func (d Duration) String() string { return time.Duration(d).String() }
