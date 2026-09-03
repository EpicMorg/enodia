// SPDX-License-Identifier: AGPL-3.0-or-later

package render

import (
	"encoding/json"
	"io"
)

// JSON writes the full report — observations and assessments both, per D7
// kept as separate fields rather than merged — as indented JSON.
func JSON(w io.Writer, r Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
