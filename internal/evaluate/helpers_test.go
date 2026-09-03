// SPDX-License-Identifier: AGPL-3.0-or-later

package evaluate

import (
	"time"

	"github.com/EpicMorg/enodia/internal/resolver"
)

func day(s string) time.Time {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		panic(err)
	}
	return t
}

func dateFlag(s string) *resolver.Flag {
	return &resolver.Flag{Bool: true, IsDate: true, Date: day(s)}
}

func boolFlag(b bool) *resolver.Flag {
	return &resolver.Flag{Bool: b}
}
