// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

// zookeeperProbe sends the "srvr" four-letter word over the client port
// and reads the reply until the server closes the connection: "Zookeeper
// version: 3.9.6-<git hash>, built on 2026-09-03 19:29 UTC", then
// latency/connection counters and "Mode: standalone" (confirmed live
// against zookeeper:3.9, see testdata/zookeeper_3.9.6_srvr.bin). srvr is
// the one four-letter word ZooKeeper 3.5+ allows by default
// (4lw.commands.whitelist); stat, mntr, ruok and the rest answered "is not
// executed because it is not in the whitelist". No authentication exists
// for four-letter words.
type zookeeperProbe struct{}

func (zookeeperProbe) Meta() Meta {
	return Meta{
		Product:         "zookeeper",
		Summary:         "Apache ZooKeeper",
		Auth:            AuthSpec{Required: false},
		DefaultResolver: ResolverRef{Type: "endoflife", ID: "zookeeper"},
	}
}

const (
	zookeeperDefaultPort = "2181"
	zookeeperMaxReply    = 64 << 10
)

var (
	zookeeperVersionPattern = regexp.MustCompile(`(?m)^Zookeeper version: (\d+(?:\.\d+)+)(?:-([0-9a-f]+))?`)
	zookeeperModePattern    = regexp.MustCompile(`(?m)^Mode: (\S+)`)
)

func (zookeeperProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product, CollectedAt: start.UTC()}

	addr := defaultPort(t.Address, zookeeperDefaultPort)
	conn, cleanup, err := dialTCP(ctx, addr, t.Timeout)
	if err != nil {
		return obs, err
	}
	defer cleanup()

	if _, err := conn.Write([]byte("srvr")); err != nil {
		return obs, tcpErr(ctx, fmt.Errorf("%w: sending srvr: %w", ErrUnreachable, err))
	}
	// The server closes right after replying; a reset after a full reply
	// is that close, not a failure.
	reply, err := io.ReadAll(io.LimitReader(conn, zookeeperMaxReply))
	if err != nil && len(reply) == 0 {
		return obs, tcpErr(ctx, fmt.Errorf("%w: reading srvr reply: %w", ErrUnreachable, err))
	}
	if err := parseZookeeperSrvr(string(reply), &obs); err != nil {
		return obs, err
	}
	obs.Endpoint = addr
	obs.DurationMS = time.Since(start).Milliseconds()
	return obs, nil
}

func parseZookeeperSrvr(reply string, obs *Observation) error {
	if strings.Contains(reply, "is not executed because it is not in the whitelist") {
		return fmt.Errorf("%w: srvr is not in this server's 4lw.commands.whitelist", ErrNotSupported)
	}
	m := zookeeperVersionPattern.FindStringSubmatch(reply)
	if m == nil {
		return fmt.Errorf("%w: no \"Zookeeper version:\" line in the srvr reply", ErrUnparseable)
	}
	obs.Version = m[1]
	obs.Extra = map[string]string{}
	if m[2] != "" {
		obs.Extra["git"] = m[2]
	}
	if mm := zookeeperModePattern.FindStringSubmatch(reply); mm != nil {
		obs.Extra["mode"] = mm[1]
	}
	return nil
}
