// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"errors"
	"testing"
	"time"
)

func kafkaTarget(addr, fp string, options map[string]string) Target {
	return Target{
		ID: "x", Product: "kafka", Address: addr,
		Creds:   Credentials{Username: "probeuser", Password: "probepass"},
		TLS:     TLSSettings{PinSHA256: []string{fp}},
		Timeout: 2 * time.Second,
		Options: options,
	}
}

// The command's real output inside apache/kafka:latest (4.3.1) and
// confluentinc/cp-kafka:latest (8.3.2-ccs).
func TestKafkaProbe(t *testing.T) {
	for _, tc := range []struct {
		fixture, version, edition, apache string
		options                           map[string]string
		cmd                               string
	}{
		{"kafka_apache_4.3.1_out.txt", "4.3.1", "", "", map[string]string{"container": "kafka"}, "docker exec kafka sh -c '" + kafkaVersionCommand + "'"},
		{"kafka_confluent_8.3.2_out.txt", "8.3.2-ccs", "confluent", "4.3", nil, kafkaVersionCommand},
	} {
		addr, fp := sshTestServer(t, "probeuser", "probepass", nil, map[string]string{tc.cmd: string(readFixture(t, tc.fixture))})
		obs, err := kafkaProbe{}.Probe(context.Background(), kafkaTarget(addr, fp, tc.options))
		if err != nil {
			t.Fatalf("%s: Probe: %v", tc.fixture, err)
		}
		if obs.Version != tc.version || obs.Edition != tc.edition || obs.Extra["apacheKafka"] != tc.apache {
			t.Fatalf("%s: got %q %q %+v", tc.fixture, obs.Version, obs.Edition, obs.Extra)
		}
	}
}

func TestParseKafkaVersionFallbacks(t *testing.T) {
	var obs Observation
	if err := parseKafkaVersion("[2026-10-09 00:56:57,176] INFO Registered MBean\n3.9.1\n", &obs); err != nil || obs.Version != "3.9.1" {
		t.Fatalf("--version output: got %q, %v", obs.Version, err)
	}
	obs = Observation{}
	if err := parseKafkaVersion("6.2.1-ccs\n", &obs); err != nil || obs.Edition != "confluent" || obs.Extra["apacheKafka"] != "" {
		t.Fatalf("pre-7.0 Confluent: got %q %q %+v, %v", obs.Version, obs.Edition, obs.Extra, err)
	}
	if err := parseKafkaVersion("sh: kafka-topics: not found\n", &Observation{}); !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}
