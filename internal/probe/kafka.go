// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"time"
)

// kafkaVersionCommand finds the broker's version on its host without
// starting a JVM: the kafka_<scala>-<version>.jar every distribution ships
// in its libs directory (Apache's image: /opt/kafka/libs/kafka_2.13-4.3.1.jar;
// Confluent's cp-kafka: /usr/share/java/kafka/kafka_2.13-8.3.2-ccs.jar),
// looked for under $KAFKA_HOME and the usual install paths. kafka-topics
// --version (a JVM start, a few seconds) runs only when no jar is found,
// for an install elsewhere on PATH. `|| true` keeps a host without Kafka
// from failing the command; that is reported from the missing version
// instead.
const kafkaVersionCommand = `j=$(for d in "$KAFKA_HOME" /opt/kafka /opt/bitnami/kafka /usr/local/kafka /usr/share/java/kafka; do [ -n "$d" ] && ls "$d"/libs/kafka_2.*.jar "$d"/kafka_2.*.jar 2>/dev/null; done); if [ -n "$j" ]; then echo "$j"; else kafka-topics.sh --version 2>/dev/null || kafka-topics --version 2>/dev/null || true; fi`

var (
	kafkaJarPattern     = regexp.MustCompile(`kafka_2\.\d+-(\d+\.\d+\.\d+(?:-[A-Za-z0-9]+)?)\.jar`)
	kafkaVersionLine    = regexp.MustCompile(`(?m)^(\d+\.\d+\.\d+(?:-[A-Za-z0-9]+)?)(?:\s|$)`)
	kafkaConfluentBuild = regexp.MustCompile(`^(\d+)\.(\d+)\.\d+-(?:ccs|ce)$`)
)

// kafkaProbe reads a Kafka broker's version over SSH (optionally inside a
// container, options.container), like minio (D56).
//
// Not over the network: the Kafka protocol's only anonymous exchange,
// ApiVersions, lists API version ranges and no software version (D21), and
// JMX's kafka.server:type=app-info MBean is Java RMI with Java
// serialization — a JVM's protocol, not something to reimplement for one
// string. Over SSH the broker's own jar names it.
//
// Confluent Platform builds ("8.3.2-ccs") number themselves on Confluent's
// line: since 7.0, x.y ships Apache Kafka (x-4).y (7.6 → 3.6, 8.3 → 4.3;
// before 7.0 it didn't hold — 6.0 was 2.6), but its patch numbers are its
// own, and endoflife.date has no Confluent calendar. Such a
// build is reported as is, edition "confluent", with the Apache Kafka line
// it carries in extra.
type kafkaProbe struct{}

func (kafkaProbe) Meta() Meta {
	return Meta{
		Product:         "kafka",
		Aliases:         []string{"apache-kafka"},
		Summary:         "Apache Kafka broker (over SSH)",
		Auth:            AuthSpec{Required: true, Kinds: []AuthKind{AuthPassword, AuthSSHKey}},
		DefaultResolver: ResolverRef{Type: "endoflife", ID: "apache-kafka"},
	}
}

func (kafkaProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product, CollectedAt: start.UTC()}

	cmd, err := containerCommand(t, kafkaVersionCommand)
	if err != nil {
		return obs, err
	}
	out, verified, err := sshRunCommand(ctx, t, cmd)
	if err != nil {
		if isSSHExitError(err) {
			return obs, fmt.Errorf("%w: %w", ErrNotSupported, err)
		}
		return obs, err
	}
	if err := parseKafkaVersion(out, &obs); err != nil {
		return obs, err
	}
	obs.Extra["hostKeyVerified"] = strconv.FormatBool(verified)
	if c := t.Options[containerOption]; c != "" {
		obs.Extra["container"] = c
	}
	obs.DurationMS = time.Since(start).Milliseconds()
	return obs, nil
}

func parseKafkaVersion(out string, obs *Observation) error {
	obs.Extra = map[string]string{}
	if m := kafkaJarPattern.FindStringSubmatch(out); m != nil {
		obs.Version = m[1]
		obs.Endpoint = "kafka_*.jar"
	} else if m := kafkaVersionLine.FindStringSubmatch(out); m != nil {
		obs.Version = m[1]
		obs.Endpoint = "kafka-topics --version"
	} else {
		return fmt.Errorf("%w: no Kafka jar or version found (not installed in the usual paths, or in a container — see options.%s)", ErrNotSupported, containerOption)
	}
	if m := kafkaConfluentBuild.FindStringSubmatch(obs.Version); m != nil {
		obs.Edition = "confluent"
		if major, err := strconv.Atoi(m[1]); err == nil && major >= 7 {
			obs.Extra["apacheKafka"] = strconv.Itoa(major-4) + "." + m[2]
		}
	}
	return nil
}
