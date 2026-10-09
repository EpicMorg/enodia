// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/EpicMorg/enodia/internal/config"
	"github.com/EpicMorg/enodia/internal/cveupdate"
	"github.com/EpicMorg/enodia/internal/inventory"
)

var (
	cveUpdateFromFlag       []string
	cveUpdateOVALFlag       []string
	cveUpdateAlpineFlag     []string
	cveUpdatePostgreSQLFlag []string
	cveUpdateAllYearsFlag   bool
	cveUpdateDryRunFlag     bool
)

var cveCmd = &cobra.Command{
	Use:   "cve",
	Short: "Manage the local CVE databases",
}

var cveUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Download the CVE databases the config's cve.*.path entries name",
	Long: `update downloads into each configured cve.*.path what that entry reads:
BDU's vulxml.zip, NVD's yearly files (this year, last year and any year
not on disk yet; every year with --all-years), the Debian Security Tracker
JSON, vendor OVAL files, Alpine secdb, and MariaDB's, Atlassian's,
PostgreSQL's and nginx's own data. It is the only command that fetches
them; check, collect and serve never do.

OVAL releases, Alpine branches and PostgreSQL majors come from the files
already in those directories, from the inventories given with --from, and
from --oval/--alpine/--postgresql.

Each file is sent If-Modified-Since its copy on disk, downloaded beside it,
loaded by the same code the CVE lookup uses, and only then moved over the
old one, so a failed or broken download never replaces a working file.
TLS is verified against the system's roots plus cve.update.ca_file and
cve.update.ca_dir; cve.update.tls_skip_verify turns verification off.
Exit status 1 if any file failed; the rest are still updated.`,
	Args: cobra.NoArgs,
	RunE: runCVEUpdateCmd,
}

func init() {
	cveUpdateCmd.Flags().StringArrayVar(&cveUpdateFromFlag, "from", nil, "an inventory to read OVAL releases, Alpine branches and PostgreSQL majors from (repeatable)")
	cveUpdateCmd.Flags().StringArrayVar(&cveUpdateOVALFlag, "oval", nil, "an OVAL release to fetch: ubuntu:<codename>, rhel:<N>, almalinux:<N>, oracle-linux:<N>, astra-linux:<X.Y>, redos:<X.Y> (repeatable)")
	cveUpdateCmd.Flags().StringArrayVar(&cveUpdateAlpineFlag, "alpine", nil, "an Alpine branch to fetch secdb for, e.g. v3.22 (repeatable)")
	cveUpdateCmd.Flags().StringArrayVar(&cveUpdatePostgreSQLFlag, "postgresql", nil, "a PostgreSQL major whose own security page to fetch, e.g. 13 (repeatable)")
	cveUpdateCmd.Flags().BoolVar(&cveUpdateAllYearsFlag, "all-years", false, "refresh every NVD year, not only this one, last one and missing ones")
	cveUpdateCmd.Flags().BoolVar(&cveUpdateDryRunFlag, "dry-run", false, "list what would be fetched, download nothing")
	cveCmd.AddCommand(cveUpdateCmd)
	rootCmd.AddCommand(cveCmd)
}

func runCVEUpdateCmd(cmd *cobra.Command, _ []string) error {
	path, err := config.Locate(configFlag)
	if err != nil {
		return &ExitError{Code: 1, Err: err}
	}
	cfg, err := config.Load(path)
	if err != nil {
		return &ExitError{Code: 1, Err: err}
	}

	var paths cveupdate.Paths
	for _, p := range []struct {
		dst     *string
		resolve func() (string, bool)
	}{
		{&paths.BDU, cfg.BDUPath}, {&paths.NVD, cfg.NVDPath}, {&paths.Debian, cfg.DebianPath},
		{&paths.OVAL, cfg.OVALPath}, {&paths.Alpine, cfg.AlpinePath}, {&paths.MariaDB, cfg.MariaDBPath},
		{&paths.Atlassian, cfg.AtlassianPath}, {&paths.PostgreSQL, cfg.PostgreSQLPath}, {&paths.Nginx, cfg.NginxPath},
	} {
		*p.dst, _ = p.resolve()
	}
	if paths == (cveupdate.Paths{}) {
		return &ExitError{Code: 2, Err: fmt.Errorf("%s: no cve.*.path is set, nothing to update", path)}
	}

	wants := cveupdate.Wants{OVAL: cveUpdateOVALFlag, Alpine: cveUpdateAlpineFlag, PostgreSQL: cveUpdatePostgreSQLFlag}
	for _, from := range cveUpdateFromFlag {
		f, err := os.Open(from)
		if err != nil {
			return &ExitError{Code: 1, Err: err}
		}
		inv, err := inventory.Read(f)
		f.Close()
		if err != nil {
			return &ExitError{Code: 1, Err: fmt.Errorf("%s: %w", from, err)}
		}
		w := cveupdate.WantsFromInventory(inv.Observations)
		wants.OVAL = append(wants.OVAL, w.OVAL...)
		wants.Alpine = append(wants.Alpine, w.Alpine...)
		wants.PostgreSQL = append(wants.PostgreSQL, w.PostgreSQL...)
	}

	items, planErrs := cveupdate.Plan(paths, wants, time.Now(), cveUpdateAllYearsFlag)
	warn := warnPrinter(cmd)
	for _, e := range planErrs {
		warn(e.Error())
	}
	out := cmd.OutOrStdout()
	if cveUpdateDryRunFlag {
		for _, it := range items {
			fmt.Fprintf(out, "%-10s %s -> %s\n", it.Source, it.URL, it.Dest)
		}
		return nil
	}

	tlsOpts := cveupdate.TLSOptions{SkipVerify: cfg.CVE.Update.TLSSkipVerify}
	tlsOpts.CAFile, _ = cfg.UpdateCAFile()
	tlsOpts.CADir, _ = cfg.UpdateCADir()
	client, err := cveupdate.NewClient(tlsOpts, "enodia/"+buildVersion+" (+https://github.com/EpicMorg/enodia)")
	if err != nil {
		return &ExitError{Code: 1, Err: err}
	}

	failed := len(planErrs)
	for _, it := range items {
		r := client.Fetch(cmd.Context(), it)
		switch r.Status {
		case cveupdate.Failed:
			failed++
			fmt.Fprintf(out, "%-6s %-10s %s: %v\n", r.Status, it.Source, it.Dest, r.Err)
		default:
			fmt.Fprintf(out, "%-6s %-10s %s\n", r.Status, it.Source, it.Dest)
		}
	}
	if failed > 0 {
		return &ExitError{Code: 1, Err: fmt.Errorf("%d of %d download(s) failed", failed, len(items)+len(planErrs))}
	}
	return nil
}
