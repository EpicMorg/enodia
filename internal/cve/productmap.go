// SPDX-License-Identifier: AGPL-3.0-or-later

package cve

// Both tables below are keyed by CVE product — usually the enodia probe's
// own product id, except where one probe covers several independently
// versioned implementations (ssh -> openssh or dropbear, see Subject).
//
// Every pair was verified to exist verbatim in the real exports (NVD's
// 2002-2026 yearly files and BDU's full vulxml.zip) before being added
// here — a typo in a vendor or product string doesn't error, it just
// silently matches nothing. What was deliberately left out, and why, is
// in docs/DECISIONS.md D33: general-purpose Linux distributions (their
// CVEs are package-level; a release number can't say which packages are
// patched), the BSDs and Solaris (base-system CVEs, but keyed on patch
// levels in the CPE "update" field this package doesn't read), ESXi and
// vCenter (same "update" field problem), Synology DSM (build-suffixed
// bounds like "6.2.4-25556-3" the strict bound parser rejects), and every
// probe with no real entries in either source at all.

// bduName is one BDU <soft> (vendor, name) pair. Matching on the vendor
// too, not the name alone, is what keeps e.g. Oracle's own "HTTP Server"
// (its own 12.2.1.x numbering) out of Apache httpd's findings — the same
// name appears under both vendors in the real export.
type bduName struct{ vendor, name string }

// cpeName is one NVD CPE 2.3 (vendor, product) pair — the 4th and 5th
// colon-separated fields of a cpeMatch `criteria` string. Built from
// real CVE configurations, not the separate CPE dictionary API, which
// disagrees with them (see docs/DECISIONS.md D31).
type cpeName struct{ vendor, product string }

var productSoftNames = map[string][]bduName{
	"apache":        {{"Apache Software Foundation", "HTTP Server"}},
	"artifactory":   {{"JFrog", "JFrog Artifactory"}},
	"bamboo":        {{"Atlassian", "Bamboo"}, {"Atlassian", "Bamboo Data Center and Server"}},
	"bitbucket":     {{"Atlassian", "Bitbucket Data Center"}, {"Atlassian", "Bitbucket Server and Data Center"}, {"Atlassian", "Bitbucket Server"}},
	"clickhouse":    {{"ClickHouse, Inc.", "ClickHouse"}},
	"confluence":    {{"Atlassian", "Confluence Server"}},
	"dropbear":      {{"Matt Johnston", "Dropbear SSH"}},
	"elasticsearch": {{"Elastic NV", "Elasticsearch"}},
	"forgejo":       {{"Forgejo", "Forgejo"}},
	"fortios":       {{"Fortinet Inc.", "FortiOS"}},
	"gitlab":        {{"GitLab Inc.", "Gitlab"}},
	"grafana":       {{"Grafana Labs", "Grafana"}},
	"graylog":       {{"Graylog, Inc", "Graylog"}},
	"haproxy":       {{"Willy Terreau", "HAProxy"}},
	"harbor":        {{"Project Harbor", "harbor"}},
	"jenkins":       {{"CD Foundation", "Jenkins"}},
	"jira":          {{"Atlassian", "Jira"}, {"Atlassian", "Jira Server"}, {"Atlassian", "Jira Data Center"}, {"Atlassian", "Jira Software Data Center and Server"}, {"Atlassian", "Jira Software Server"}},
	"keycloak":      {{"Red Hat, Inc.", "Keycloak"}, {"Сообщество свободного программного обеспечения", "Keycloak"}},
	"kibana":        {{"Elastic NV", "Kibana"}},
	"logstash":      {{"Elastic NV", "Logstash"}},
	"macos":         {{"Apple Inc.", "MacOS"}},
	"mattermost":    {{"Mattermost Inc", "Mattermost"}},
	"mongodb":       {{"MongoDB Inc.", "MongoDB"}, {"MongoDB Inc.", "MongoDB Server"}, {"MongoDB Inc.", "MongoDB Enterprise Server"}},
	"mysql":         {{"Oracle Corp.", "MySQL"}, {"Oracle Corp.", "MySQL Server"}},
	"nextcloud":     {{"Nextcloud GmbH", "Nextcloud Server"}, {"Nextcloud GmbH", "Nextcloud Enterprise Server"}},
	"nexus":         {{"Sonatype Inc.", "Nexus Repository Manager"}},
	"nginx":         {{"NGINX Inc.", "nginx"}, {"NGINX Inc.", "NGINX Open Source"}},
	"oauth2-proxy":  {{"Сообщество свободного программного обеспечения", "OAuth2-Proxy"}},
	"openssh":       {{"The OpenBSD Project", "OpenSSH"}, {"The OpenBSD Project", "OpenSSH Server"}},
	"opensearch":    {{"Amazon", "OpenSearch"}, {"Сообщество свободного программного обеспечения", "opensearch"}},
	"opnsense":      {{"Сообщество свободного программного обеспечения", "OPNsense"}},
	"p4d":           {{"Perforce Software, Inc.", "Helix Core"}},
	"pgadmin":       {{"PostgreSQL Community Association of Canada", "pgAdmin 4"}},
	"phpmyadmin":    {{"phpMyAdmin Developer Team", "phpMyAdmin"}},
	"portainer":     {{"Сообщество свободного программного обеспечения", "Portainer"}, {"Сообщество свободного программного обеспечения", "Portainer CE"}},
	"postgresql":    {{"PostgreSQL Global Development Group", "PostgreSQL"}},
	"proftpd":       {{"The ProFTPD Project", "ProFTPD"}},
	"proxmox":       {{"Proxmox Server Solutions GmbH", "Proxmox VE"}},
	"redis":         {{"Redis Labs", "Redis"}},
	"routeros":      {{"MikroTik", "RouterOS"}},
	"sonarqube":     {{"SonarSource", "SonarQube"}},
	"teamcity":      {{"JetBrains", "TeamCity"}},
	"traefik":       {{"Containous", "Traefik"}},
	"vault":         {{"HashiCorp", "Vault"}, {"HashiCorp", "Vault Enterprise"}, {"HashiCorp", "Vault Community Edition"}},
	"vaultwarden":   {{"Elest.io", "Vaultwarden"}},
	"wordpress":     {{"WordPress Foundation", "WordPress"}},
	"youtrack":      {{"JetBrains", "YouTrack"}},
	"zabbix":        {{"Zabbix LLC.", "Zabbix"}, {"Zabbix LLC.", "Zabbix Frontend"}},
}

var productCPENames = map[string][]cpeName{
	"apache":        {{"apache", "http_server"}},
	"artifactory":   {{"jfrog", "artifactory"}},
	"bamboo":        {{"atlassian", "bamboo"}, {"atlassian", "bamboo_data_center"}, {"atlassian", "bamboo_server"}},
	"bitbucket":     {{"atlassian", "bitbucket"}, {"atlassian", "bitbucket_data_center"}, {"atlassian", "bitbucket_server"}},
	"bitwarden":     {{"bitwarden", "server"}},
	"clickhouse":    {{"clickhouse", "clickhouse"}},
	"confluence":    {{"atlassian", "confluence"}, {"atlassian", "confluence_server"}, {"atlassian", "confluence_data_center"}},
	"dropbear":      {{"dropbear_ssh_project", "dropbear_ssh"}},
	"elasticsearch": {{"elastic", "elasticsearch"}},
	"forgejo":       {{"forgejo", "forgejo"}},
	"fortios":       {{"fortinet", "fortios"}},
	"gitlab":        {{"gitlab", "gitlab"}},
	"grafana":       {{"grafana", "grafana"}},
	"graylog":       {{"graylog", "graylog"}, {"torch_gmbh", "graylog2"}},
	"haproxy":       {{"haproxy", "haproxy"}},
	"harbor":        {{"linuxfoundation", "harbor"}},
	"jaeger":        {{"linuxfoundation", "jaeger"}},
	"jellyfin":      {{"jellyfin", "jellyfin"}},
	"jenkins":       {{"jenkins", "jenkins"}},
	"jira":          {{"atlassian", "jira"}, {"atlassian", "jira_core"}, {"atlassian", "jira_server"}, {"atlassian", "jira_data_center"}, {"atlassian", "jira_software_data_center"}, {"atlassian", "jira_server_and_data_center"}},
	"keycloak":      {{"keycloak", "keycloak"}, {"redhat", "keycloak"}},
	"kibana":        {{"elastic", "kibana"}},
	"logstash":      {{"elastic", "logstash"}},
	"macos":         {{"apple", "macos"}, {"apple", "mac_os_x"}},
	"mattermost":    {{"mattermost", "mattermost_server"}, {"mattermost", "mattermost"}},
	"mongodb":       {{"mongodb", "mongodb"}},
	"mysql":         {{"oracle", "mysql"}, {"mysql", "mysql"}},
	"nextcloud":     {{"nextcloud", "nextcloud_server"}},
	"nexus":         {{"sonatype", "nexus_repository_manager"}, {"sonatype", "nexus"}},
	"nginx":         {{"f5", "nginx"}, {"f5", "nginx_open_source"}, {"nginx", "nginx"}},
	"oauth2-proxy":  {{"oauth2_proxy_project", "oauth2_proxy"}},
	"openssh":       {{"openbsd", "openssh"}},
	"opensearch":    {{"amazon", "opensearch"}},
	"opnsense":      {{"opnsense", "opnsense"}},
	"owncast":       {{"owncast_project", "owncast"}},
	"p4d":           {{"perforce", "helix_core"}, {"perforce", "perforce_server"}},
	"pgadmin":       {{"pgadmin", "pgadmin_4"}},
	"phpmyadmin":    {{"phpmyadmin", "phpmyadmin"}},
	"portainer":     {{"portainer", "portainer"}},
	"postgresql":    {{"postgresql", "postgresql"}},
	"proftpd":       {{"proftpd", "proftpd"}},
	"proxmox":       {{"proxmox", "virtual_environment"}},
	"redis":         {{"redis", "redis"}, {"redislabs", "redis"}},
	"routeros":      {{"mikrotik", "routeros"}},
	"sonarqube":     {{"sonarsource", "sonarqube"}},
	"teamcity":      {{"jetbrains", "teamcity"}},
	"testrail":      {{"gurock", "testrail"}},
	"traefik":       {{"traefik", "traefik"}},
	"vault":         {{"hashicorp", "vault"}},
	"vaultwarden":   {{"dani-garcia", "vaultwarden"}},
	"wordpress":     {{"wordpress", "wordpress"}},
	"youtrack":      {{"jetbrains", "youtrack"}},
	"zabbix":        {{"zabbix", "zabbix"}},
}
