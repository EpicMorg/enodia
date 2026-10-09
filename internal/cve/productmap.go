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
// vCenter (same "update" field problem), and every probe with no real
// entries in either source at all. Synology DSM, left out there for its
// build-suffixed bounds ("6.2.4-25556-3"), is in since D72 (boundFolds);
// dell-idrac is one CVE product per iDRAC generation (idrac6 … idrac10,
// see Subject).

// bduName is one BDU <soft> (vendor, name) pair. Matching on the vendor
// too, not the name alone, is what keeps e.g. Oracle's own "HTTP Server"
// (its own 12.2.1.x numbering) out of Apache httpd's findings — the same
// name appears under both vendors in the real export. edition, when set,
// is carried into Finding.Edition: BDU has no sw_edition field, but it
// lists some editions as separate products ("Vault Enterprise"), which
// says the same thing.
type bduName struct{ vendor, name, edition string }

// cpeName is one NVD CPE 2.3 (vendor, product) pair — the 4th and 5th
// colon-separated fields of a cpeMatch `criteria` string. Built from
// real CVE configurations, not the separate CPE dictionary API, which
// disagrees with them (see docs/DECISIONS.md D31).
type cpeName struct{ vendor, product string }

var productSoftNames = map[string][]bduName{
	"apache":        {{"Apache Software Foundation", "HTTP Server", ""}},
	"artifactory":   {{"JFrog", "JFrog Artifactory", ""}},
	"bamboo":        {{"Atlassian", "Bamboo", ""}, {"Atlassian", "Bamboo Data Center and Server", ""}},
	"bitbucket":     {{"Atlassian", "Bitbucket Data Center", ""}, {"Atlassian", "Bitbucket Server and Data Center", ""}, {"Atlassian", "Bitbucket Server", ""}},
	"cassandra":     {{"Apache Software Foundation", "Cassandra", ""}},
	"clickhouse":    {{"ClickHouse, Inc.", "ClickHouse", ""}},
	"confluence":    {{"Atlassian", "Confluence Server", ""}},
	"dropbear":      {{"Matt Johnston", "Dropbear SSH", ""}},
	"elasticsearch": {{"Elastic NV", "Elasticsearch", ""}},
	"forgejo":       {{"Forgejo", "Forgejo", ""}},
	"fortios":       {{"Fortinet Inc.", "FortiOS", ""}},
	"freeradius":    {{"FreeRADIUS Development Team", "FreeRADIUS", ""}},
	"ghost":         {{"Ghost Foundation", "Ghost", ""}},
	"gitlab":        {{"GitLab Inc.", "Gitlab", ""}},
	"grafana":       {{"Grafana Labs", "Grafana", ""}},
	"graylog":       {{"Graylog, Inc", "Graylog", ""}},
	"haproxy":       {{"Willy Terreau", "HAProxy", ""}},
	"hp-ilo4":       {{"HP Inc.", "HP iLO 4", ""}},
	"harbor":        {{"Project Harbor", "harbor", ""}},
	"idrac10":       {{"Dell Technologies", "iDRAC10", ""}},
	"idrac7":        {{"Dell Technologies", "iDRAC7", ""}},
	"idrac8":        {{"Dell Technologies", "iDRAC8", ""}},
	"idrac9":        {{"Dell Technologies", "iDRAC9", ""}},
	"jenkins":       {{"CD Foundation", "Jenkins", ""}},
	"jira":          {{"Atlassian", "Jira", ""}, {"Atlassian", "Jira Server", ""}, {"Atlassian", "Jira Data Center", ""}, {"Atlassian", "Jira Software Data Center and Server", ""}, {"Atlassian", "Jira Software Server", ""}},
	"kafka":         {{"Apache Software Foundation", "Kafka", ""}},
	"keycloak":      {{"Red Hat, Inc.", "Keycloak", ""}, {"Сообщество свободного программного обеспечения", "Keycloak", ""}},
	"kibana":        {{"Elastic NV", "Kibana", ""}},
	"logstash":      {{"Elastic NV", "Logstash", ""}},
	"macos":         {{"Apple Inc.", "MacOS", ""}},
	"mariadb":       {{"MariaDB Foundation", "MariaDB", ""}},
	"mattermost":    {{"Mattermost Inc", "Mattermost", ""}},
	"memcached":     {{"Danga Interactive", "memcached", ""}},
	"minio":         {{"MinIO Inc", "MinIO", ""}},
	"mongodb":       {{"MongoDB Inc.", "MongoDB", ""}, {"MongoDB Inc.", "MongoDB Server", ""}, {"MongoDB Inc.", "MongoDB Enterprise Server", "enterprise"}},
	"mysql":         {{"Oracle Corp.", "MySQL", ""}, {"Oracle Corp.", "MySQL Server", ""}},
	"netdata":       {{"Netdata Inc.", "Netdata", ""}},
	"nextcloud":     {{"Nextcloud GmbH", "Nextcloud Server", ""}, {"Nextcloud GmbH", "Nextcloud Enterprise Server", "enterprise"}},
	"nexus":         {{"Sonatype Inc.", "Nexus Repository Manager", ""}},
	"nginx":         {{"NGINX Inc.", "nginx", ""}, {"NGINX Inc.", "NGINX Open Source", ""}},
	"oauth2-proxy":  {{"Сообщество свободного программного обеспечения", "OAuth2-Proxy", ""}},
	"onlyoffice":    {{"Ascensio System SIA", "ONLYOFFICE Docs", ""}},
	"opensearch":    {{"Amazon", "OpenSearch", ""}, {"Сообщество свободного программного обеспечения", "opensearch", ""}},
	"openssh":       {{"The OpenBSD Project", "OpenSSH", ""}, {"The OpenBSD Project", "OpenSSH Server", ""}},
	"opnsense":      {{"Сообщество свободного программного обеспечения", "OPNsense", ""}},
	"p4d":           {{"Perforce Software, Inc.", "Helix Core", ""}},
	"pfsense":       {{"Rubicon Communications, LLC (Netgate)", "pfSense", ""}},
	"pgadmin":       {{"PostgreSQL Community Association of Canada", "pgAdmin 4", ""}},
	"phpipam":       {{"Сообщество свободного программного обеспечения", "phpIPAM", ""}},
	"phpmyadmin":    {{"phpMyAdmin Developer Team", "phpMyAdmin", ""}},
	"portainer":     {{"Сообщество свободного программного обеспечения", "Portainer", ""}, {"Сообщество свободного программного обеспечения", "Portainer CE", ""}},
	"postgresql":    {{"PostgreSQL Global Development Group", "PostgreSQL", ""}},
	"proftpd":       {{"The ProFTPD Project", "ProFTPD", ""}},
	"proxmox":       {{"Proxmox Server Solutions GmbH", "Proxmox VE", ""}},
	"qbittorrent":   {{"Christophe Dumez", "qBittorrent", ""}},
	"rabbitmq":      {{"Broadcom Inc.", "RabbitMQ", ""}, {"Broadcom Inc.", "RabbitMQ Server", ""}},
	"redis":         {{"Redis Labs", "Redis", ""}},
	"routeros":      {{"MikroTik", "RouterOS", ""}},
	"sonarqube":     {{"SonarSource", "SonarQube", ""}},
	"splunk":        {{"Splunk Inc.", "Splunk Enterprise", ""}},
	"synology-dsm":  {{"Synology Inc.", "DiskStation Manager (DSM)", ""}},
	"teamcity":      {{"JetBrains", "TeamCity", ""}},
	"traefik":       {{"Containous", "Traefik", ""}},
	"vault":         {{"HashiCorp", "Vault", ""}, {"HashiCorp", "Vault Enterprise", "enterprise"}, {"HashiCorp", "Vault Community Edition", "community"}},
	"vaultwarden":   {{"Elest.io", "Vaultwarden", ""}},
	"wordpress":     {{"WordPress Foundation", "WordPress", ""}},
	"youtrack":      {{"JetBrains", "YouTrack", ""}},
	"zabbix":        {{"Zabbix LLC.", "Zabbix", ""}, {"Zabbix LLC.", "Zabbix Frontend", ""}},
	"zookeeper":     {{"Apache Software Foundation", "ZooKeeper", ""}},
}

var productCPENames = map[string][]cpeName{
	"apache":         {{"apache", "http_server"}},
	"artifactory":    {{"jfrog", "artifactory"}},
	"bamboo":         {{"atlassian", "bamboo"}, {"atlassian", "bamboo_data_center"}, {"atlassian", "bamboo_server"}},
	"bitbucket":      {{"atlassian", "bitbucket"}, {"atlassian", "bitbucket_data_center"}, {"atlassian", "bitbucket_server"}},
	"bitwarden":      {{"bitwarden", "server"}},
	"cassandra":      {{"apache", "cassandra"}},
	"clickhouse":     {{"clickhouse", "clickhouse"}},
	"code-server":    {{"coder", "code-server"}},
	"confluence":     {{"atlassian", "confluence"}, {"atlassian", "confluence_server"}, {"atlassian", "confluence_data_center"}},
	"domainmod":      {{"domainmod", "domainmod"}},
	"doxygen":        {{"doxygen", "doxygen"}},
	"dropbear":       {{"dropbear_ssh_project", "dropbear_ssh"}},
	"elasticsearch":  {{"elastic", "elasticsearch"}},
	"forgejo":        {{"forgejo", "forgejo"}},
	"fortios":        {{"fortinet", "fortios"}},
	"freeradius":     {{"freeradius", "freeradius"}},
	"ghost":          {{"ghost", "ghost"}},
	"gitlab":         {{"gitlab", "gitlab"}},
	"grafana":        {{"grafana", "grafana"}},
	"graylog":        {{"graylog", "graylog"}, {"torch_gmbh", "graylog2"}},
	"greenbone":      {{"greenbone", "greenbone_security_assistant"}},
	"haproxy":        {{"haproxy", "haproxy"}},
	"harbor":         {{"linuxfoundation", "harbor"}},
	"home-assistant": {{"home-assistant", "home-assistant"}},
	"hp-ilo4":        {{"hp", "integrated_lights-out_4"}, {"hp", "integrated_lights-out_4_firmware"}},
	"idrac10":        {{"dell", "idrac10_firmware"}},
	"idrac6":         {{"dell", "idrac6_firmware"}, {"dell", "idrac6_modular"}, {"dell", "idrac6_monolithic"}},
	"idrac7":         {{"dell", "idrac7_firmware"}, {"dell", "idrac7"}, {"dell", "emc_idrac7"}},
	"idrac8":         {{"dell", "idrac8_firmware"}, {"dell", "idrac8"}, {"dell", "emc_idrac8"}, {"dell", "emc_idrac8_firmware"}, {"dell", "integrated_dell_remote_access_controller_8_firmware"}},
	"idrac9":         {{"dell", "idrac9_firmware"}, {"dell", "idrac9"}, {"dell", "emc_idrac9_firmware"}, {"dell", "integrated_dell_remote_access_controller_9_firmware"}},
	"jaeger":         {{"linuxfoundation", "jaeger"}},
	"jellyfin":       {{"jellyfin", "jellyfin"}},
	"jenkins":        {{"jenkins", "jenkins"}},
	"jira":           {{"atlassian", "jira"}, {"atlassian", "jira_core"}, {"atlassian", "jira_server"}, {"atlassian", "jira_data_center"}, {"atlassian", "jira_software_data_center"}, {"atlassian", "jira_server_and_data_center"}},
	"kafka":          {{"apache", "kafka"}},
	"keycloak":       {{"keycloak", "keycloak"}, {"redhat", "keycloak"}},
	"kibana":         {{"elastic", "kibana"}},
	"logstash":       {{"elastic", "logstash"}},
	"macos":          {{"apple", "macos"}, {"apple", "mac_os_x"}},
	"mariadb":        {{"mariadb", "mariadb"}},
	"mattermost":     {{"mattermost", "mattermost_server"}, {"mattermost", "mattermost"}},
	"memcached":      {{"memcached", "memcached"}},
	"minio":          {{"minio", "minio"}},
	"mongodb":        {{"mongodb", "mongodb"}},
	"mysql":          {{"oracle", "mysql"}, {"mysql", "mysql"}},
	"netbox":         {{"netbox", "netbox"}},
	"netdata":        {{"netdata", "netdata"}},
	"nextcloud":      {{"nextcloud", "nextcloud_server"}},
	"nexus":          {{"sonatype", "nexus_repository_manager"}, {"sonatype", "nexus"}},
	"nginx":          {{"f5", "nginx"}, {"f5", "nginx_open_source"}, {"nginx", "nginx"}},
	"oauth2-proxy":   {{"oauth2_proxy_project", "oauth2_proxy"}},
	"onlyoffice":     {{"onlyoffice", "document_server"}},
	"openhab":        {{"openhab", "openhab"}},
	"opensearch":     {{"amazon", "opensearch"}},
	"openssh":        {{"openbsd", "openssh"}},
	"opnsense":       {{"opnsense", "opnsense"}},
	"owncast":        {{"owncast_project", "owncast"}},
	"p4d":            {{"perforce", "helix_core"}, {"perforce", "perforce_server"}},
	"pfsense":        {{"netgate", "pfsense"}, {"netgate", "pfsense_ce"}, {"pfsense", "pfsense"}},
	"pgadmin":        {{"pgadmin", "pgadmin_4"}},
	"phpipam":        {{"phpipam", "phpipam"}},
	"phpmyadmin":     {{"phpmyadmin", "phpmyadmin"}},
	"portainer":      {{"portainer", "portainer"}},
	"postgresql":     {{"postgresql", "postgresql"}},
	"proftpd":        {{"proftpd", "proftpd"}},
	"proxmox":        {{"proxmox", "virtual_environment"}},
	"qbittorrent":    {{"qbittorrent", "qbittorrent"}},
	"rabbitmq":       {{"pivotal_software", "rabbitmq"}, {"vmware", "rabbitmq"}, {"broadcom", "rabbitmq_server"}},
	"redis":          {{"redis", "redis"}, {"redislabs", "redis"}},
	"routeros":       {{"mikrotik", "routeros"}},
	"sentry":         {{"sentry", "sentry"}},
	"sonarqube":      {{"sonarsource", "sonarqube"}},
	"splunk":         {{"splunk", "splunk"}},
	"synology-dsm":   {{"synology", "diskstation_manager"}},
	"teamcity":       {{"jetbrains", "teamcity"}},
	"testrail":       {{"gurock", "testrail"}},
	"traefik":        {{"traefik", "traefik"}},
	"uptime-kuma":    {{"uptime.kuma", "uptime_kuma"}, {"uptime-kuma_project", "uptime-kuma"}, {"uptime_kuma_project", "uptime_kuma"}},
	"vault":          {{"hashicorp", "vault"}},
	"vaultwarden":    {{"dani-garcia", "vaultwarden"}},
	"wapt":           {{"tranquil", "wapt"}},
	"weblate":        {{"weblate", "weblate"}},
	"wordpress":      {{"wordpress", "wordpress"}},
	"youtrack":       {{"jetbrains", "youtrack"}},
	"zabbix":         {{"zabbix", "zabbix"}},
	"zookeeper":      {{"apache", "zookeeper"}},
}
