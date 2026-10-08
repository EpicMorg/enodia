# Privacy

enodia is a command-line tool you run on your own machine. It has no
telemetry, no usage statistics, no update check and no account. EpicMorg
runs no server that enodia talks to and receives nothing from it.

## What enodia connects to

- **Your own services** — the targets listed in your `enodia.yaml`, over
  HTTPS, SSH or their native protocols, with the credentials you configure,
  to read their version (and, for Linux hosts, the installed package list).
- **endoflife.date** (`https://endoflife.date/api/...`) — to fetch public
  release and end-of-life dates. The request names a product (for example
  `postgresql`); no host names, addresses, versions or other data about
  your fleet are sent.
- **GitHub API** (`https://api.github.com/repos/.../releases`, `.../tags`)
  — for products whose releases are published on GitHub. Same as above:
  only the public repository name is in the request. If you set
  `GITHUB_TOKEN`, it is sent to GitHub only, to raise the rate limit.

That is all. CVE databases (NVD, BDU, Debian, OVAL, Alpine) are files you
download yourself; enodia only reads them from disk.

The HTML report loads Bootstrap from a CDN (jsDelivr / cdnjs) **in the
browser that opens it** when `html.assets: cdn` is set; the default
(`inline`) makes no external requests at all.

## What enodia stores

Only on your machine, and only where you tell it to:

- the inventory, reports and history files you write with `-o`;
- a cache of endoflife.date/GitHub answers and parsed CVE databases in the
  OS cache directory (`~/.cache/enodia`, `%LocalAppData%\enodia`) — safe to
  delete at any time.

Nothing is sent anywhere else, and nothing is retained by EpicMorg.

## Contact

Questions: open an issue at https://github.com/EpicMorg/enodia/issues.
