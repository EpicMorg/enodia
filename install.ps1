# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Installs the enodia binary for Windows from GitHub Releases.
#
#   irm https://raw.githubusercontent.com/EpicMorg/enodia/master/install.ps1 | iex
#
# Mirrors install.sh's logic (same repo, same archive naming, same
# latest/download alias to avoid the GitHub API's rate limit) for the one
# OS install.sh explicitly declines to handle itself.
#
# Env vars (set before running, e.g. `$env:ENODIA_VERSION = "1.2.3+4"`):
#   ENODIA_VERSION      version tag to install, e.g. "1.2.3+4" (default: latest)
#   ENODIA_INSTALL_DIR  directory to install into (default: %LOCALAPPDATA%\enodia)

$ErrorActionPreference = "Stop"

$repo = "EpicMorg/enodia"
$installDir = if ($env:ENODIA_INSTALL_DIR) { $env:ENODIA_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA "enodia" }

switch ([System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture) {
	"X64"   { $arch = "amd64" }
	"Arm64" { $arch = "arm64" }
	"X86"   { $arch = "386" }
	default {
		Write-Error "install.ps1: unsupported architecture: $_"
		exit 1
	}
}

$version = if ($env:ENODIA_VERSION) { $env:ENODIA_VERSION } else { "latest" }

# Must match archives.name_template + format_overrides in .goreleaser.yaml
# exactly: windows archives are zip, everything else is tar.gz.
$archive = "enodia_windows_${arch}.zip"
if ($version -eq "latest") {
	# GitHub's own alias — resolves server-side with no API call, so
	# there's no tag_name to parse and no API rate limit to hit.
	$baseUrl = "https://github.com/$repo/releases/latest/download"
} else {
	$baseUrl = "https://github.com/$repo/releases/download/$version"
}

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
	Write-Host "install.ps1: downloading enodia $version for windows/$arch..."
	Invoke-WebRequest -Uri "$baseUrl/$archive" -OutFile (Join-Path $tmp $archive)
	Invoke-WebRequest -Uri "$baseUrl/checksums.txt" -OutFile (Join-Path $tmp "checksums.txt")

	Write-Host "install.ps1: verifying checksum..."
	$expected = (Select-String -Path (Join-Path $tmp "checksums.txt") -Pattern "  $archive$").Line
	if (-not $expected) {
		Write-Error "install.ps1: $archive not listed in checksums.txt"
		exit 1
	}
	$expectedHash = ($expected -split "\s+")[0]
	$actualHash = (Get-FileHash -Path (Join-Path $tmp $archive) -Algorithm SHA256).Hash.ToLower()
	if ($actualHash -ne $expectedHash) {
		Write-Error "install.ps1: checksum mismatch for $archive (expected $expectedHash, got $actualHash)"
		exit 1
	}

	Expand-Archive -Path (Join-Path $tmp $archive) -DestinationPath $tmp -Force

	New-Item -ItemType Directory -Path $installDir -Force | Out-Null
	Copy-Item -Path (Join-Path $tmp "enodia.exe") -Destination (Join-Path $installDir "enodia.exe") -Force
} finally {
	Remove-Item -Path $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

# Persist to the registry (HKCU\Environment) so every future shell has it...
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ((($userPath -split ";") | Where-Object { $_ }) -notcontains $installDir) {
	Write-Host "install.ps1: adding $installDir to your user PATH"
	$newUserPath = if ($userPath) { "$userPath;$installDir" } else { $installDir }
	[Environment]::SetEnvironmentVariable("Path", $newUserPath, "User")
}

# ...and also patch this process's own $env:Path: SetEnvironmentVariable above
# only changes the registry, which an already-running shell (this one, if
# invoked via "irm ... | iex") never re-reads — without this, `enodia` stays
# "not recognized" until a brand new terminal is opened, even though the
# install just "succeeded".
if ((($env:Path -split ";") | Where-Object { $_ }) -notcontains $installDir) {
	$env:Path = "$env:Path;$installDir"
}

$installed = & (Join-Path $installDir "enodia.exe") version
Write-Host "install.ps1: installed $installed to $installDir\enodia.exe"
