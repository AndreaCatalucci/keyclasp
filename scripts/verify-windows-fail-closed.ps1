param([Parameter(Mandatory = $true)][string]$Artifact)

$ErrorActionPreference = "Stop"
$sourceArtifact = (Resolve-Path $Artifact).Path
if ($env:EXPECTED_SHA256 -notmatch "^[a-f0-9]{64}$") { throw "EXPECTED_SHA256 must name the reviewed candidate." }
$root = Join-Path $env:RUNNER_TEMP "keyclasp-windows-fail-closed-$([guid]::NewGuid())"
$install = Join-Path $root "install"
$vault = Join-Path $root "vault-state"
New-Item -ItemType Directory -Path $install -Force | Out-Null
$Artifact = Join-Path $root (Split-Path $sourceArtifact -Leaf)
[System.IO.File]::WriteAllBytes($Artifact, [System.IO.File]::ReadAllBytes($sourceArtifact))
$stagedSha256 = (Get-FileHash -Algorithm SHA256 $Artifact).Hash.ToLowerInvariant()
if ($stagedSha256 -ne $env:EXPECTED_SHA256) {
  throw "Artifact SHA-256 mismatch: expected $($env:EXPECTED_SHA256), received $stagedSha256."
}

Push-Location $install
try {
  npm install $Artifact 2>&1 | Out-String | Set-Variable normalInstall
  if ($LASTEXITCODE -eq 0) { throw "Windows installation unexpectedly succeeded without --force." }
  if ($normalInstall -notmatch "EBADPLATFORM") { throw "Windows installation did not fail with EBADPLATFORM." }

  npm install --force --ignore-scripts $Artifact
  if ($LASTEXITCODE -ne 0) { throw "Forced diagnostic installation failed." }
  $cli = Join-Path $install "node_modules/keyclasp/dist/cli.js"
  $statefulCommands = @(
    @{ Name = "init"; Args = @("init") },
    @{ Name = "set"; Args = @("set", "TOKEN") },
    @{ Name = "get"; Args = @("get", "TOKEN") },
    @{ Name = "list"; Args = @("list") },
    @{ Name = "delete"; Args = @("delete", "TOKEN") },
    @{ Name = "use"; Args = @("use", "project", "environment") },
    @{ Name = "projects"; Args = @("projects") },
    @{ Name = "environments"; Args = @("environments") },
    @{ Name = "rename"; Args = @("rename", "--project", "old", "--to-project", "new") },
    @{ Name = "run"; Args = @("run", "--env", "TOKEN", "--", "node", "-e", "process.exit(0)") },
    @{ Name = "lock"; Args = @("lock", "--project", "project") },
    @{ Name = "unlock"; Args = @("unlock", "--project", "project") },
    @{ Name = "inherit"; Args = @("inherit", "--project", "project") },
    @{ Name = "passphrase"; Args = @("passphrase", "set") },
    @{ Name = "backup"; Args = @("backup", "create", (Join-Path $root "backup")) },
    @{ Name = "status"; Args = @("status") }
  )
  foreach ($entry in $statefulCommands) {
    $entryVault = Join-Path $vault $entry.Name
    $env:KEYCLASP_HOME = $entryVault
    $entryArgs = $entry.Args
    & node $cli @entryArgs 2>&1 | Out-String | Set-Variable entryOutput
    if ($LASTEXITCODE -eq 0) { throw "Windows $($entry.Name) unexpectedly succeeded." }
    if ($entryOutput -notmatch "unsupported on Windows" -or $entryOutput -notmatch "No vault state was created or changed") {
      throw "Windows $($entry.Name) did not return the fail-closed platform message."
    }
    if (Test-Path $entryVault) { throw "Windows $($entry.Name) created vault state before rejecting the platform." }
  }
} finally {
  Pop-Location
}

Write-Output "PASS: Windows install and every stateful CLI command fail closed before vault creation."
