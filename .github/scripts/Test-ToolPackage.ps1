param(
    [Parameter(Mandatory)][string] $PackageDirectory,
    [Parameter(Mandatory)][string] $RuntimeIdentifier
)

$ErrorActionPreference = 'Stop'
$packages = @(Get-ChildItem -LiteralPath $PackageDirectory -File -Filter "*.$RuntimeIdentifier.*.nupkg")
if ($packages.Count -ne 1) {
    throw "Expected exactly one $RuntimeIdentifier Native AOT package, found $($packages.Count)."
}

$archive = [System.IO.Compression.ZipFile]::OpenRead($packages[0].FullName)
try {
    if (-not ($archive.Entries | Where-Object FullName -like 'tools/*')) {
        throw "The $RuntimeIdentifier package does not contain tool payload files."
    }

    $hostArchitecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()
    if (-not $RuntimeIdentifier.EndsWith("-$hostArchitecture")) {
        Write-Output "Package layout verified; execution skipped for cross-compiled $RuntimeIdentifier."
        return
    }

    $smokeDirectory = Join-Path ([System.IO.Path]::GetTempPath()) "hibp-package-$([Guid]::NewGuid().ToString('N'))"
    [System.IO.Compression.ZipFileExtensions]::ExtractToDirectory($archive, $smokeDirectory)
}
finally {
    $archive.Dispose()
}

$executableName = if ($IsWindows) { 'haveibeenpwned-downloader.exe' } else { 'haveibeenpwned-downloader' }
$executables = @(Get-ChildItem -LiteralPath $smokeDirectory -Recurse -File -Filter $executableName)
if ($executables.Count -ne 1) {
    throw "Expected exactly one native executable, found $($executables.Count)."
}
$executable = $executables[0].FullName
if (-not $IsWindows) {
    & chmod +x $executable
    if ($LASTEXITCODE -ne 0) { throw 'Could not mark the native executable as executable.' }
}
& $executable --help
if ($LASTEXITCODE -ne 0) { throw 'Native tool --help failed.' }

$outputDirectory = Join-Path $smokeDirectory 'existing-output'
$null = New-Item -ItemType Directory -Path $outputDirectory
Set-Content -LiteralPath (Join-Path $outputDirectory '00000.txt') -Value 'preserve me'
$output = (& $executable $outputDirectory --ntlm 2>&1 | Out-String)
if ($LASTEXITCODE -ne 1 -or $output -match 'Finished processing|NaN') {
    throw "Native tool did not correctly reject existing output: $output"
}
& $executable --version
if ($LASTEXITCODE -ne 0) { throw 'Native tool --version failed.' }
Write-Output "Verified $RuntimeIdentifier native package, --help, and output refusal."
