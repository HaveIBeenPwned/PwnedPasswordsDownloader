# What is haveibeenpwned-downloader?
`haveibeenpwned-downloader` is a [dotnet tool](https://docs.microsoft.com/en-us/dotnet/core/tools/global-tools) to download all Pwned Passwords hash ranges and save them offline so they can be used without a dependency on the k-anonymity API.

An alternative to running this tool is to use Zsolt Müller's cURL approach in https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader/issues/79 that makes use of a glob pattern and parallelism.

# Installation

## Prerequisites
Install the [.NET 11 SDK](https://dotnet.microsoft.com/en-us/download/dotnet/11.0) or later to install the tool. Native AOT, self-contained packages are available for Windows x64/Arm64, Linux x64/Arm64, and macOS Apple silicon; the installed tool does not require a separate .NET runtime. Other runtime combinations use a framework-dependent fallback package and require the .NET 11 runtime.

## How to install
1. Open a command line window
2. Run `dotnet tool install --global haveibeenpwned-downloader`

## How to update to the latest version
1. Open a command line window
2. Run `dotnet tool update --global haveibeenpwned-downloader`

### Troubleshooting
If the installer is unable to resolve the package, then you can run the following and then try again.
```
dotnet nuget add source https://api.nuget.org/v3/index.json -n nuget.org
```

## Content verification
Every downloaded hash range is verified against the `Content-MD5` response header supplied by the Pwned Passwords API before it is accepted. Verification hashes the response while copying it, without rereading range files from disk. Directory downloads replace each range atomically after verification, preserving an existing file if downloading or verification fails. A verification failure is retried according to `--max-retries`; if retries are exhausted, the downloader fails rather than reporting the corrupt range as successfully downloaded.

## Incremental directory downloads
Directory downloads create `sha1.index` or `ntlm.index` in the output directory. The index is a prefix-sorted, tab-delimited list of range prefixes and ETags, written atomically. On later runs, the downloader sends the saved ETag with `If-None-Match`; ranges that have not changed are retained locally without downloading their content again. Ranges returned without an ETag are not indexed and download again on each run.

Use `--force` to ignore the existing index, download every range, and rebuild the index. Indexes are not used with `--single`, which always creates a complete output file.

A nonempty directory without an index (for example, after an interrupted first download) requires `--overwrite` (`-o`) to download again. Refusing to overwrite exits with code 1 and does not print download statistics. `-o` permits replacement of range files; it does not delete unrelated files.

# Usage Examples

Run `haveibeenpwned-downloader` with no parameters to display its usage and examples. Supply an output name to begin a download.

## **Windows**


### Download all SHA1 hashes to a single txt file called `pwnedpasswords.txt`
`haveibeenpwned-downloader.exe pwnedpasswords --single`

### Download all SHA1 hashes to individual txt files into a custom directory called `hashes`
`haveibeenpwned-downloader.exe hashes`

### Download all NTLM hashes to individual txt files into a custom directory called `ntlm_hashes`
`haveibeenpwned-downloader.exe ntlm_hashes --ntlm`

### Download all NTLM hashes to a single txt file called `pwnedpasswords_ntlm.txt`
`haveibeenpwned-downloader.exe -n pwnedpasswords_ntlm --single`



## **Linux**


### Download all SHA1 hashes to a single txt file called `pwnedpasswords.txt` :
`haveibeenpwned-downloader pwnedpasswords --single`

### Download all SHA1 hashes to individual txt files into a custom directory called `hashes`:
`haveibeenpwned-downloader hashes`

### Download all NTLM hashes to individual txt files into a custom directory called `ntlm_hashes`:
`haveibeenpwned-downloader ntlm_hashes --ntlm`

### Download all NTLM hashes to a single txt file called `pwnedpasswords_ntlm.txt` : 
`haveibeenpwned-downloader -n pwnedpasswords_ntlm --single`



# Additional parameters

| Parameter   | Default value | Description |
|-------------|---------------|-------------|
| -s/--single | false | When set, downloads hashes to a single file instead of individual .txt files in a directory |
| -p/--parallelism | Eight times `Environment.ProcessorCount` (minimum 2) | Determines how many ranges to download at a time; values less than 2 select the default |
| --max-retries | Unlimited | Determines how many times each prefix is retried after a failure. Omit for unlimited retries, or pass `0` to disable retries. Retry delays increase per prefix up to 10 seconds. |
| -o/--overwrite | false | Determines if output files should be overwritten or not |
| -n/--ntlm | (none) | When set, the downloader fetches NTLM hashes instead of SHA1 |
| --force | false | Ignores saved ETags, downloads every range, and rebuilds the index for directory output |

# Additional usage examples
## Download all hashes to individual txt files into a custom directory called `hashes` using 64 threads to download the hashes
`haveibeenpwned-downloader.exe hashes -p 64`
## Download all hashes to a single txt file called `pwnedpasswords.txt` using 64 threads, overwriting the file if it already exists
`haveibeenpwned-downloader.exe pwnedpasswords --single -o -p 64`
## Download all hashes with at most 5 retries per prefix
`haveibeenpwned-downloader.exe pwnedpasswords --max-retries 5`

# Development

The SDK version is selected by `global.json`. Build and run the regression tests with:

```sh
dotnet test src/HaveIBeenPwned.PwnedPasswords.Downloader.sln --configuration Release -p:PublishAot=false -p:PublishTrimmed=false
```

CI and deployment run these tests on Windows, Linux, and macOS before packaging the Native AOT and framework-dependent tools.
