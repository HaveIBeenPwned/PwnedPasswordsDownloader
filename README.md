# What is haveibeenpwned-downloader?
`haveibeenpwned-downloader` is a [dotnet tool](https://docs.microsoft.com/en-us/dotnet/core/tools/global-tools) to download all Pwned Passwords hash ranges and save them offline so they can be used without a dependency on the k-anonymity API.

An alternative to running this tool is to use Zsolt Müller's cURL approach in https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader/issues/79 that makes use of a glob pattern and parallelism.

# Installation

## Prerequisites
You'll need to install the latest [LTS (Long Term Support)](https://dotnet.microsoft.com/en-us/download/dotnet/8.0) or [STS (Short Term Support)](https://dotnet.microsoft.com/en-us/download/dotnet/9.0) version of the .NET SDK to be able to install and run the tool.

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

# Usage Examples

## **Windows**


### Download all SHA1 hashes to a single txt file called `pwnedpasswords.txt`
`haveibeenpwned-downloader.exe pwnedpasswords`

### Download all SHA1 hashes to individual txt files into a custom directory called `hashes`
`haveibeenpwned-downloader.exe pwnedpasswords -s false`

### Download all NTLM hashes to a single txt file called `pwnedpasswords_ntlm.txt`
`haveibeenpwned-downloader.exe -n pwnedpasswords_ntlm`



## **Linux**


### Download all SHA1 hashes to a single txt file called `pwnedpasswords.txt` :
`haveibeenpwned-downloader pwnedpasswords`

### Download all SHA1 hashes to individual txt files into a custom directory called `hashes`:
`haveibeenpwned-downloader pwnedpasswords -s false`

### Download all NTLM hashes to a single txt file called `pwnedpasswords_ntlm.txt` : 
`haveibeenpwned-downloader -n pwnedpasswords_ntlm`



# Additional parameters

| Parameter   | Default value | Description |
|-------------|---------------|-------------|
| -s/--single | true | Determines whether to download hashes to a single file or as individual .txt files into another directory |
| -p/--parallelism | Same as `Environment.ProcessorCount` | Determines how many hashes to download at a time |
| -o/--overwrite | false | Determines if output files should be overwritten or not |
| -n | (none) | When set, the downloader fetches NTLM hashes instead of SHA1 |

# Additional usage examples
## Download all hashes to individual txt files into a custom directory called `hashes` using 64 threads to download the hashes
`haveibeenpwned-downloader.exe hashes -s false -p 64`
## Download all hashes to a single txt file called `pwnedpasswords.txt` using 64 threads, overwriting the file if it already exists
`haveibeenpwned-downloader.exe pwnedpasswords -o -p 64`
