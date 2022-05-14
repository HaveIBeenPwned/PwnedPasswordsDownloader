# What is haveibeenpwned-downloader?
`haveibeenpwned-downloader` is a [dotnet tool](https://docs.microsoft.com/en-us/dotnet/core/tools/global-tools) to download all Pwned Passwords hash ranges and save them offline so they can be used without a dependency on the k-anonymity API

## Installation

### Prerequisites
You'll need to install [.NET 6](https://dotnet.microsoft.com/en-us/download/dotnet/6.0) to be able to install the tool.

### How to install
1. Open a command line window
2. Run `dotnet tool install --global haveibeenpwned-downloader`

## Usage

Download all hashes to a single txt file called `pwnedpasswords.txt`

```
haveibeenpwned-downloader.exe pwnedpasswords
```

Download all hashes to individual txt files into a custom directory called `hashes`

```
haveibeenpwned-downloader.exe pwnedpasswords -s false
```

### Additional parameters

| Parameter   | Default value | Description |
|-------------|---------------|-------------|
| -s/--single | true | Determines wether to download hashes to a single file or as individual .txt files into another directory |
| -p/--parallelism | Same as `Environment.ProcessorCount` | Determines how many hashes to download at a time |
| -o/--overwrite | false | Determines if output files should be overwritten or not |

### Additional usage examples
Download all hashes to individual txt files into a custom directory called `hashes` using 64 threads to download the hashes

```
haveibeenpwned-downloader.exe hashes -s false -p 64
```

Download all hashes to a single txt file called `pwnedpasswords.txt` using 64 threads, overwriting the file if it already exists

```
haveibeenpwned-downloader.exe pwnedpasswords -o -p 64
```
