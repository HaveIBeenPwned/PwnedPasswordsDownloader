# Copilot instructions for PwnedPasswordsDownloader

## Build, test, and lint commands

- Primary validation command: `dotnet pack .\src\HaveIBeenPwned.PwnedPasswords.Downloader\HaveIBeenPwned.PwnedPasswords.Downloader.csproj --configuration Release`
- Local CLI smoke test: `dotnet run --project .\src\HaveIBeenPwned.PwnedPasswords.Downloader\HaveIBeenPwned.PwnedPasswords.Downloader.csproj --framework net9.0 -- --help`
- The project multi-targets `net8.0` and `net9.0`, so `dotnet run` must include `--framework net8.0` or `--framework net9.0`.
- There is currently no test project in the repository, so there is no full-suite or single-test command yet.
- There is no repo-specific lint command configured; follow `src\.editorconfig` and use the normal .NET build/pack output as the main validation signal.

## High-level architecture

- This repository is a single packaged .NET CLI tool. The only product project is `src\HaveIBeenPwned.PwnedPasswords.Downloader\HaveIBeenPwned.PwnedPasswords.Downloader.csproj`, and CI validates it by packing the tool rather than building a larger solution graph.
- `Program.cs` contains nearly all runtime behavior: it bootstraps a generic host, wires an `HttpClient` named `PwnedPasswords`, and runs a single Spectre.Console command class, `PwnedPasswordsDownloader`.
- The downloader always iterates the full Pwned Passwords range space (`0` through `1024 * 1024 - 1`). `GetHashRange` converts each integer to the 5-character range prefix used by the HIBP range API, and single-file output reconstructs full hashes by prepending that prefix to every returned suffix line.
- Networking is centralized around the named `HttpClient` plus a Polly resilience pipeline. Requests go to `https://api.pwnedpasswords.com/range/`, use HTTP/2 when available, retry failures up to 10 times, and track Cloudflare cache-hit metrics in `Statistics`.
- Output has two distinct write paths. `ProcessRanges` either:
  - streams all ranges through a bounded `Channel<Task<Stream>>` into one `outputFile.txt`, preserving range order, or
  - downloads each range directly to its own `xxxxx.txt` file with `Parallel.ForEachAsync`.
- `Helpers.CopyFrom` is the custom high-throughput file-writing primitive for per-range files. It copies the HTTP response stream into a pooled `Pipe` and writes buffers with `RandomAccess.WriteAsync` on a `SafeFileHandle`; reuse that path if you change direct-to-file downloads.

## Key conventions

- Most logic lives in `Program.cs`, including the command settings, downloader implementation, host registration, and DI bridge types. Do not assume this repo follows a many-files-per-type layout.
- User-facing behavior is intentionally surfaced through Spectre.Console output instead of logging providers. `Program.cs` clears default host logging and reports retries, failures, progress, and final statistics through `AnsiConsole`.
- Existing output safety checks are part of the command contract: single-file mode refuses to overwrite `outputFile.txt` unless `-o` is set, and directory mode refuses to write into a non-empty directory unless `-o` is set.
- Keep the packaging layout intact when editing the project file: the NuGet tool package embeds the repository `README.md` and `.github\images\hibp.png`, and the command name is `haveibeenpwned-downloader`.
- Follow `src\.editorconfig` conventions when editing C#: explicit types are preferred over `var` unless the type is obvious, private/internal fields use `_camelCase`, private/internal static fields use `s_` prefixes, and braces stay on new lines.
