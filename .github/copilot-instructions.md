# Copilot instructions for PwnedPasswordsDownloader

## Build and test

- The project targets .NET 11; `global.json` selects the SDK and C# 15 is the default language version.
- Run regression tests: `dotnet test src/HaveIBeenPwned.PwnedPasswords.Downloader.sln --configuration Release -p:PublishAot=false -p:PublishTrimmed=false`.
- Smoke test the CLI: `dotnet run --project src/HaveIBeenPwned.PwnedPasswords.Downloader -- --help`.
- Package a native tool: `dotnet pack src/HaveIBeenPwned.PwnedPasswords.Downloader --configuration Release --runtime <rid>`.
- Package the framework-dependent fallback with `--runtime any -p:PublishAot=false`. For the pointer package, omit `--runtime` and set `-p:CreateRidSpecificToolPackages=false` so .NET 11 does not rebuild the runtime packages.
- CI and deployment call `.github/workflows/test.yml` before packaging. Keep their SDK and package layout checks consistent with the project target.

## Architecture

- `Program.cs` contains command parsing, HTTP setup, progress, retries, verification, and both download paths.
- `RangeIndex.cs` stores ETags and atomically saves a prefix-sorted index for conditional directory downloads.
- All 1,048,576 five-character uppercase hexadecimal prefixes are downloaded. NTLM requests add `?mode=ntlm`.
- Directory mode uses `Parallel.ForEachAsync`. Honor the loop-provided cancellation token so a failing worker stops its siblings.
- Single-file mode uses a bounded window of download tasks, writes in prefix order, and joins all outstanding work on failure/cancellation.
- MD5 is an API-provided content-integrity check. Hash while copying with asynchronous I/O; do not reread asynchronous file handles synchronously.
- Replace directory range files only after verification succeeds. Keep index entries consistent with accepted files.
- Explicit `HttpRequestMessage` instances must copy the client's HTTP version and version policy before `SendAsync`.

## Conventions

- Preserve output guards: existing single files require `-o`; nonempty directories without an index require `-o` or `--force`. Refusal returns a nonzero exit code without success statistics.
- Use Spectre.Console for user-facing output and escape interpolated paths and exception messages with `EscapeMarkup()`.
- Follow `src/.editorconfig`. Keep asynchronous operations cancellable and await owned work before disposing resources.
- Tests use simulated HTTP responses and temporary directories; they must not download the live corpus.
- Preserve Native AOT tool packaging, the `haveibeenpwned-downloader` command, and the embedded README/icon.
