using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using Spectre.Console;
using Xunit;

[assembly: CollectionBehavior(DisableTestParallelization = true)]

namespace HaveIBeenPwned.PwnedPasswords.Downloader.Tests;

public sealed class DownloaderTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), $"hibp-tests-{Guid.NewGuid():N}");
    private readonly StringWriter _output = new();
    private readonly IAnsiConsole _originalConsole = AnsiConsole.Console;

    public DownloaderTests()
    {
        Directory.CreateDirectory(_directory);
        AnsiConsole.Console = AnsiConsole.Create(new AnsiConsoleSettings
        {
            Ansi = AnsiSupport.No,
            Interactive = InteractionSupport.No,
            Out = new AnsiConsoleOutput(_output)
        });
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ExistingOutputFailsWithoutRequestsOrSuccessSummary(bool singleFile)
    {
        var output = Path.Combine(_directory, "existing");
        var existingFile = singleFile ? $"{output}.txt" : Path.Combine(output, "00000.txt");
        if (!singleFile) Directory.CreateDirectory(output);
        await File.WriteAllTextAsync(existingFile, "keep me");
        using var client = CreateClient((_, _) => throw new Xunit.Sdk.XunitException("Unexpected HTTP request"));
        var downloader = new PwnedPasswordsDownloader(client);

        var result = await downloader.ExecuteAsync(new() { OutputFile = output, SingleFile = singleFile }, CancellationToken.None);

        Assert.Equal(1, result);
        Assert.Contains("already exists", _output.ToString());
        Assert.DoesNotContain("Finished processing", _output.ToString());
        Assert.DoesNotContain("NaN", _output.ToString());
        Assert.Equal("keep me", await File.ReadAllTextAsync(existingFile));
    }

    [Fact]
    public void ZeroElapsedTimeHasFiniteThroughput()
    {
        Assert.Equal(0, new Statistics().HashesPerSecond);
        Assert.Equal(0, new Statistics { HashesDownloaded = 1 }.HashesPerSecond);
        Assert.Equal(2, new Statistics { HashesDownloaded = 4, ElapsedMilliseconds = 2000 }.HashesPerSecond);
    }

    [Fact]
    public void HighestCompletedRangeNeverRegressesWhenRangesFinishOutOfOrder()
    {
        var statistics = new Statistics();
        Assert.Equal(-1, statistics.HighestCompletedRange);

        statistics.RecordCompletedRange(0);
        Assert.Equal(0, statistics.HighestCompletedRange);
        statistics.RecordCompletedRange(0x01234);
        statistics.RecordCompletedRange(0x00001);
        Assert.Equal(0x01234, statistics.HighestCompletedRange);
        Assert.Equal(3, statistics.HashesDownloaded);

        Parallel.For(0, 4096, i => statistics.RecordCompletedRange(0xFFFFF - i));
        Assert.Equal(0xFFFFF, statistics.HighestCompletedRange);
        Assert.Equal(4099, statistics.HashesDownloaded);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(32767)]
    [InlineData(32768)]
    [InlineData(100000)]
    public async Task VerificationStreamsToAWriteOnlyFile(int length)
    {
        var bytes = RandomNumberGenerator.GetBytes(length);
        using var source = new AsyncOnlyReadStream(bytes);
        var path = Path.Combine(_directory, "range.txt");
        await using (var destination = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 32768, FileOptions.Asynchronous))
        {
            await PwnedPasswordsDownloader.CopyAndVerifyAsync(source, destination, MD5.HashData(bytes), CancellationToken.None);
        }
        Assert.Equal(bytes, await File.ReadAllBytesAsync(path));
    }

    [Fact]
    public async Task CorruptResponsePreservesExistingRangeAndEtag()
    {
        var path = Path.Combine(_directory, "00000.txt");
        await File.WriteAllTextAsync(path, "original");
        var index = new RangeIndex();
        index.Set("00000", "\"old\"");
        using var client = CreateClient((_, _) =>
        {
            var response = Response("corrupt"u8.ToArray());
            response.Content.Headers.ContentMD5 = MD5.HashData("expected"u8);
            return Task.FromResult(response);
        });

        await Assert.ThrowsAsync<InvalidDataException>(() => new PwnedPasswordsDownloader(client)
            .DownloadRangeToFile(0, _directory, true, 0, index, CancellationToken.None));

        Assert.Equal("original", await File.ReadAllTextAsync(path));
        Assert.True(index.TryGet("00000", out var etag));
        Assert.Equal("\"old\"", etag);
        Assert.Empty(Directory.EnumerateFiles(_directory, "*.tmp"));
    }

    [Fact]
    public async Task ConcurrentRangesVerifyAndHonorNtlmAndHttpVersion()
    {
        var bytes = RandomNumberGenerator.GetBytes(70000);
        using var client = CreateClient((request, _) =>
        {
            Assert.Equal("?mode=ntlm", request.RequestUri!.Query);
            Assert.Equal(HttpVersion.Version30, request.Version);
            Assert.Equal(HttpVersionPolicy.RequestVersionOrLower, request.VersionPolicy);
            return Task.FromResult(Response(bytes));
        });
        var downloader = new PwnedPasswordsDownloader(client);
        var index = new RangeIndex();

        await Parallel.ForEachAsync(Enumerable.Range(0, 256), new ParallelOptions { MaxDegreeOfParallelism = 32 },
            async (i, token) => await downloader.DownloadRangeToFile(i, _directory, true, 0, index, token));

        Assert.Equal(256, index.Count);
        foreach (var file in Directory.EnumerateFiles(_directory, "*.txt"))
        {
            Assert.Equal(bytes, await File.ReadAllBytesAsync(file));
        }
        Assert.Equal(256, Directory.EnumerateFiles(_directory, "*.txt").Count());
    }

    [Fact]
    public async Task NotModifiedRetainsExistingRange()
    {
        var path = Path.Combine(_directory, "FFFFF.txt");
        await File.WriteAllTextAsync(path, "original");
        var index = new RangeIndex();
        index.Set("FFFFF", "\"old\"");
        using var client = CreateClient((request, _) =>
        {
            Assert.Equal("/range/FFFFF", request.RequestUri!.AbsolutePath);
            Assert.Equal("\"old\"", Assert.Single(request.Headers.IfNoneMatch).ToString());
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotModified));
        });
        await new PwnedPasswordsDownloader(client).DownloadRangeToFile(0xFFFFF, _directory, false, 0, index, CancellationToken.None);
        Assert.Equal("original", await File.ReadAllTextAsync(path));
    }

    [Fact]
    public async Task IndexedRangeWithMissingFileDownloadsWithoutConditionalHeader()
    {
        var index = new RangeIndex();
        index.Set("00000", "\"old\"");
        var bytes = "ABC:1\r\n"u8.ToArray();
        using var client = CreateClient((request, _) =>
        {
            Assert.Empty(request.Headers.IfNoneMatch);
            return Task.FromResult(Response(bytes));
        });

        await new PwnedPasswordsDownloader(client).DownloadRangeToFile(0, _directory, true, 0, index, CancellationToken.None);

        Assert.Equal(bytes, await File.ReadAllBytesAsync(Path.Combine(_directory, "00000.txt")));
        Assert.True(index.TryGet("00000", out var etag));
        Assert.Equal("\"etag\"", etag);
        Assert.Empty(Directory.EnumerateFiles(_directory, "*.tmp"));
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public async Task CancellationAndFailureJoinOutstandingRequests(bool singleFile, bool fail)
    {
        using var cancellation = new CancellationTokenSource();
        var allStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var active = 0;
        var started = 0;
        using var client = CreateClient(async (request, token) =>
        {
            Interlocked.Increment(ref active);
            if (Interlocked.Increment(ref started) == 4) allStarted.SetResult();
            try
            {
                await allStarted.Task.WaitAsync(token);
                if (fail && request.RequestUri!.AbsolutePath.EndsWith("00000", StringComparison.Ordinal))
                {
                    return new HttpResponseMessage(HttpStatusCode.InternalServerError);
                }
                await Task.Delay(Timeout.Infinite, token);
                throw new InvalidOperationException("Unreachable");
            }
            finally
            {
                await Task.Delay(150, CancellationToken.None); // Simulate native I/O finishing after cancellation.
                Interlocked.Decrement(ref active);
            }
        });
        var task = new PwnedPasswordsDownloader(client).ExecuteAsync(new()
        {
            OutputFile = Path.Combine(_directory, "output"),
            SingleFile = singleFile,
            Parallelism = 4,
            MaxRetries = 0
        }, cancellation.Token);
        await allStarted.Task.WaitAsync(TimeSpan.FromSeconds(10));
        if (!fail) await cancellation.CancelAsync();

        Assert.Equal(fail ? -1 : -2, await task.WaitAsync(TimeSpan.FromSeconds(10)));
        Assert.Equal(0, Volatile.Read(ref active));
        Assert.DoesNotContain("Finished processing", _output.ToString());
    }

    [Fact]
    public async Task SingleFilePreservesPrefixOrderWithoutEmbeddedBom()
    {
        using var client = CreateClient(async (request, token) =>
        {
            var prefix = request.RequestUri!.Segments[^1];
            if (prefix == "00000") await Task.Delay(100, token);
            if (prefix == "00003") return new HttpResponseMessage(HttpStatusCode.InternalServerError);
            return Response("ABC:1\r\nDEF:2\r\n"u8.ToArray());
        });
        var output = Path.Combine(_directory, "single");
        var result = await new PwnedPasswordsDownloader(client).ExecuteAsync(new()
        {
            OutputFile = output, SingleFile = true, Parallelism = 4, MaxRetries = 0
        }, CancellationToken.None);

        Assert.Equal(-1, result);
        var expected = string.Concat(Enumerable.Range(0, 3).Select(i => $"{i:X5}ABC:1{Environment.NewLine}{i:X5}DEF:2{Environment.NewLine}"));
        Assert.Equal(Encoding.UTF8.GetBytes(expected), await File.ReadAllBytesAsync($"{output}.txt"));
    }

    private static HttpClient CreateClient(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) => new(new Handler(send))
    {
        BaseAddress = new Uri("https://example.test/range/"),
        DefaultRequestVersion = HttpVersion.Version30,
        DefaultVersionPolicy = HttpVersionPolicy.RequestVersionOrLower
    };

    private static HttpResponseMessage Response(byte[] bytes)
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(new AsyncOnlyReadStream(bytes)) };
        response.Content.Headers.ContentMD5 = MD5.HashData(bytes);
        response.Headers.ETag = new EntityTagHeaderValue("\"etag\"");
        return response;
    }

    public void Dispose()
    {
        AnsiConsole.Console = _originalConsole;
        _output.Dispose();
        Directory.Delete(_directory, recursive: true);
    }

    private sealed class Handler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => send(request, cancellationToken);
    }

    private sealed class AsyncOnlyReadStream(byte[] bytes) : Stream
    {
        private int _position;
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException("Synchronous read");
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            await Task.Yield();
            cancellationToken.ThrowIfCancellationRequested();
            var count = Math.Min(Math.Min(buffer.Length, 4093), bytes.Length - _position);
            bytes.AsMemory(_position, count).CopyTo(buffer);
            _position += count;
            return count;
        }
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
