using System.Buffers.Binary;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Channels;

using HaveIBeenPwned.PwnedPasswords;

using Polly;
using Polly.Extensions.Http;
using Polly.Retry;

using Spectre.Console;
using Spectre.Console.Cli;

var app = new CommandApp<PwnedPasswordsDownloader>();

app.Configure(config => config.PropagateExceptions());

try
{
    return app.Run(args);
}
catch (Exception ex)
{
    AnsiConsole.WriteException(ex, ExceptionFormats.ShortenEverything);
    return -99;
}

internal sealed class Statistics
{
    public int HashesDownloaded = 0;
    public int CloudflareRequests = 0;
    public int CloudflareHits = 0;
    public int CloudflareMisses = 0;
    public long CloudflareRequestTimeTotal = 0;
    public long ElapsedMilliseconds = 0;
    public double CloudflareHitPercentage => CloudflareHits / (double)CloudflareHits * 100;
    public double CloudflareMissPercentage => CloudflareHits / (double)CloudflareHits * 100;
    public double HashesPerSecond => HashesDownloaded / (ElapsedMilliseconds / 1000.0);
}

internal sealed class PwnedPasswordsDownloader : Command<PwnedPasswordsDownloader.Settings>
{
    internal int _hashesInProgress = 0;
    internal Statistics _statistics = new();
    internal static Encoding s_encoding = Encoding.UTF8;
    internal HttpClient _httpClient = InitializeHttpClient();
    internal AsyncRetryPolicy<HttpResponseMessage> _policy = HttpPolicyExtensions.HandleTransientHttpError().RetryAsync(5);

    public sealed class Settings : CommandSettings
    {
        [Description("Name of the output. Defaults to pwnedpasswords, which writes the output to pwnedpasswords.txt for single file output, or a directory called pwnedpasswords.")]
        [CommandArgument(0, "[outputFile]")]
        public string OutputFile { get; init; } = "pwnedpasswords";

        [Description("The number of parallel requests to make to HaveIBeenPwned to download the hash ranges. If omitted or less than 2, defaults to the number of processors on the machine.")]
        [CommandOption("-p||--parallelism")]
        [DefaultValue(0)]
        public int Parallelism { get; set; } = 0;

        [Description("When set, overwrite any existing files while writing the results. Defaults to false.")]
        [CommandOption("-o|--overwrite")]
        [DefaultValue(false)]
        public bool Overwrite { get; set; } = false;

        [Description("When set, writes the hash ranges into a single .txt file. Otherwise downloads ranges to individual files into a subfolder.")]
        [CommandOption("-s|--single")]
        [DefaultValue(true)]
        public bool SingleFile { get; set; } = true;
    }

    public override int Execute([NotNull] CommandContext context, [NotNull] Settings settings)
    {
        if (settings.Parallelism < 2)
        {
            settings.Parallelism = Math.Max(Environment.ProcessorCount, 2);
        }

        Task processingTask = AnsiConsole.Progress()
            .AutoRefresh(false) // Turn off auto refresh
            .AutoClear(false)   // Do not remove the task list when done
            .HideCompleted(false)   // Hide tasks as they are completed
            .Columns(new ProgressColumn[]
            {
                new TaskDescriptionColumn(),    // Task description
                new ProgressBarColumn(),        // Progress bar
                new PercentageColumn(),         // Percentage
                new RemainingTimeColumn(),      // Remaining time
                new SpinnerColumn(),
            })
            .StartAsync(async ctx =>
            {
                if (settings.SingleFile)
                {
                    if (File.Exists(settings.OutputFile))
                    {
                        if (!settings.Overwrite)
                        {
                            AnsiConsole.MarkupLine($"Output file {settings.OutputFile.EscapeMarkup()}.txt already exists. Use -o if you want to overwrite it.");
                            return;
                        }

                        File.Delete(settings.OutputFile);
                    }
                }
                else
                {
                    if (Directory.Exists(settings.OutputFile))
                    {
                        if (!settings.Overwrite && Directory.EnumerateFiles(settings.OutputFile).Any())
                        {
                            AnsiConsole.MarkupLine($"Output directory {settings.OutputFile.EscapeMarkup()} already exists and is not empty. Use -o if you want to overwrite files.");
                            return;
                        }
                    }
                    else
                    {
                        Directory.CreateDirectory(settings.OutputFile);
                    }
                }


                var timer = Stopwatch.StartNew();
                ProgressTask progressTask = ctx.AddTask("[green]Hash ranges downloaded[/]", true, 1024 * 1024);
                Task processTask = ProcessRanges(settings);

                do
                {
                    progressTask.Value = _statistics.HashesDownloaded;
                    ctx.Refresh();
                    await Task.Delay(100).ConfigureAwait(false);
                }
                while (!processTask.IsCompleted);

                _statistics.ElapsedMilliseconds = timer.ElapsedMilliseconds;
                progressTask.Value = _statistics.HashesDownloaded;
                ctx.Refresh();
                progressTask.StopTask();
            });

        processingTask.Wait();
        AnsiConsole.MarkupLine($"Finished downloading all hash ranges in {_statistics.ElapsedMilliseconds:N0}ms ({_statistics.HashesPerSecond:N2} hashes per second).");
        AnsiConsole.MarkupLine($"We made {_statistics.CloudflareRequests:N0} Cloudflare requests (avg response time: {(double)_statistics.CloudflareRequestTimeTotal / _statistics.CloudflareRequests:N2}ms). Of those, Cloudflare had already cached {_statistics.CloudflareHits:N0} requests, and made {_statistics.CloudflareMisses:N0} requests to the HaveIBeenPwned origin server.");

        return 0;
    }

    private static HttpClient InitializeHttpClient()
    {
        var handler = new HttpClientHandler();

        if (handler.SupportsAutomaticDecompression)
        {
            handler.AutomaticDecompression = DecompressionMethods.All;
            handler.SslProtocols = System.Security.Authentication.SslProtocols.Tls13 | System.Security.Authentication.SslProtocols.Tls12;
        }

        HttpClient client = new(handler) { BaseAddress = new Uri("https://api.pwnedpasswords.com/range/"), DefaultRequestVersion = HttpVersion.Version20 };
        string? process = Environment.ProcessPath;
        if (process != null)
        {
            client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("hibp-downloader", FileVersionInfo.GetVersionInfo(process).ProductVersion));
        }

        return client;
    }

    private async Task<Stream> GetPwnedPasswordsRangeFromWeb(int i)
    {
        var cloudflareTimer = Stopwatch.StartNew();
        string requestUri = GetHashRange(i);
        HttpResponseMessage response = await _policy.ExecuteAsync(() =>
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, requestUri);
            return _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead);
        }).ConfigureAwait(false);
        Stream content = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
        Interlocked.Add(ref _statistics.CloudflareRequestTimeTotal, cloudflareTimer.ElapsedMilliseconds);
        Interlocked.Increment(ref _statistics.CloudflareRequests);
        if (response.Headers.TryGetValues("CF-Cache-Status", out IEnumerable<string>? values) && values != null)
        {
            switch (values.FirstOrDefault())
            {
                case "HIT":
                    Interlocked.Increment(ref _statistics.CloudflareHits);
                    break;
                default:
                    Interlocked.Increment(ref _statistics.CloudflareMisses);
                    break;
            };
        }

        return content;
    }

    private string GetHashRange(int i)
    {
        Span<byte> bytes = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(bytes, i);
        return Convert.ToHexString(bytes)[3..];
    }

    private async Task ProcessRanges(Settings settings)
    {
        if (settings.SingleFile)
        {
            Channel<Task<Stream>> downloadTasks = Channel.CreateBounded<Task<Stream>>(new BoundedChannelOptions(settings.Parallelism) { SingleReader = true, SingleWriter = true });
            using var file = new FileStream($"{settings.OutputFile}.txt", FileMode.Append, FileAccess.Write, FileShare.None, 4096, true);

            Task producerTask = StartDownloads(downloadTasks.Writer);
            await foreach (Task<Stream> item in downloadTasks.Reader.ReadAllAsync().ConfigureAwait(false))
            {
                string prefix = GetHashRange(_statistics.HashesDownloaded++);
                using Stream inputStream = await item.ConfigureAwait(false);
                using var writer = new StreamWriter(file, leaveOpen: true);
                await foreach (string line in inputStream.ParseLinesAsync().ConfigureAwait(false))
                {
                    await writer.WriteLineAsync($"{prefix}{line}");
                }

                await writer.FlushAsync().ConfigureAwait(false);
            }

            await producerTask.ConfigureAwait(false);
        }
        else
        {
            Task[] downloadTasks = new Task[settings.Parallelism];
            for (int i = 0; i < downloadTasks.Length; i++)
            {
                downloadTasks[i] = DownloadRangeToFile(settings.OutputFile);
            }

            await Task.WhenAll(downloadTasks).ConfigureAwait(false);
        }
    }

    private async Task StartDownloads(ChannelWriter<Task<Stream>> channelWriter)
    {
        for (int i = 0; i < 1024 * 1024; i++)
        {
            await channelWriter.WriteAsync(GetPwnedPasswordsRangeFromWeb(i)).ConfigureAwait(false);
        }

        channelWriter.Complete();
    }

    private async Task DownloadRangeToFile(string outputDirectory)
    {
        int nextHash = Interlocked.Increment(ref _hashesInProgress);
        int currentHash = nextHash - 1;
        while (currentHash < 1024 * 1024)
        {
            using Stream stream = await GetPwnedPasswordsRangeFromWeb(currentHash).ConfigureAwait(false);
            using var file = new FileStream(Path.Combine(outputDirectory, $"{GetHashRange(currentHash)}.txt"), FileMode.Create, FileAccess.Write, FileShare.None, 64 * 1024, true);
            await stream.CopyToAsync(file).ConfigureAwait(false);
            await file.FlushAsync().ConfigureAwait(false);
            Interlocked.Increment(ref _statistics.HashesDownloaded);
            nextHash = Interlocked.Increment(ref _hashesInProgress);
            currentHash = nextHash - 1;
        }
    }
}
