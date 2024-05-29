using System.Buffers.Binary;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Http.Headers;
using System.Threading.Channels;

using HaveIBeenPwned.PwnedPasswords;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Win32.SafeHandles;

using Polly;
using Polly.Retry;

using Spectre.Console;
using Spectre.Console.Cli;

IHostBuilder host = CreateHostBuilder(args);

var registrar = new TypeRegistrar(host);

var app = new CommandApp<PwnedPasswordsDownloader>(registrar);

app.Configure(config => config.PropagateExceptions());

try
{
    return await app.RunAsync(args);
}
catch (Exception ex)
{
    AnsiConsole.WriteException(ex, ExceptionFormats.ShortenEverything);
    return -99;
}

static IHostBuilder CreateHostBuilder(string[] args) =>
    Host
    .CreateDefaultBuilder(args)
    .ConfigureServices((hostContext, services) =>
    {
        IHttpClientBuilder clientBuilder = services.AddHttpClient("PwnedPasswords");
        clientBuilder.AddResilienceHandler("retry", b =>
        {
            b.AddRetry(new RetryStrategyOptions<HttpResponseMessage> { MaxRetryAttempts = 10, OnRetry = OnRequestErrorAsync });
        });
        clientBuilder.ConfigurePrimaryHttpMessageHandler(() =>
        {
            var handler = new HttpClientHandler();

            if (handler.SupportsAutomaticDecompression)
            {
                handler.AutomaticDecompression = DecompressionMethods.All;
                handler.SslProtocols = System.Security.Authentication.SslProtocols.Tls13 | System.Security.Authentication.SslProtocols.Tls12;
            }

            return handler;
        })
        .ConfigureHttpClient(client =>
        {
            client.BaseAddress = new Uri("https://api.pwnedpasswords.com/range/");
            string? process = Environment.ProcessPath;
            if (process != null)
            {
                client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("hibp-downloader", FileVersionInfo.GetVersionInfo(process).ProductVersion));
            }

#if NET7_0_OR_GREATER
            client.DefaultRequestVersion = HttpVersion.Version30;
            client.DefaultVersionPolicy = HttpVersionPolicy.RequestVersionOrLower;
#endif
        });
    });

static ValueTask OnRequestErrorAsync(OnRetryArguments<HttpResponseMessage> args)
{
    string requestUri = args.Outcome.Result?.RequestMessage?.RequestUri?.ToString() ?? "";
    AnsiConsole.MarkupLine(args.Outcome.Exception != null
        ? $"[yellow]Failed request #{args.AttemptNumber} while fetching {requestUri}. Exception message: {args.Outcome.Exception.Message}.[/]"
        : $"[yellow]Failed attempt #{args.AttemptNumber} while fetching {requestUri}. Response contained HTTP Status code {args.Outcome.Result?.StatusCode}.[/]");
    if (args.Outcome.Exception != null)
    {
        AnsiConsole.WriteException(args.Outcome.Exception, ExceptionFormats.ShortenEverything);
    }

    return ValueTask.CompletedTask;
}

internal sealed class Statistics
{
    public int HashesDownloaded;
    public int CloudflareRequests;
    public int CloudflareHits;
    public int CloudflareMisses;
    public long CloudflareRequestTimeTotal;
    public long ElapsedMilliseconds;
    public double HashesPerSecond => HashesDownloaded / (ElapsedMilliseconds / 1000.0);
}

internal sealed class PwnedPasswordsDownloader : Command<PwnedPasswordsDownloader.Settings>
{
    private readonly Statistics _statistics = new();
    private readonly HttpClient _httpClient;

    public PwnedPasswordsDownloader(Statistics statistics, IHttpClientFactory httpClientFactory)
    {
        _statistics = statistics;
        _httpClient = httpClientFactory.CreateClient("PwnedPasswords");
    }

    public sealed class Settings : CommandSettings
    {
        [Description("Name of the output. Defaults to pwnedpasswords, which writes the output to pwnedpasswords.txt for single file output, or a directory called pwnedpasswords.")]
        [CommandArgument(0, "[outputFile]")]
        public string OutputFile { get; init; } = "pwnedpasswords";

        [Description("The number of parallel requests to make to Have I Been Pwned to download the hash ranges. If omitted or less than 2, defaults to eight times the number of processors on the machine.")]
        [CommandOption("-p||--parallelism")]
        [DefaultValue(0)]
        public int Parallelism { get; set; }

        [Description("When set, overwrite any existing files while writing the results. Defaults to false.")]
        [CommandOption("-o|--overwrite")]
        [DefaultValue(false)]
        public bool Overwrite { get; set; } = false;

        [Description("When set, writes the hash ranges into a single .txt file. Otherwise downloads ranges to individual files into a subfolder. If ommited defaults to single file.")]
        [CommandOption("-s|--single")]
        [DefaultValue(true)]
        public bool SingleFile { get; set; } = true;

        [Description("When set, fetches NTLM hashes instead of SHA1.")]
        [CommandOption("-n|--ntlm")]
        [DefaultValue(false)]
        public bool FetchNtlm { get; set; } = false;
    }

    public override int Execute([NotNull]CommandContext context, [NotNull]Settings settings)
    {
        if (settings.Parallelism < 2)
        {
            settings.Parallelism = Math.Max(Environment.ProcessorCount * 8, 2);
        }

        Task processingTask = AnsiConsole.Progress()
            .AutoRefresh(false) // Turn off auto refresh
            .AutoClear(false)   // Do not remove the task list when done
            .HideCompleted(false)   // Hide tasks as they are completed
            .Columns(new TaskDescriptionColumn(), new ProgressBarColumn(), new PercentageColumn(), new RemainingTimeColumn(), new SpinnerColumn())
            .StartAsync(async ctx =>
            {
                if (settings.SingleFile)
                {
                    if (File.Exists($"{settings.OutputFile}.txt"))
                    {
                        if (!settings.Overwrite)
                        {
                            AnsiConsole.MarkupLine($"Output file {settings.OutputFile.EscapeMarkup()}.txt already exists. Use -o if you want to overwrite it.");
                            return;
                        }

                        File.Delete($"{settings.OutputFile}.txt");
                    }
                }
                else
                {
                    if (!Directory.Exists(settings.OutputFile))
                    {
                        Directory.CreateDirectory(settings.OutputFile);
                    }

                    if (!settings.Overwrite && Directory.EnumerateFiles(settings.OutputFile).Any())
                    {
                        AnsiConsole.MarkupLine($"Output directory {settings.OutputFile.EscapeMarkup()} already exists and is not empty. Use -o if you want to overwrite files.");
                        return;
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

                if (processTask.Exception is not null && processTask.Exception.InnerException is not null)
                {
                    AnsiConsole.WriteException(processTask.Exception.InnerException);
                }

                _statistics.ElapsedMilliseconds = timer.ElapsedMilliseconds;
                progressTask.Value = _statistics.HashesDownloaded;
                ctx.Refresh();
                progressTask.StopTask();
            });

        processingTask.Wait();
        AnsiConsole.MarkupLine($"Finished downloading all hash ranges in {_statistics.ElapsedMilliseconds:N0}ms ({_statistics.HashesPerSecond:N2} hashes per second).");
        AnsiConsole.MarkupLine($"We made {_statistics.CloudflareRequests:N0} Cloudflare requests (avg response time: {(double)_statistics.CloudflareRequestTimeTotal / _statistics.CloudflareRequests:N2}ms). Of those, Cloudflare had already cached {_statistics.CloudflareHits:N0} requests, and made {_statistics.CloudflareMisses:N0} requests to the Have I Been Pwned origin server.");

        return 0;
    }

    private async Task<Stream> GetPwnedPasswordsRangeFromWeb(int i, bool fetchNtlm)
    {
        var cloudflareTimer = Stopwatch.StartNew();
        string requestUri = GetHashRange(i);
        if (fetchNtlm)
        {
            requestUri += "?mode=ntlm";
        }

        HttpResponseMessage response = await _httpClient.GetAsync(requestUri);
        Stream content = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
        Interlocked.Add(ref _statistics.CloudflareRequestTimeTotal, cloudflareTimer.ElapsedMilliseconds);
        Interlocked.Increment(ref _statistics.CloudflareRequests);
        if (!response.Headers.TryGetValues("CF-Cache-Status", out IEnumerable<string>? values))
        {
            return content;
        }

        switch (values.FirstOrDefault())
        {
            case "HIT":
                Interlocked.Increment(ref _statistics.CloudflareHits);
                break;
            default:
                Interlocked.Increment(ref _statistics.CloudflareMisses);
                break;
        }

        return content;
    }

    private static string GetHashRange(int i)
    {
        Span<byte> bytes = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(bytes, i);
        return Convert.ToHexString(bytes)[3..];
    }

    private async Task ProcessRanges(Settings settings)
    {
        if (settings.SingleFile)
        {
            Channel<Task<Stream>> downloadTasks = Channel.CreateBounded<Task<Stream>>(new BoundedChannelOptions(settings.Parallelism) { SingleReader = true, SingleWriter = true, AllowSynchronousContinuations = true });
            await using FileStream file = File.Open($"{settings.OutputFile}.txt", new FileStreamOptions { Access = FileAccess.Write, BufferSize = 32767, Mode = FileMode.Create, Options = FileOptions.Asynchronous, Share = FileShare.None });
            await using StreamWriter writer = new(file);
            Task producerTask = StartDownloads(downloadTasks.Writer, settings.FetchNtlm);
            await foreach (Task<Stream> item in downloadTasks.Reader.ReadAllAsync().ConfigureAwait(false))
            {
                string prefix = GetHashRange(_statistics.HashesDownloaded++);
                await using Stream inputStream = await item.ConfigureAwait(false);
                using StreamReader reader = new(inputStream);
                while (await reader.ReadLineAsync() is { } line)
                {
                    if (line.Length > 0)
                    {
                        await writer.WriteLineAsync($"{prefix}{line}");
                    }
                }

                await writer.FlushAsync();
            }

            await producerTask.ConfigureAwait(false);
        }
        else
        {
            await Parallel.ForEachAsync(EnumerateRanges(), new ParallelOptions
            {
                MaxDegreeOfParallelism = settings.Parallelism,
                TaskScheduler = TaskScheduler.Default
            }, async (i, _) =>
            {
                await DownloadRangeToFile(i, settings.OutputFile, settings.FetchNtlm).ConfigureAwait(false);
            });
        }
    }

    private static IEnumerable<int> EnumerateRanges()
    {
        for (int i = 0; i < 1024*1024; i++)
        {
            yield return i;
        }
    }

    private async Task StartDownloads(ChannelWriter<Task<Stream>> channelWriter, bool fetchNtlm)
    {
        try
        {
            foreach(int i in EnumerateRanges())
            {
                await channelWriter.WriteAsync(GetPwnedPasswordsRangeFromWeb(i, fetchNtlm));
            }

            channelWriter.TryComplete();
        }
        catch (Exception e)
        {
            channelWriter.TryComplete(e);
        }
    }

    private async Task DownloadRangeToFile(int currentHash, string outputDirectory, bool fetchNtlm)
    {
        await using Stream stream = await GetPwnedPasswordsRangeFromWeb(currentHash, fetchNtlm).ConfigureAwait(false);
        using SafeFileHandle handle = File.OpenHandle(Path.Combine(outputDirectory, $"{GetHashRange(currentHash)}.txt"), FileMode.Create, FileAccess.Write,
            FileShare.None, FileOptions.Asynchronous);
        await handle.CopyFrom(stream).ConfigureAwait(false);
        Interlocked.Increment(ref _statistics.HashesDownloaded);
    }
}

public sealed class TypeRegistrar : ITypeRegistrar
{
    private readonly IHostBuilder _builder;
    public TypeRegistrar(IHostBuilder builder) => _builder = builder;
    public ITypeResolver Build() => new TypeResolver(_builder.Build());
    public void Register(Type service, Type implementation) => _builder.ConfigureServices((_, services) => services.AddSingleton(service, implementation));
    public void RegisterInstance(Type service, object implementation) => _builder.ConfigureServices((_, services) => services.AddSingleton(service, implementation));
    public void RegisterLazy(Type service, Func<object> func)
    {
        ArgumentNullException.ThrowIfNull(func);
        _builder.ConfigureServices((_, services) => services.AddSingleton(service, _ => func()));
    }
}
public sealed class TypeResolver : ITypeResolver, IDisposable
{
    private readonly IHost _host;
    public TypeResolver(IHost provider) => _host = provider ?? throw new ArgumentNullException(nameof(provider));
    public object? Resolve(Type? type) => type != null ? _host.Services.GetService(type) : null;
    public void Dispose() => _host.Dispose();
}
