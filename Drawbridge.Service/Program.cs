using Drawbridge.Core;
using Drawbridge.Service;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

bool cleanupMode = args.Any(argument =>
    string.Equals(argument, "--cleanup", StringComparison.OrdinalIgnoreCase));
bool consoleMode = args.Any(argument =>
    string.Equals(argument, "--console", StringComparison.OrdinalIgnoreCase));

if (cleanupMode)
{
    bool cleaned = SystemIntegration.FullCleanup(message => Console.WriteLine($"[cleanup] {message}"));
    if (!cleaned)
    {
        Environment.ExitCode = 1;
    }

    return;
}

string[] hostArguments = args
    .Where(argument => !string.Equals(argument, "--console", StringComparison.OrdinalIgnoreCase))
    .ToArray();

string? dataRootOverride = consoleMode ? GetOption(args, "--data-root") : null;
int dnsPort = consoleMode ? GetPortOption(args, "--dns-port", 53) : 53;
int controlApiPort = consoleMode ? GetPortOption(args, "--api-port", 8054) : 8054;

var paths = dataRootOverride is null
    ? new DrawbridgePaths()
    : new DrawbridgePaths(dataRootOverride);
paths.EnsureCreated();
bool dataRootWasEmpty = paths.WasEmptyBeforeEnsureCreated;

var blocklists = new BlocklistService(paths);
var blockLog = new BlockLogService(paths);
blockLog.Load();
var pin = new PinService(paths);
var dns = new DnsServer(blocklists, new DnsServerOptions { ListenPort = dnsPort });
var webMonitor = new WebMonitorService(
    pin,
    blockLog,
    () => dns.IsRunning,
    () => blocklists.BlockedDomainCount,
    () => blocklists.Mode,
    paths);
bool defaultDnsRouting = ServiceStartupPolicy.DefaultDnsRouting(dataRootOverride);
var serviceConfig = new ServiceConfigurationStore(
    paths,
    dataRootWasEmpty,
    defaultDnsRouting,
    recoverLegacyRouting: paths.LegacyEmptyDaclRepairPerformed && defaultDnsRouting);
var recentLogs = new RecentLogBuffer(paths.LogsDirectory);
var runtimeOptions = new ServiceRuntimeOptions(controlApiPort);

IHost host = Host.CreateDefaultBuilder(hostArguments)
    .UseWindowsService(options => options.ServiceName = "DrawbridgeService")
    .ConfigureLogging(logging =>
    {
        logging.SetMinimumLevel(LogLevel.Information);
        logging.AddFilter<Microsoft.Extensions.Logging.EventLog.EventLogLoggerProvider>(
            level => level >= LogLevel.Information);
        logging.AddProvider(new RollingFileLoggerProvider(paths.LogsDirectory, recentLogs));

        if (!consoleMode && OperatingSystem.IsWindows())
        {
            logging.AddEventLog(settings =>
            {
                settings.LogName = "Application";
                settings.SourceName = "DrawbridgeService";
            });
        }
    })
    .ConfigureServices(services =>
    {
        services.AddSingleton(paths);
        services.AddSingleton(blocklists);
        services.AddSingleton(blockLog);
        services.AddSingleton(pin);
        services.AddSingleton(dns);
        services.AddSingleton(webMonitor);
        services.AddSingleton(serviceConfig);
        services.AddSingleton(recentLogs);
        services.AddSingleton(runtimeOptions);
        services.AddSingleton<BridgeController>();
        services.AddSingleton<SystemChangeCoordinator>();
        services.AddSingleton<MigrationCoordinator>();
        services.AddHostedService<DrawbridgeWorker>();
        services.AddHostedService<ControlApiService>();
    })
    .Build();

await host.RunAsync();

static string? GetOption(string[] arguments, string name)
{
    for (int index = 0; index < arguments.Length; index++)
    {
        string argument = arguments[index];
        if (argument.StartsWith(name + "=", StringComparison.OrdinalIgnoreCase))
        {
            return argument[(name.Length + 1)..];
        }

        if (string.Equals(argument, name, StringComparison.OrdinalIgnoreCase) &&
            index + 1 < arguments.Length)
        {
            return arguments[index + 1];
        }
    }

    return null;
}

static int GetPortOption(string[] arguments, string name, int fallback)
{
    string? value = GetOption(arguments, name);
    if (value is null)
    {
        return fallback;
    }

    if (!int.TryParse(value, out int port) || port is < 1 or > 65535)
    {
        throw new ArgumentException($"{name} must be a TCP/UDP port from 1 through 65535.");
    }

    return port;
}
