using FirewallService.ipc;
using Microsoft.Extensions.Logging;

namespace FirewallService;

public class Worker : BackgroundService
{
    private readonly ILogger<Worker> _logger;

    public Worker(ILogger<Worker> logger)
    {
        _logger = logger;
        Logger.Initialize(logger); // Initialize the static Log class
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var server = new Server();

        try
        {
            // Run the server loop on a separate task
            var serverTask = Task.Run(() => server.Loop(stoppingToken), stoppingToken);

            // Wait for the cancellation request
            await Task.Delay(Timeout.Infinite, stoppingToken);
        }
        catch (TaskCanceledException)
        {
            Logger.Warn("Task was canceled.");
        }
        catch (Exception ex)
        {
            Logger.Critical($"Unhandled exception: {ex.Message}");
        }
        finally
        {
            Logger.RegWrite("Server shutting down...");
        }
    }
}