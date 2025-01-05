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
        server.Setup();

        try
        {
            // Run the server loop on a separate task
            var serverTask = Task.Run(() => server.Loop(stoppingToken), stoppingToken);

            // Wait for the cancellation request
            await Task.Delay(Timeout.Infinite, stoppingToken);
        }
        catch (TaskCanceledException)
        {
            Console.WriteLine("Task was canceled.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Unhandled exception: {ex.Message}");
        }
        finally
        {
            Console.WriteLine("Server shutting down...");
        }
    }


}