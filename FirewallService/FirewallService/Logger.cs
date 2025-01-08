using Microsoft.Extensions.Logging;

namespace FirewallService
{
    public static class Logger
    {
        private static ILogger? _logger;

        public static void Initialize(ILogger logger)
        {
            _logger = logger;
        }

        public static void Info(string message, params object[] args)
        {
            _logger?.LogInformation(message, args);
        }

        public static void Error(string message, params object[] args)
        {
            _logger?.LogError(message, args);
        }

        public static void Debug(string message, params object[] args)
        {
            _logger?.LogDebug(message, args);
        }
    }
}