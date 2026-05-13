using Microsoft.Extensions.Logging;
using System.Collections.Concurrent;
using System.Text;

namespace WebServer
{
    public sealed class FastFileLoggerProvider : ILoggerProvider
    {
        public ILogger CreateLogger(string categoryName)
            => new FastFileLogger();

        public void Dispose() { }
    }
    public sealed class FastFileLogger : ILogger
    {
        private static readonly object Lock = new();

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel)
            => logLevel >= LogLevel.Error;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (logLevel < LogLevel.Error)
                return;

            string msg =
                $"[{DateTimeOffset.UtcNow:O}] [{logLevel}] " +
                $"{formatter(state, exception)}\n{exception}\n";

            lock (Lock)
            {
                File.AppendAllText("./joncserror.log", msg);
            }
        }
    }
}
