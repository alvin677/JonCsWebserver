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
        private static readonly ConcurrentQueue<string> Queue = new();
        private static readonly AutoResetEvent Signal = new(false);

        static FastFileLogger()
        {
            Thread t = new(WriterLoop)
            {
                IsBackground = true,
                Name = "FastFileLogger"
            };
            t.Start();
        }

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

            string msg = formatter(state, exception);

            Queue.Enqueue(
                $"[{DateTimeOffset.UtcNow:O}] [{logLevel}] {msg}\n{exception}\n"
            );

            Signal.Set();
        }
        private static void WriterLoop()
        {
            using var fs = new FileStream(
                "./joncserror.log",
                FileMode.Append,
                FileAccess.Write,
                FileShare.ReadWrite,
                1 << 16);

            using var sw = new StreamWriter(fs, Encoding.UTF8, 1 << 16);

            List<string> batch = new(256);

            while (true)
            {
                Signal.WaitOne();

                while (Queue.TryDequeue(out string? s))
                    batch.Add(s);

                for (int i = 0; i < batch.Count; i++)
                    sw.WriteLine(batch[i]);

                sw.Flush();
                batch.Clear();
            }
        }
    }
}
