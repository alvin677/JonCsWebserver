using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO.Pipelines;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WebServer
{
    public class BandwidthLimiterMiddleware
    {
        private readonly RequestDelegate _next;
        private static readonly ConcurrentDictionary<string, BandwidthTracker> _trackers = new();
        public BandwidthLimiterMiddleware(RequestDelegate next) => _next = next;
        public async Task Invoke(HttpContext context)
        {
            string ip = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            var tracker = _trackers.GetOrAdd(ip, _ => new BandwidthTracker(Startup.config.MaxBytesPerSecond));
            var originalBody = context.Features.Get<IHttpResponseBodyFeature>()!;
            var throttledBody = new ThrottledResponseBody(originalBody, tracker);
            context.Features.Set<IHttpResponseBodyFeature>(throttledBody);
            await _next(context);
            context.Features.Set(originalBody);
        }
    }
    public class BandwidthTracker
    {
        private readonly long _maxBytesPerSecond;
        private long _bytesThisSecond;
        private long _windowStart;
        public BandwidthTracker(long maxBytesPerSecond)
        {
            _maxBytesPerSecond = maxBytesPerSecond;
            _windowStart = Stopwatch.GetTimestamp();
        }
        public async ValueTask ThrottleAsync(int bytes, CancellationToken ct)
        {
            long now = Stopwatch.GetTimestamp();
            long elapsed = now - _windowStart;
            if (elapsed >= Stopwatch.Frequency) // new second
            {
                Interlocked.Exchange(ref _bytesThisSecond, 0);
                Interlocked.Exchange(ref _windowStart, now);
            }
            long total = Interlocked.Add(ref _bytesThisSecond, bytes);
            if (total > _maxBytesPerSecond)
            {
                // calculate how long to wait until next window
                long remaining = Stopwatch.Frequency - (Stopwatch.GetTimestamp() - _windowStart);
                int delayMs = (int)(remaining * 1000 / Stopwatch.Frequency);
                if (delayMs > 0)
                    await Task.Delay(delayMs, ct);
            }
        }
    }

    public class ThrottledResponseBody : IHttpResponseBodyFeature
    {
        private readonly IHttpResponseBodyFeature _inner;
        private readonly BandwidthTracker _tracker;
        public ThrottledResponseBody(IHttpResponseBodyFeature inner, BandwidthTracker tracker)
        {
            _inner = inner;
            _tracker = tracker;
            Writer = inner.Writer; // PipeWriter passthrough
        }
        public Stream Stream => _inner.Stream;
        public PipeWriter Writer { get; }
        public Task StartAsync(CancellationToken ct = default) => _inner.StartAsync(ct);
        public Task SendFileAsync(string path, long offset, long? count, CancellationToken ct = default)
            => _inner.SendFileAsync(path, offset, count, ct);
        public Task CompleteAsync() => _inner.CompleteAsync();
        public void DisableBuffering() => _inner.DisableBuffering();
        public async Task WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default)
        {
            await _tracker.ThrottleAsync(buffer.Length, ct);
            await _inner.Stream.WriteAsync(buffer, ct);
        }
    }
}
