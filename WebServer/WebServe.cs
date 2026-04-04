using CSScripting;
using CSScriptLib;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Components.RenderTree;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Http.Timeouts;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.ResponseCompression;
using Microsoft.AspNetCore.WebSockets;
using Microsoft.CodeAnalysis;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Primitives;
using Microsoft.Win32.SafeHandles;
using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Frozen;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq.Expressions;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Net.WebSockets;
using System.Reflection;
using System.Reflection.PortableExecutable;
using System.Runtime.CompilerServices;
using System.Runtime.Loader;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading.RateLimiting;
using Wasmtime;
using static System.Net.Mime.MediaTypeNames;

namespace WebServer
{
    public class Startup
    {
        const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        const string error404 = "<!DOCTYPE HTML><html><head><title>Err 404 Page not found</title><link href=\"/main.css\" rel=\"stylesheet\"/><meta name=\"viewport\" content=\"width=device-width,initial-scale=1.0\"/></head><body><center><span style=\"font-size:24\">Error 404</span><h1 color=red>Page not found</h1><br/><img src=\"//jonhosting.com/JonHost.png\"/><br/><p>Please wait. Maybe we are working on loading or adding this page.</p>${0}<br/><div style=\"display:inline-table;\"><iframe style=\"margin:auto\" src=\"https://discordapp.com/widget?id=473863639347232779&theme=dark\" width=\"350\" height=\"500\" allowtransparency=\"true\" frameborder=\"0\"></iframe><iframe style=\"margin:auto\" src=\"https://discordapp.com/widget?id=670549627455668245&theme=dark\" width=\"350\" height=\"500\" allowtransparency=\"true\" frameborder=\"0\"></iframe></div></center><br/><ul style=\"display:inline-block;float:right\"><li style='display:inline-block;background-image:url(\"/social-icons.png\");background-position:0px;'><a href=\"https://twitter.com/JonTVme\" style=\"display:block;text-indent:-9999px;width:25px;height:25px;\">Twitter</a></li><li style='display:inline-block;background-image:url(\"/social-icons.png\");background-position:--25px;'><a href=\"https://facebook.com/realJonTV\" style=\"display:block;text-indent:-9999px;width:25px;height:25px;\">Facebook</a></li><li style='display:inline-block;background-image:url(\"/social-icons.png\");background-position:-50px'><a href=\"https://reddit.com/r/JonTV\" style=\"display:block;text-indent:-9999px;width:25px;height:25px;\">Reddit</a></li><li style='display:inline-block;background-image:url(\"/social-icons.png\");background-position:-75px'><a href=\"https://discord.gg/4APyyak\" style=\"display:block;text-indent:-9999px;width:25px;height:25px;\">Discord server</a></li></ul><br/><sup><em>Did you know that you're old?</em></sup></body></html>";
        public static string WWWdir = "";
        public static string BackendDir = "/var/www";
        public static Config config = new Config();
        public static readonly ConcurrentDictionary<string, long[]> FileIndex = new ConcurrentDictionary<string, long[]>(StringComparer.OrdinalIgnoreCase);
        public readonly struct EndpointEntry
        {
            public readonly Func<HttpContext, string, Task> Handler;
            public readonly string FilePath;
            public readonly string[]? ContentTypeHeaders; // precomputed ctype array, or null

            public EndpointEntry(Func<HttpContext, string, Task> handler, string filePath, string[]? contentTypeHeaders)
            {
                Handler = handler;
                FilePath = filePath;
                ContentTypeHeaders = contentTypeHeaders;
            }
            public EndpointEntry(Func<HttpContext, string, Task> handler, string filePath)
            {
                Handler = handler;
                FilePath = filePath;

                // Precompute content-type headers at index time
                int dot = filePath.LastIndexOf('.');
                if (dot >= 0)
                {
                    string ext = filePath[(dot + 1)..];
                    config.OptExtTypes.TryGetValue(ext, out ContentTypeHeaders);
                }
                else
                {
                    ContentTypeHeaders = null;
                }
            }
        }

        public static readonly ConcurrentDictionary<ulong, EndpointEntry> FileLead = new();
        public static readonly Dictionary<string, RequestDelegate> ErrorDict = new Dictionary<string, RequestDelegate>(StringComparer.OrdinalIgnoreCase);
        public static ConcurrentDictionary<string, Dictionary<string,string>> Sessions = new ConcurrentDictionary<string, Dictionary<string,string>>(StringComparer.OrdinalIgnoreCase);
        private static readonly Dictionary<string, Func<HttpContext, string, Task>> Extensions = new Dictionary<string, Func<HttpContext, string, Task>>(StringComparer.OrdinalIgnoreCase);
        private static readonly ConcurrentDictionary<string, HashSet<string>> reverseSymlinkMap = new ConcurrentDictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        private static readonly ConcurrentDictionary<string, HotReloadContext> LiveAssemblies = new ConcurrentDictionary<string, HotReloadContext>(StringComparer.OrdinalIgnoreCase);
        private static readonly ConcurrentDictionary<ulong, HtaccessRules> HtaccessMap = new(); // Store per-directory
        private static Timer _cleanupTimer = new Timer(_ => Sessions.Clear(), null, TimeSpan.Zero, TimeSpan.FromMinutes(config.ClearSessEveryXMin));
        private FileSystemWatcher watcher = new FileSystemWatcher { };
        public static FastCGIClient FastCGI = new FastCGIClient();
        public static ParallelOptions paralleloptions = new ParallelOptions
        {
            MaxDegreeOfParallelism = Environment.ProcessorCount > 12 ? Environment.ProcessorCount / 2 : Environment.ProcessorCount
        };
        public static int GetDictLenA() => reverseSymlinkMap.Count;
        public static int GetDictLenB() => LiveAssemblies.Count;
        public static int GetDictLenC() => HtaccessMap.Count;
        public static int GetDictLenD() => _pending.Count;

        static int defaultHeaderCount = 0;
        static string[] defaultHeaderKeys = new string[0];
        static string[] defaultHeaderValues = new string[0];
        public class DeflateCompressionProvider : ICompressionProvider
        {
            public string EncodingName => "deflate";

            public bool SupportsFlush => true;

            public Stream CreateStream(Stream outputStream)
            {
                return new DeflateStream(outputStream, Startup.config.CompressionLevel, leaveOpen: true);
            }
        }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddRouting();
            services.AddWebSockets(config => {
                config.KeepAliveInterval = TimeSpan.FromSeconds(Startup.config.WebSocketTimeout);
            });
            // services.AddSingleton<BackgroundTaskQueue>();
            // services.AddHostedService<Worker>();

            services.AddResponseCompression(options =>
            {
                options.EnableForHttps = true;
                options.Providers.Add<GzipCompressionProvider>();
                options.Providers.Add<BrotliCompressionProvider>();
                options.Providers.Add<DeflateCompressionProvider>();
            });

            services.Configure<GzipCompressionProviderOptions>(options =>
            {
                options.Level = Startup.config.CompressionLevel;
            });
            if (Startup.config.Logging) services.AddHttpLogging(options => { });
            if (Startup.config.RateLimitReq != 0)
                services.AddRateLimiter(options => { });
            if(Startup.config.RequestTimeout != 0)
                services.AddRequestTimeouts(options =>
                {
                    options.DefaultPolicy = new RequestTimeoutPolicy
                    {
                        Timeout = TimeSpan.FromSeconds(Startup.config.RequestTimeout),
                        TimeoutStatusCode = StatusCodes.Status504GatewayTimeout
                    };
                });
        }
        public void Configure(IApplicationBuilder app)
        {
            if (WWWdir != "")
            {
                app.UseStaticFiles(new StaticFileOptions
                {
                    FileProvider = new PhysicalFileProvider(Path.Combine(WWWdir)) //,
                                                                                          //RequestPath = "/"
                });
            }
            if (config.RequestTimeout != 0) 
                app.UseRequestTimeouts();
            if (config.MaxBytesPerSecond != 0)
                app.UseMiddleware<BandwidthLimiterMiddleware>();
            if (config.Logging) app.UseHttpLogging();
            if (config.DebugPages) app.UseDeveloperExceptionPage();
            if (config.ServerMetrics)
                app.Use(async (context, next) => {
                    Interlocked.Increment(ref Program.totalRequests);
                    await next(context);
                });
            if (config.RateLimitReq != 0)
            {
                var rate = new RateLimiterOptions();
                rate.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
                rate.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>
                    RateLimitPartition.GetTokenBucketLimiter(
                        context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                        _ => new TokenBucketRateLimiterOptions
                        {
                            TokenLimit = config.RateLimitReq,
                            ReplenishmentPeriod = TimeSpan.FromSeconds(config.RateLimitTime),
                            TokensPerPeriod = config.RateLimitRefill,
                            AutoReplenishment = true,
                            QueueLimit = config.RateLimitQueue
                        }));
                app.UseRateLimiter(rate);
            }
            app.UseResponseCompression();

            if (BackendDir != "")
            {
                if (!BackendDir.EndsWith('/')) // need to perform the check here for the check above to be valid
                    BackendDir += '/'; // avoid per-req addition
                // ReadOnlyMemory<char> BackendDirMemory = BackendDir.AsMemory();
                app.UseWebSockets();
                app.UseRouting();
                app.UseEndpoints(endpoints =>
                {
                    endpoints.Map("/{**catchAll}", async context =>
                     {
                         var hostValue = context.Request.Host.Value!; // while .Host is nullable, it is always set in this case. Checking for .HasValue would probably waste a CPU cycle.
                         if (config.DomainAlias.TryGetValue(hostValue, out string? OtherDomain)) // Whether this is true may vary greatly on WebAdmin, can be used for www.example.com -> example.com
                         {
                             context.Request.Host = new HostString(OtherDomain);
                             hostValue = OtherDomain;
                         }
                         ReadOnlySpan<char> _host = StripPort(hostValue.AsSpan()); // example.com:8080 -> example.com
                         string? filteredHost = null;
                         ReadOnlySpan<char> hostSpan;
                         if (config.DomainFilterEnabled) // Optional domain filter
                         {
                             filteredHost = _host.ToString().Replace(config.FilterFromDomain, config.DomainFilterTo); // Store into a string to prevent GC issues.
                             hostSpan = filteredHost.AsSpan(); // hostSpan example.com -> examplecom (example)
                         }
                         else hostSpan = _host;
                         ReadOnlySpan<char> _path = context.Request.Path.Value.AsSpan();

                         // Build hash incrementally — no buffer, no slashPositions needed
                         const ulong FNV_OFFSET = 14695981039346656037UL;
                         const ulong FNV_PRIME = 1099511628211UL;

                         ulong hash = FNV_OFFSET;

                         // Hash host (already case-folded by StripPort/filter)
                         for (int k = 0; k < hostSpan.Length; k++)
                         {
                             char c = hostSpan[k];
                             c |= (char)((uint)(c - 'A') <= 25 ? 32 : 0);
                             hash = (hash ^ c) * FNV_PRIME;
                         }

                         // ulong key = HashHostAndPath(hostSpan, _path); // skip string concat
                         if (config.UrlAliasHash.Count != 0 && config.UrlAliasHash.TryGetValue(HashHostAndPath(hash, _path), out string? newPath)) // rarely true. Only if webadmin has added values // (hash, _path) -> use the hash that is already done.
                         {
                             context.Request.Path = new PathString(newPath); // needed for C#-endpoints
                             _path = newPath.AsSpan(); // update the span used directly below
                         }

                         // Per-segment hash accumulation + snapshot after each segment
                         Span<ulong> slashHashes = stackalloc ulong[config.MaxDirDepth + 4];
                         int slashCount = 0;

                         int i = _path.Length > 0 && _path[0] == '/' ? 1 : 0;
                         while (i < _path.Length)
                         {
                             if (_path[i] == '/') { i++; continue; }

                             int segStart = i;
                             while (i < _path.Length && _path[i] != '/') i++;

                             ReadOnlySpan<char> segment = _path.Slice(segStart, i - segStart);

                             if (segment.Length != 2 || segment[0] != '.' || segment[1] != '.')
                             {
                                 if (slashCount >= slashHashes.Length)
                                 {
                                     context.Response.StatusCode = StatusCodes.Status414RequestUriTooLong;
                                     return;
                                 }

                                 // Snapshot hash before this segment (for fallback to parent directory)
                                 slashHashes[slashCount++] = hash;

                                 // Fold in '/' + segment chars
                                 hash = (hash ^ '/') * FNV_PRIME;
                                 for (int k = 0; k < segment.Length; k++)
                                 {
                                     char c = segment[k];
                                     c |= (char)((uint)(c - 'A') <= 25 ? 32 : 0);
                                     hash = (hash ^ c) * FNV_PRIME;
                                 }
                             }
                             // no i++ — handled by leading check
                         }

                         // hash now represents the full path
                         var headers = context.Response.Headers;
                         if (FileLead.TryGetValue(hash, out var entry))
                         {
                             for (int j = 0; j < defaultHeaderCount; j++)
                                 headers[defaultHeaderKeys[j]] = defaultHeaderValues[j];

                             if (entry.ContentTypeHeaders != null)
                                 for (int j = 0; j < entry.ContentTypeHeaders.Length; j += 2)
                                     headers[entry.ContentTypeHeaders[j]] = entry.ContentTypeHeaders[j + 1];

                             await entry.Handler(context, entry.FilePath);
                             return;
                         }
                         else if (config.LoopFindEndpoint)
                         {
                             for (int s = slashCount - 1; s >= 0; s--)
                             {
                                 if (FileLead.TryGetValue(slashHashes[s], out entry))
                                 {
                                     for (int j = 0; j < defaultHeaderCount; j++)
                                         headers[defaultHeaderKeys[j]] = defaultHeaderValues[j];

                                     if (entry.ContentTypeHeaders != null)
                                         for (int j = 0; j < entry.ContentTypeHeaders.Length; j += 2)
                                             headers[entry.ContentTypeHeaders[j]] = entry.ContentTypeHeaders[j + 1];

                                     await entry.Handler(context, entry.FilePath);
                                     return;
                                 }
                             }
                         }

                         // .htaccess support // Reuses hash, should have minimal overhead.
                         if (config.EnableHtaccess && HtaccessMap.TryGetValue(slashHashes[slashCount > 0 ? slashCount - 1 : 0], out var htRules))
                         {
                             if (htRules.DenyAll)
                             {
                                 context.Response.StatusCode = StatusCodes.Status403Forbidden;
                                 return;
                             }

                             string reqPath = context.Request.Path.Value ?? "/";

                             foreach (var redirect in htRules.Redirects)
                             {
                                 if (redirect.Pattern.IsMatch(reqPath))
                                 {
                                     context.Response.StatusCode = redirect.StatusCode;
                                     headers.Location = redirect.Target;
                                     return;
                                 }
                             }

                             foreach (var rewrite in htRules.Rewrites)
                             {
                                 // Evaluate conditions
                                 bool condsPass = true;
                                 foreach (var cond in rewrite.Conditions)
                                 {
                                     string testVal = ResolveTestString(cond.TestString, context);
                                     bool matched;

                                     if (cond.IsFileExists)
                                         matched = File.Exists(testVal);
                                     else if (cond.IsDirExists)
                                         matched = Directory.Exists(testVal);
                                     else if (cond.IsFileSymlink)
                                         matched = (File.GetAttributes(testVal) & FileAttributes.ReparsePoint) != 0;
                                     else
                                         matched = cond.Pattern?.IsMatch(testVal) ?? false;

                                     if (cond.Negate) matched = !matched;
                                     if (!matched) { condsPass = false; break; }
                                 }
                                 if (!condsPass) continue;

                                 var match = rewrite.Pattern.Match(reqPath);
                                 if (!match.Success) continue;

                                 string rewPath = rewrite.Pattern.Replace(reqPath, rewrite.Replacement);

                                 if (rewrite.IsRedirect)
                                 {
                                     context.Response.StatusCode = rewrite.RedirectCode;
                                     headers.Location = rewPath;
                                     return;
                                 }

                                 // Internal rewrite — update path and re-lookup
                                 context.Request.Path = new PathString(rewPath);
                                 if (rewrite.IsLast) break;
                             }

                             foreach (var (key, value) in htRules.Headers)
                                 headers[key] = value;
                         }

                         context.Response.StatusCode = StatusCodes.Status404NotFound;
                         if (ErrorDict.TryGetValue(hostValue, out var errHandler))
                         {
                             await errHandler(context);
                             return;
                         }
                         await context.Response.WriteAsync(error404);
                     });
                });

                Reload();
                Task.Run(() =>
                {
                    IndexFiles(BackendDir);
                    IndexDirectories(BackendDir);
                    IndexErrorPages(BackendDir);
                });
                SetupFileWatcher(BackendDir);
            }
        }

        public void Reload()
        {
            foreach (KeyValuePair<string, string> ext in config.ForwardExt)
            {
                Extensions[ext.Key] = (context, path) =>
                {
                    string targetUrl = ext.Value.Replace("{domain}", context.Request.Host.Value!.Split(':')[0]) + context.Request.Path.Value + context.Request.QueryString.Value;
                    return ForwardRequestTo(context, targetUrl);
                };
            }
            Reload2();
        }
        public static void Reload2()
        {
            defaultHeaderKeys = new string[config.DefaultHeaders.Count];
            defaultHeaderValues = new string[config.DefaultHeaders.Count];
            int idx = 0;
            foreach (var kv in config.DefaultHeaders)
            {
                defaultHeaderKeys[idx] = kv.Key;
                defaultHeaderValues[idx] = kv.Value;
                idx++;
            }
            defaultHeaderCount = defaultHeaderKeys.Length;

            foreach (string ext in config.DownloadIfExtension) Extensions[ext] = DefDownload;
            if (config.Enable_PHP)
            {
                FastCGI = new FastCGIClient(config.PHP_FPM); //.Split(":")[0], int.Parse(Startup.config.PHP_FPM.Split(":")[1]));
            }

            httpClient.Timeout = TimeSpan.FromSeconds(config.HttpProxyTimeout);
            handler.SslProtocols = System.Security.Authentication.SslProtocols.Tls12;
            handler.AllowAutoRedirect = false;
            if (!config.ForceTLS)
            {
                handler.ServerCertificateCustomValidationCallback = IgnoreCert;
                handler.CheckCertificateRevocationList = false;
            }
            else handler.ServerCertificateCustomValidationCallback = null;

            string customLibPath = Path.Combine(AppContext.BaseDirectory, "deps");
            CSScript.GlobalSettings.AddSearchDir(customLibPath);
            /*
            try
            {
                CSScript.RoslynEvaluator.Reset(true);
                CSScript.EvaluatorConfig.ReferenceDomainAssemblies = false;
                CSScript.Evaluator.DisableReferencingFromCode = true;

                foreach (string dll in Directory.GetFiles(customLibPath, "*.dll"))
                {
                    try
                    {
                        CSScript.Evaluator.ReferenceAssembly(dll);
                        Console.WriteLine(dll + " added to CSScript.Evaluator Assembly-References");
                    }
                    catch (Exception e) { Console.WriteLine(dll + " failed: \n" + e.ToString()); }
                }
                // CSScript.GlobalSettings.ClearSearchDirs();
                CSScript.GlobalSettings.AddSearchDir(customLibPath);
                CSScript.Evaluator.ReferenceAssembly("System");
            }
            catch (Exception e) { Console.WriteLine(e.Message); }
            */
            Console.WriteLine("Need references for ._cs files? Add referenced libraries (.dll) to " + customLibPath);
        }
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ReadOnlySpan<char> StripPort(ReadOnlySpan<char> host)
        {
            int colon = host.IndexOf(':');
            return colon >= 0 ? host[..colon] : host;
        }
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static string ExtractDomain(string folder)
        {
            int lastSlash = folder.LastIndexOf('/');
            return lastSlash >= 0 ? folder[(lastSlash + 1)..] : folder;
        }

        // Sequential FNV-1a: host then path
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ulong HashHostAndPath(ReadOnlySpan<char> host, ReadOnlySpan<char> path)
        {
            ulong hash = 14695981039346656037UL; // FNV-1a offset basis

            for (int i = 0; i < host.Length; i++)
            {
                char c = host[i];
                // Branch-free ASCII lowercase: only OR 32 if 'A' <= c <= 'Z'
                c |= (char)((uint)(c - 'A') <= 25 ? 32 : 0);
                hash = (hash ^ c) * 1099511628211UL;
            }

            for (int i = 0; i < path.Length; i++)
            {
                char c = path[i];
                // If you want path to be case-sensitive, skip this line
                c |= (char)((uint)(c - 'A') <= 25 ? 32 : 0);
                hash = (hash ^ c) * 1099511628211UL;
            }

            return hash;
        }
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ulong HashHostAndPath(ulong hash, ReadOnlySpan<char> path)
        {
            for (int i = 0; i < path.Length; i++)
            {
                char c = path[i];
                // If you want path to be case-sensitive, skip this line
                c |= (char)((uint)(c - 'A') <= 25 ? 32 : 0);
                hash = (hash ^ c) * 1099511628211UL;
            }
            return hash;
        }
        public static async Task StreamFileUsingBodyWriter(HttpContext context, string file, long start, long length)
        {
            const int bufferSize = 16384; // 16 KB chunks
            System.IO.Pipelines.PipeWriter bodyWriter = context.Response.BodyWriter;

            using SafeFileHandle handle = File.OpenHandle(file, FileMode.Open, FileAccess.Read, FileShare.Read, FileOptions.Asynchronous);

            long offset = start;
            long remaining = length;
            while (remaining > 0)
            {
                int toRead = remaining > bufferSize ? bufferSize : (int)remaining;
                var memory = bodyWriter.GetMemory(toRead).Slice(0, toRead);
                int bytesRead = await RandomAccess.ReadAsync(handle, memory, offset);
                if (bytesRead == 0) break; // End of file

                bodyWriter.Advance(bytesRead);
                offset += bytesRead;
                remaining -= bytesRead;

                var flushResult = await bodyWriter.FlushAsync();
                if (flushResult.IsCanceled || flushResult.IsCompleted) break;
            }

            // await bodyWriter.CompleteAsync();
        }

        public static async Task DefHandle(HttpContext context, string file)
        {
            if (context.Request.Method == HttpMethods.Options)
            {
                context.Response.StatusCode = StatusCodes.Status204NoContent;
                return;
            }
            if (FileIndex.TryGetValue(file, out long[]? LastMod))
            {
                context.Response.Headers["last-modified"] = DateTimeOffset.FromUnixTimeSeconds(LastMod[0]).ToString("R");
                if (DateTimeOffset.TryParseExact(
                    context.Request.Headers.IfModifiedSince,
                    "R",                          // RFC1123, e.g. "Mon, 10 Nov 2025 14:16:20 GMT"
                    System.Globalization.CultureInfo.InvariantCulture,
                    System.Globalization.DateTimeStyles.None,
                    out DateTimeOffset ifModifiedSince))
                {
                    if (LastMod[0] <= ifModifiedSince.ToUnixTimeSeconds())
                    {
                        context.Response.StatusCode = StatusCodes.Status304NotModified;
                        return;
                    }
                }
                if (context.Request.Headers.TryGetValue("Range", out var rangeHeader))
                {
                    string range = rangeHeader.ToString();
                    if (range.StartsWith("bytes=") && RangeHeaderValue.TryParse(range, out var parsedRange))
                    {
                        var firstRange = parsedRange.Ranges.First();
                        long start = firstRange.From ?? 0;
                        long end = firstRange.To ?? LastMod[1] - 1;
                        if (start >= LastMod[1] || end >= LastMod[1] || start > end)
                        {
                            context.Response.StatusCode = StatusCodes.Status416RangeNotSatisfiable;
                            context.Response.Headers["Content-Range"] = "bytes */" + LastMod[1]; // No valid range
                            return;
                        }
                        long contentLength = end - start + 1;
                        if (contentLength != LastMod[1]) // only chunk if not requesting whole file
                        {
                            context.Response.StatusCode = StatusCodes.Status206PartialContent;
                            context.Response.ContentLength = contentLength;
                            context.Response.Headers["Content-Range"] = "bytes " + start + "-" + end + "/" + LastMod[1];
                            if (context.Request.Method == HttpMethods.Head) return;
                            await StreamFileUsingBodyWriter(context, file, start, contentLength);
                            return;
                        }
                    }
                }
                context.Response.ContentLength = LastMod[1];
            }
            if (context.Request.Method == HttpMethods.Head) return;
            await context.Response.SendFileAsync(file);
        }
        private static async Task DefDownload(HttpContext context, string file)
        {
            int slash = file.LastIndexOf('/');
            string fn = slash >= 0 ? file[(slash + 1)..] : "undefined";
            context.Response.Headers["content-disposition"] = "attachment; filename=" + fn;
            await DefHandle(context, file);
        }
        private static HttpClientHandler handler = new HttpClientHandler {
            UseCookies = false
        };
        private static readonly HttpClient httpClient = new HttpClient(handler);
        private static bool IgnoreCert(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors)
        {
            return true;
        }
        private async Task ForwardRequestTo(HttpContext context, string targetUrl)
        {
            if (config.MaxRequestBodySize != null && context.Request.ContentLength > config.MaxRequestBodySize)
            {
                context.Response.StatusCode = StatusCodes.Status413PayloadTooLarge;
                return;
            }
            try
            {
                if (context.WebSockets.IsWebSocketRequest)
                {
                    WebSocket webSocket = await context.WebSockets.AcceptWebSocketAsync();
                    ClientWebSocket client = new ClientWebSocket();
                    client.Options.CollectHttpResponseDetails = true;
                    //client.Options.HttpVersion = HttpVersion.Version11;
                    //client.Options.HttpVersionPolicy = HttpVersionPolicy.RequestVersionOrHigher;
                    SocketsHttpHandler websockethandler = new SocketsHttpHandler
                    {
                        SslOptions = { EnabledSslProtocols = SslProtocols.Tls12, RemoteCertificateValidationCallback = IgnoreCert },
                        EnableMultipleHttp2Connections = true
                    };
                    client.Options.KeepAliveInterval = TimeSpan.FromSeconds(config.WebSocketEndpointTimeout);
                    websockethandler.ConnectTimeout = TimeSpan.FromSeconds(config.WebSocketEndpointTimeout);
                    websockethandler.CookieContainer = new CookieContainer();
                    websockethandler.Credentials = client.Options.Credentials;
                    /*
                    context.Request.Headers.ForEach((header) => {
                        client.Options.SetRequestHeader(header.Key, header.Value);
                        Console.WriteLine(header.Key +  ": " + header.Value);
                    });
                    */
                    client.Options.SetRequestHeader("X-Forwarded-For", context.Connection.RemoteIpAddress?.ToString());
                    
                    //client.Options.Cookies = new CookieContainer();
                    string Domain = context.Request.Host.Value!.Split(":")[0];
                    context.Request.Cookies.ForEach((cookie) => {
                        Cookie cook = new Cookie(cookie.Key, cookie.Value);
                        try
                        {
                            cook.Domain = Domain;
                            websockethandler.CookieContainer.Add(cook);
                            //client.Options.Cookies.Add(cook);
                        }
                        catch (Exception){}
                    });
                    // client.Options.Cookies = CopyCookies;
                    try
                    {
                        HttpMessageInvoker invoker = new HttpMessageInvoker(websockethandler);
                        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(config.WebSocketEndpointTimeout));
                        await client.ConnectAsync(new Uri(targetUrl.Replace("https:", "wss:").Replace("http:", "ws:")), invoker, cts.Token);
                    }
                    catch(Exception){
                        // Console.WriteLine("Error proxying websocket: \n" + e.ToString());
                        client.Dispose();
                        webSocket.Abort();
                        context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
                        return;
                    }
                    // context.Response.StatusCode = (int)client.HttpStatusCode;
                    await PipeSockets(webSocket, client);
                    return;
                }
                HttpRequestMessage requestMessage = new HttpRequestMessage
                {
                    Method = new HttpMethod(context.Request.Method),
                    RequestUri = new Uri(targetUrl),
                    Version = HttpVersion.Version30,
                    VersionPolicy = HttpVersionPolicy.RequestVersionOrLower
                    // Content = new StreamContent(context.Request.Body)
                };
                if (context.Request.Method != HttpMethods.Get && context.Request.Method != HttpMethods.Head && context.Request.Method != HttpMethods.Options)
                {
                    // context.Request.EnableBuffering();
                    // context.Request.Body.Position = 0;
                    requestMessage.Headers.TransferEncodingChunked = true;
                    requestMessage.Content = new StreamContent(context.Request.Body);
                    if (context.Request.ContentType != null)
                    {
                        string[] contentType = context.Request.ContentType.Split(';');
                        string mediaType = contentType[0].Trim(); // e.g., "text/plain"
                        string? charset = contentType.Length > 1 ? contentType[1].Trim() : null; // e.g., "charset=UTF-8"

                        var mediaTypeHeader = new MediaTypeHeaderValue(mediaType);
                        if (charset != null)
                        {
                            mediaTypeHeader.CharSet = charset.Substring(charset.IndexOf('=') + 1);
                        }

                        requestMessage.Content.Headers.ContentType = mediaTypeHeader;
                    }
                }

                foreach (var header in context.Request.Headers)
                {
                    requestMessage.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray());
                }
                if (!requestMessage.Headers.Contains("cookie")) // patch edge-case from reusing Httpclient
                {
                    requestMessage.Headers.TryAddWithoutValidation("cookie", "");
                }
                requestMessage.Headers.TryAddWithoutValidation(":authority", requestMessage.RequestUri.Host.Split(":")[0]);
                requestMessage.Headers.TryAddWithoutValidation(":path", context.Request.Path + context.Request.QueryString);
                requestMessage.Headers.TryAddWithoutValidation(":method", context.Request.Method);
                requestMessage.Headers.TryAddWithoutValidation(":scheme", context.Request.Scheme);
                string? UserIp = context.Connection.RemoteIpAddress?.ToString();
                if (context.Request.Headers.TryGetValue("X-Forwarded-For", out StringValues val))
                {
                    requestMessage.Headers.TryAddWithoutValidation("X-Forwarded-For", val + "," + UserIp);
                }
                else
                {
                    requestMessage.Headers.TryAddWithoutValidation("X-Forwarded-For", UserIp);
                }
                requestMessage.Headers.TryAddWithoutValidation("CF-Connecting-IP", UserIp);

                using (HttpResponseMessage responseMessage = await httpClient.SendAsync(requestMessage, HttpCompletionOption.ResponseHeadersRead))
                {
                    context.Response.StatusCode = (int)responseMessage.StatusCode;
                    foreach (var header in responseMessage.Headers)
                    {
                        context.Response.Headers[header.Key] = header.Value.ToArray();
                    }
                    foreach (var header in responseMessage.Content.Headers)
                    {
                        context.Response.Headers[header.Key] = header.Value.ToArray();
                    }
                    // Stream the response body back to the client
                    using (var responseStream = await responseMessage.Content.ReadAsStreamAsync())
                    {
                        await responseStream.CopyToAsync(context.Response.Body);
                    }
                }
                return;
            }
            catch (Exception e)
            {
                context.Response.StatusCode = StatusCodes.Status500InternalServerError;
                context.Response.Headers.Remove("Cache-Control");
                await context.Response.WriteAsync("Sorry. An error occurred.");
                Console.Error.WriteLine(e.Message);
                return;
            }
        }
        private async Task PipeSockets(WebSocket webSocket, ClientWebSocket clientWebSocket) // user, proxyClient
        {
            // User -> C# -> Endpoint
            Task serverToClient = Task.Run(async () =>
            {
                byte[] buff = new byte[1024];
                ArraySegment<byte> buffer = new ArraySegment<byte>(buff);
                while (webSocket.State == WebSocketState.Open && clientWebSocket.State == WebSocketState.Open)
                {
                    WebSocketReceiveResult result = await webSocket.ReceiveAsync(buffer, CancellationToken.None);

                    if (result.MessageType == WebSocketMessageType.Close)
                    {
                        await clientWebSocket.CloseAsync(WebSocketCloseStatus.NormalClosure, "Closed by client", CancellationToken.None);
                        break;
                    }

                    await clientWebSocket.SendAsync(new ArraySegment<byte>(buff, 0, result.Count), result.MessageType, result.EndOfMessage, CancellationToken.None);
                }
                Console.WriteLine("Proxy websock kestrel->endpoint closed.");
            });

            // Endpoint -> C# -> Client
            Task clientToServer = Task.Run(async () =>
            {
                byte[] buff = new byte[8192];
                ArraySegment<byte> buffer = new ArraySegment<byte>(buff);
                while (webSocket.State == WebSocketState.Open && clientWebSocket.State == WebSocketState.Open)
                {
                    WebSocketReceiveResult result = await clientWebSocket.ReceiveAsync(buffer, CancellationToken.None);

                    if (result.MessageType == WebSocketMessageType.Close)
                    {
                        await webSocket.CloseAsync(WebSocketCloseStatus.NormalClosure, "Closed by server", CancellationToken.None);
                        break;
                    }

                    await webSocket.SendAsync(new ArraySegment<byte>(buff, 0, result.Count), result.MessageType, result.EndOfMessage, CancellationToken.None);
                }
                Console.WriteLine("Proxy websock endpoint->kestrel closed.");
            });

            // Wait for either direction to close.
            await Task.WhenAny(serverToClient, clientToServer);
        }

        public static void IndexFiles(string rootDirectory)
        {
            var files = Directory.EnumerateFiles(rootDirectory, "*.*", SearchOption.AllDirectories);
            var partitioner = Partitioner.Create(files, EnumerablePartitionerOptions.NoBuffering);

            Parallel.ForEach(partitioner, paralleloptions, file =>
            {
                IndexFile(file.Replace(Path.DirectorySeparatorChar, '/'));
            });
        }
        public static void IndexFile(string file)
        {
            int dotIdx = file.LastIndexOf('.');
            string Ext = dotIdx >= 0 ? file[(dotIdx + 1)..] : "";
            if (config.Enable_CS)
            {
                if (Ext == "_cs")
                {
                    try { CompileAndAddFunction(file); } catch (Exception e) { Console.ForegroundColor = ConsoleColor.Red; Console.WriteLine(file + "\n" + e); Console.ResetColor(); }
                    return;
                }
                else if (Ext == "_csdll")
                {
                    try { LoadCompiledFunc(file); } catch (Exception e) { Console.ForegroundColor = ConsoleColor.Red; Console.WriteLine(file + "\n" + e); Console.ResetColor(); }
                    return;
                }
            }
            if (config.Enable_PHP)
            {
                if (Ext == "php")
                {
                    try {
                        AddToFileLead(file, FastCGI.Run);
                        //if (GenPhpAssembly(file)) LoadPhpAssembly(file); 
                    } catch (Exception e) { Console.ForegroundColor = ConsoleColor.Red; Console.WriteLine(file + "\n" + e); Console.ResetColor(); }
                    return;
                }
                else if (Ext == "phpdll")
                {
                    try { LoadPhpAssembly(file); } catch (Exception e) { Console.ForegroundColor = ConsoleColor.Red; Console.WriteLine(file + "\n" + e); Console.ResetColor(); }
                    return;
                }
            }
            if(config.Enable_WASM)
            {
                if(Ext == "_wasm")
                {
                    try
                    {
                        LoadWasm(file);
                    }
                    catch (Exception e) { Console.ForegroundColor = ConsoleColor.Red; Console.WriteLine(file + "\n" + e); Console.ResetColor(); }
                    return;
                }
            }
            if (Extensions.TryGetValue(Ext, out var Handler))
            {
                AddToFileLead(file, Handler);
                if (Handler == DefDownload) CacheFileInfo(file);
            }
            else
            {
                AddToFileLead(file, DefHandle);
                CacheFileInfo(file);
            }
        }
        public static void CacheFileInfo(string file) {
            try
            {
                FileInfo fileInfo = ThruSymlinks(file);
                if(fileInfo != null) FileIndex[file] = new long[] { ((DateTimeOffset)fileInfo.LastWriteTimeUtc).ToUnixTimeSeconds(), fileInfo.Length };
            }catch(Exception){
                RemoveFromFileLead(file); // no func = error 404
            } // non-existing files throw err
        }
        static FileInfo ThruSymlinks(string file)
        {
            HashSet<string> Symlinks = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            FileInfo fileInfo = new FileInfo(file);
            if(fileInfo.LinkTarget == null) // is real file
            {
                if(reverseSymlinkMap.TryGetValue(file, out HashSet<string>? Linked))
                {
                    foreach(string symlink in Linked) // Update all files linking to this file
                    {
                        string target = symlink;
                        if (target.StartsWith(BackendDir))
                        {
                            target = target.Substring(BackendDir.Length); // Resolve relative to the symlink's directory
                        }
                        CacheFileInfo(target); // Update metadata for the symlink
                    }
                }
                return fileInfo;
            }
            while(fileInfo.LinkTarget != null) // find real file
            {
                string target = fileInfo.LinkTarget;
                if (!Path.IsPathRooted(target))
                {
                    target = Path.Combine(fileInfo.DirectoryName ?? "", target); // Resolve relative to the symlink's directory
                }
                target = Path.GetFullPath(target).Replace(Path.DirectorySeparatorChar, '/');
                if(Symlinks.Contains(target))
                {
                    Console.WriteLine("[WARN] Infinite symlink loop detected for file: " + file);
                    break;
                }
                Symlinks.Add(target);
                fileInfo = new FileInfo(target);
            }
            string realFile = fileInfo.FullName.Replace(Path.DirectorySeparatorChar, '/');
            if (realFile.StartsWith(BackendDir))
            {
                realFile = realFile.Substring(BackendDir.Length); // Resolve relative to the symlink's directory
            }
            reverseSymlinkMap[realFile] = Symlinks;
            return fileInfo;
        }
        public static void IndexDirectories(string rootDirectory)
        {
            foreach (string Folder in Directory.EnumerateDirectories(rootDirectory, "*", SearchOption.AllDirectories)) {
                IndexDirectory(Folder.Replace(Path.DirectorySeparatorChar, '/'));
            }
        }
        public static void IndexDirectory(string Folder)
        {
            if (Folder.Length <= BackendDir.Length) return; // guard against malformed paths

            ulong folderHash = HashSpan(Folder.AsSpan(BackendDir.Length));
            bool any = false;

            foreach (string file in config.indexPriority)
            {
                string tmpfile = Path.Combine(Folder, file).Replace(Path.DirectorySeparatorChar, '/');
                ulong tmpHash = HashSpan(tmpfile.AsSpan(BackendDir.Length));

                if (FileLead.TryGetValue(tmpHash, out var existingEntry))
                {
                    FileLead[folderHash] = existingEntry; // reuse entire entry — same handler, path, content-type
                    any = true;
                    break;
                }
            }

            if (!any)
                FileLead.TryRemove(folderHash, out _);

            if (config.EnableHtaccess)
            {
                string htaccessPath = Path.Combine(Folder, ".htaccess").Replace(Path.DirectorySeparatorChar, '/');
                HtaccessRules? htaccess = HtaccessParser.Parse(htaccessPath);
                if (htaccess != null)
                    HtaccessMap[folderHash] = htaccess;
                else
                    HtaccessMap.TryRemove(folderHash, out _);
            }
        }
        private static string ResolveTestString(string testString, HttpContext context) =>
            testString.ToUpperInvariant() switch
            {
                "%{REQUEST_FILENAME}" => Path.Combine(BackendDir,
                                             context.Request.Host.Value?.Split(':')[0] ?? "",
                                             context.Request.Path.Value?.TrimStart('/') ?? ""),
                "%{REQUEST_URI}" => context.Request.Path.Value + context.Request.QueryString,
                "%{QUERY_STRING}" => context.Request.QueryString.Value ?? "",
                "%{HTTP_HOST}" => context.Request.Host.Value ?? "",
                "%{REMOTE_ADDR}" => context.Connection.RemoteIpAddress?.ToString() ?? "",
                "%{REQUEST_METHOD}" => context.Request.Method,
                "%{HTTPS}" => context.Request.IsHttps ? "on" : "off",
                "%{SERVER_NAME}" => context.Request.Host.Host,
                "%{SERVER_PORT}" => context.Request.Host.Port?.ToString() ?? (context.Request.IsHttps ? "443" : "80"),
                "%{HTTP_REFERER}" => context.Request.Headers.Referer.ToString(),
                "%{HTTP_USER_AGENT}" => context.Request.Headers.UserAgent.ToString(),
                _ => testString
            };
        public static void IndexErrorPages(string rootDirectory)
        {
            foreach (string folder in Directory.EnumerateDirectories(rootDirectory, "*", SearchOption.TopDirectoryOnly))
                IndexErrorPage(folder.Replace(Path.DirectorySeparatorChar, '/'));
        }
        public static void IndexErrorPage(string Folder)
        {
            string tmpfile = Path.Combine(Folder, "error404.html").Replace(Path.DirectorySeparatorChar, '/');
            ulong tmpHash = HashSpan(tmpfile.AsSpan(BackendDir.Length));

            if (!FileLead.TryGetValue(tmpHash, out _)) return; // error404.html not indexed

            string dom = ExtractDomain(Folder);
            ulong folderHash = HashSpan(Folder.AsSpan(BackendDir.Length));

            try
            {
                string errcontent = File.ReadAllText(tmpfile);
                string[] parts = errcontent.Split("${0}");
                bool hasPlaceholder = parts.Length > 1;

                if (hasPlaceholder)
                {
                    ErrorDict[dom] = async context =>
                    {
                        await context.Response.WriteAsync(parts[0]);
                        if (!string.IsNullOrEmpty(context.Request.Headers.Referer))
                            await context.Response.WriteAsync(context.Request.Headers.Referer!);
                        await context.Response.WriteAsync(parts[1]);
                    };

                    if (!FileLead.ContainsKey(folderHash))
                    {
                        Func<HttpContext, string, Task> fallback = async (context, path) =>
                        {
                            context.Response.StatusCode = StatusCodes.Status404NotFound;
                            await context.Response.WriteAsync(parts[0]);
                            if (!string.IsNullOrEmpty(context.Request.Headers.Referer))
                                await context.Response.WriteAsync(context.Request.Headers.Referer!);
                            await context.Response.WriteAsync(parts[1]);
                        };
                        FileLead[folderHash] = new EndpointEntry(fallback, Folder, null);
                    }
                }
                else
                {
                    ErrorDict[dom] = async context =>
                        await context.Response.WriteAsync(errcontent);

                    if (!FileLead.ContainsKey(folderHash))
                    {
                        FileLead[folderHash] = new EndpointEntry(
                            async (context, path) => await context.Response.WriteAsync(errcontent),
                            Folder,
                            null);
                    }
                }
            }
            catch (Exception) { }
        }
        public static void AddToFileLead(string fullPath, Func<HttpContext, string, Task> handler)
        {
            if (fullPath.Length <= BackendDir.Length) return;
            // Strip BackendDir — constant prefix, excluded from hash to match hot path
            ReadOnlySpan<char> relative = fullPath.AsSpan(BackendDir.Length);
            ulong hash = HashSpan(relative);
            // Collision detection — fire at index time, zero hot path cost
            if (FileLead.TryGetValue(hash, out var existing)
                && !string.Equals(existing.FilePath, fullPath, StringComparison.OrdinalIgnoreCase))
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"[WARN] Hash collision: {fullPath} collides with {existing.FilePath} — skipping");
                Console.ResetColor();
                return;
            } // Same file re-indexed (e.g. file watcher update) — fall through and overwrite
            FileLead[hash] = new EndpointEntry(handler, fullPath);
        }
        public static void RemoveFromFileLead(string file)
        {
            if (file.Length <= BackendDir.Length) return;
            ulong hash = HashSpan(file.AsSpan(BackendDir.Length));
            FileLead.TryRemove(hash, out _);
        }
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ulong HashSpan(ReadOnlySpan<char> data)
        {
            ulong hash = 14695981039346656037UL;
            for (int i = 0; i < data.Length; i++)
            {
                char c = data[i];
                // Branch-free ASCII lowercase — valid for ASCII paths only
                // Non-ASCII domain names would need UTF-8 encoding first
                c |= (char)((uint)(c - 'A') <= 25 ? 32 : 0);
                hash = (hash ^ c) * 1099511628211UL;
            }
            return hash;
        }

        void SetupFileWatcher(string rootDirectory)
        {
            watcher = new FileSystemWatcher
            {
                Path = rootDirectory,
                IncludeSubdirectories = true,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.CreationTime
            };
            watcher.Filter = "*";

            watcher.Created += (sender, e) => OnFileEvent(e.FullPath.Replace(Path.DirectorySeparatorChar, '/'));
            watcher.Changed += (sender, e) => OnFileEvent(e.FullPath.Replace(Path.DirectorySeparatorChar, '/'));
            watcher.Deleted += (sender, e) => RemoveFromIndex(e.FullPath.Replace(Path.DirectorySeparatorChar, '/'));
            watcher.Renamed += (sender, e) =>
            {
                RemoveFromIndex(e.OldFullPath.Replace(Path.DirectorySeparatorChar, '/'));
                OnFileEvent(e.FullPath.Replace(Path.DirectorySeparatorChar, '/'));
            };

            watcher.EnableRaisingEvents = true;
        }

        private static readonly ConcurrentDictionary<string, long> _pending = new();
        private static readonly long debounceTicks = TimeSpan.FromMilliseconds(50).Ticks;
        void OnFileEvent(string path)
        {
            long now = Stopwatch.GetTimestamp();
            _pending[path] = now;

            ThreadPool.QueueUserWorkItem(__ =>
            {
                Thread.Sleep(50);
                if (_pending.TryGetValue(path, out var last) &&
                    Stopwatch.GetTimestamp() - last >= debounceTicks)
                {
                    _pending.TryRemove(path, out _);
                    UpdateIndex(path); // or LoadCompiledFunc for _csdll
                }
            });
        }

        static void UpdateIndex(string filePath)
        {
            if (File.Exists(filePath))
            {
                IndexFile(filePath);
            }
            string? currFolder = Path.GetDirectoryName(filePath);
            if(currFolder != null) IndexDirectory(currFolder.Replace(Path.DirectorySeparatorChar, '/'));
        }

        static void RemoveFromIndex(string filePath)
        {
            if ((config.Enable_CS && filePath.EndsWith("._csdll")) || (config.Enable_PHP && filePath.EndsWith(".phpdll"))) filePath = filePath[..^3];
            FileIndex.TryRemove(filePath, out _);
            RemoveFromFileLead(filePath);
            if (LiveAssemblies.TryGetValue(filePath, out HotReloadContext? ctx))
            {
                ctx?.Unload();
                LiveAssemblies.TryRemove(filePath, out _);
            }
        }

        public static void CompileAndAddFunction(string filePath)
        {
            // Read the code from the file
            string code = File.ReadAllText(filePath);
            //CSScript.Evaluator.CompileAssemblyFromFile(filePath, filePath + "dll");
            try
            {
                CSScript.Evaluator.ReferenceAssembliesFromCode(code, [Path.Combine(AppContext.BaseDirectory, "deps")]);
            }
            catch (Exception) { }
            dynamic script = CSScript.Evaluator
                         .Eval(code);
            
            var runMethod = script.GetType().GetMethod("Run");
            if (runMethod != null)
            {
                var func = new Func<HttpContext, string, Task>((context, path) =>
                {
                    // Invoke the Run method asynchronously
                    return (Task)runMethod.Invoke(script, new object[] { context, path });
                });

                if (func != null) AddToFileLead(filePath, func);
            }
            
            // Extract the function from the result
            //Func<HttpContext, string, Task>? func = script.Run;
            //if (func != null) FileLead[filePath] = func;
        }

        public static void LoadCompiledFunc(string file)
        {
            string toFile = file[..^3];
            // Clear old Assembly from mem
            if (LiveAssemblies.TryGetValue(toFile, out HotReloadContext? ctx))
            {
                ctx?.Unload();
                LiveAssemblies.TryRemove(toFile, out _);
                /*
                FileLead.Remove(toFile, out _); // did not help
                GC.Collect();
                GC.WaitForPendingFinalizers();
                GC.Collect();
                */
            }
            string fullPath = Path.GetFullPath(file);
            HotReloadContext context = new HotReloadContext(fullPath);
            /*foreach (var dll in Directory.GetFiles("libs", "*.dll"))
            {
                context.LoadFromAssemblyPath(Path.GetFullPath(dll));
            }*/
            Assembly assembly = context.LoadFromAssemblyPath(fullPath);
            Type? type = assembly.GetType("Is_CsScript");
            if (type == null)
            {
                Console.WriteLine("Make sure to use the namespace/class Is_CsScript for ._csdll! File: " + file);
                context.Unload();
                return;
            }
            MethodInfo? method = type.GetMethod("Run");
            if (method == null)
            {
                Console.WriteLine("Add a function to " + file + ": public class Is_CsScript{ public static async Task Run(HttpContext context, string path) {} }");
                context.Unload();
                return;
            }
            Func<HttpContext, string, Task> func = (Func<HttpContext, string, Task>)Delegate.CreateDelegate(
    typeof(Func<HttpContext, string, Task>), method
);

            AddToFileLead(toFile, func); // ._csdll -> ._cs
            LiveAssemblies[toFile] = context;
        }
        public static void LoadWasm(string file)
        {
            var module = Wasm.Load(file);
            AddToFileLead(file, async (context, path) =>
            {
                using var store = new Store(Wasm.WasmEngine);
                var wasmCtx = new Wasm.WasmContext { Http = context };
                store.SetData(wasmCtx);
                var linker = Wasm.Init(store);

                var instance = linker.Instantiate(store, module);
                var memory = instance.GetMemory("memory");
                if (memory == null)
                {
                    context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
                    return;
                }
                wasmCtx.Memory = memory;

                var handle = instance.GetAction("handle");
                if (handle == null)
                {
                    context.Response.StatusCode = StatusCodes.Status501NotImplemented;
                    return;
                }
                handle();

                await context.Response.BodyWriter.FlushAsync();
            });
        }

        public static void LoadPhpAssembly(string filePath)
        {
            Assembly assembly = Assembly.LoadFrom(filePath + "dll");

            Type? type = assembly.GetType("Is_PhpScript"); // namespace/class name in your PHP file.
            if (type == null)
            {
                Console.WriteLine("Make sure to use the namespace Is_PhpScript for .phpdll-files!");
                return;
            }
            var method = type.GetMethod("Run"); // "Run" is the entry point.

            // Create a delegate for the method (this assumes it's compatible)
            Func<HttpContext, string, Task> phpFunction = (Func<HttpContext, string, Task>)Delegate.CreateDelegate(
                typeof(Func<HttpContext, string, Task>), method
            );

            AddToFileLead(filePath, phpFunction);
        }
        public static bool GenPhpAssembly(string filePath)
        {
            try
            {
                // Create a new process
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "ppc", // Assumes "ppc" is in your PATH
                        Arguments = filePath+" -o "+filePath+"dll",
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };

                // Capture output
                process.Start();
                string output = process.StandardOutput.ReadToEnd();
                string error = process.StandardError.ReadToEnd();
                process.WaitForExit();

                // Check if there were errors
                if (process.ExitCode != 0)
                {
                    return false;
                }

                // No errors, return success
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }
    }
}
