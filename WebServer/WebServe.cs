using CSScripting;
using CSScriptLib;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Http.Timeouts;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.ResponseCompression;
using Microsoft.AspNetCore.WebSockets;
using Microsoft.CodeAnalysis;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Primitives;
using Microsoft.Win32.SafeHandles;
using System.Buffers;
using System.Collections.Concurrent;
using System.Diagnostics;
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
        const string error404 = "<!DOCTYPE HTML><html><head><title>Err 404 - page not found</title><link href=\"/main.css\" rel=\"stylesheet\" /><meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" /></head><body><center><span style=\"font-size:24\">Error 404</span><h1 color=red>Page not found</h1><br /><img src=\"//jonhosting.com/JonHost.png\" /><br /><p>Maybe we're working on adding this page.</p>${0}<br /><div style=\"display:inline-table;\"><iframe style=\"margin:auto\" src=\"https://discordapp.com/widget?id=473863639347232779&theme=dark\" width=\"350\" height=\"500\" allowtransparency=\"true\" frameborder=\"0\"></iframe><iframe style=\"margin:auto\" src=\"https://discordapp.com/widget?id=670549627455668245&theme=dark\" width=\"350\" height=\"500\" allowtransparency=\"true\" frameborder=\"0\"></iframe></div></center><br /><ul style=\"display:inline-block;float:right\"><li style='display:inline-block;background-image:url(\"/social-icons.png\");background-position:0px;'><a href=\"https://twitter.com/JonTVme\" style=\"display:block;text-indent:-9999px;width:25px;height:25px;\">Twitter</a></li><li style='display:inline-block;background-image:url(\"/social-icons.png\");background-position:--25px;'><a href=\"https://facebook.com/realJonTV\" style=\"display:block;text-indent:-9999px;width:25px;height:25px;\">Facebook</a></li><li style='display:inline-block;background-image:url(\"/social-icons.png\");background-position:-50px'><a href=\"https://reddit.com/r/JonTV\" style=\"display:block;text-indent:-9999px;width:25px;height:25px;\">Reddit</a></li><li style='display:inline-block;background-image:url(\"/social-icons.png\");background-position:-75px'><a href=\"https://discord.gg/4APyyak\" style=\"display:block;text-indent:-9999px;width:25px;height:25px;\">Discord server</a></li></ul><br /><sup><em>Did you know that you're old?</em></sup></body></html>";
        public static readonly ConcurrentDictionary<string, long[]> FileIndex = new ConcurrentDictionary<string, long[]>(StringComparer.OrdinalIgnoreCase);
        public static readonly ConcurrentDictionary<string, Func<HttpContext, string, Task>> FileLead = new ConcurrentDictionary<string, Func<HttpContext, string, Task>>(StringComparer.OrdinalIgnoreCase);
        public static ConcurrentDictionary<string, Dictionary<string,string>> Sessions = new ConcurrentDictionary<string, Dictionary<string,string>>(StringComparer.OrdinalIgnoreCase);
        private static readonly Dictionary<string, Func<HttpContext, string, Task>> Extensions = new Dictionary<string, Func<HttpContext, string, Task>>(StringComparer.OrdinalIgnoreCase);
        private static readonly Dictionary<string, HashSet<string>> reverseSymlinkMap = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        private static readonly Dictionary<string, HotReloadContext> LiveAssemblies = new Dictionary<string, HotReloadContext>(StringComparer.OrdinalIgnoreCase);
        private static Timer _cleanupTimer = new Timer(_ => Sessions.Clear(), null, TimeSpan.Zero, TimeSpan.FromMinutes(Program.config.ClearSessEveryXMin));
        private FileSystemWatcher watcher = new FileSystemWatcher { };
        public static FastCGIClient FastCGI = new FastCGIClient();
        public static ParallelOptions paralleloptions = new ParallelOptions
        {
            MaxDegreeOfParallelism = Environment.ProcessorCount > 12 ? Environment.ProcessorCount / 2 : Environment.ProcessorCount
        };
        public ICollection<string> FileLeadKeys() { return FileLead.Keys; }

        static int defaultHeaderCount = 0;
        static string[] defaultHeaderKeys = new string[0];
        static string[] defaultHeaderValues = new string[0];
        public class DeflateCompressionProvider : ICompressionProvider
        {
            public string EncodingName => "deflate";

            public bool SupportsFlush => true;

            public Stream CreateStream(Stream outputStream)
            {
                return new DeflateStream(outputStream, Program.config.CompressionLevel, leaveOpen: true);
            }
        }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddRouting();
            services.AddWebSockets(config => {
                config.KeepAliveInterval = TimeSpan.FromSeconds(Program.config.WebSocketTimeout);
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
                options.Level = Program.config.CompressionLevel;
            });
            if (Program.config.Logging) services.AddHttpLogging(options => { });
            if (Program.config.RateLimitReq != 0)
                services.AddRateLimiter(options => { });
            if(Program.config.RequestTimeout != 0)
                services.AddRequestTimeouts(options =>
                {
                    options.DefaultPolicy = new RequestTimeoutPolicy
                    {
                        Timeout = TimeSpan.FromSeconds(Program.config.RequestTimeout),
                        TimeoutStatusCode = StatusCodes.Status504GatewayTimeout
                    };
                });
        }
        public void Configure(IApplicationBuilder app)
        {
            if (Program.WWWdir != "")
            {
                app.UseStaticFiles(new StaticFileOptions
                {
                    FileProvider = new PhysicalFileProvider(Path.Combine(Program.WWWdir)) //,
                                                                                          //RequestPath = "/"
                });
            }
            if (Program.config.RequestTimeout != 0) 
                app.UseRequestTimeouts();
            if (Program.config.MaxBytesPerSecond != 0)
                app.UseMiddleware<BandwidthLimiterMiddleware>();
            if (Program.config.Logging) app.UseHttpLogging();
            if (Program.config.DebugPages) app.UseDeveloperExceptionPage();
            if (Program.config.ServerMetrics)
                app.Use(async (context, next) => {
                    Interlocked.Increment(ref Program.totalRequests);
                    await next(context);
                });
            if (Program.config.RateLimitReq != 0)
            {
                var rate = new RateLimiterOptions();
                rate.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
                rate.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>
                    RateLimitPartition.GetTokenBucketLimiter(
                        context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                        _ => new TokenBucketRateLimiterOptions
                        {
                            TokenLimit = Program.config.RateLimitReq,
                            ReplenishmentPeriod = TimeSpan.FromSeconds(Program.config.RateLimitTime),
                            TokensPerPeriod = Program.config.RateLimitRefill,
                            AutoReplenishment = true,
                            QueueLimit = Program.config.RateLimitQueue
                        }));
                app.UseRateLimiter(rate);
            }
            app.UseResponseCompression();

            if (Program.BackendDir != "")
            {
                app.UseWebSockets();
                app.UseRouting();
                app.UseEndpoints(endpoints =>
             {
                 endpoints.Map("/{**catchAll}", async context =>
                 {
#pragma warning disable CS8604 // Possible null reference argument.
                     if (Program.config.DomainAlias.TryGetValue(context.Request.Host.Value, out string? OtherDomain)) // while .Host is nullable, it is always set in this case. Checking for .HasValue would waste a CPU cycle, probably.
                     {
                         context.Request.Host = new HostString(OtherDomain);
                     }
#pragma warning restore CS8604 // Possible null reference argument.
                     ReadOnlySpan<char> _host = context.Request.Host.Value.AsSpan();
                     ReadOnlySpan<char> _path = context.Request.Path.Value.AsSpan();
                     ulong key = HashHostAndPath(_host, _path); // skip string concat // did indeed forget to trim port
                     if (Program.config.UrlAliasHash.TryGetValue(key, out string? newPath)) // rarely true. Only if webadmin has added values
                     {
                         context.Request.Path = new PathString(newPath); // needed for C#-endpoints
                         _path = newPath.AsSpan();
                     }

                     string[] pathBuffer = ArrayPool<string>.Shared.Rent(Program.config.MaxDirDepth + 2);
                     try
                     {
                         Array.Clear(pathBuffer, 0, pathBuffer.Length); // prevent leftover strings
                         GetDomainBasedPath(context, pathBuffer, out int pathLen); // fills buffer, sets actual length. Limited by Program.config.MaxDirDepth, no need for extra checks.

                         Span<char> filePathBuffer = stackalloc char[Program.config.MaxFilePathLength];
                         int pos = 0;

                         // Copy segments from pathBuffer into filePathBuffer, separated by '/'
                         for (int i = 0; i < pathLen; i++)
                         {
                             string segment = pathBuffer[i];

                             if (segment == null) continue; // defensive
                             if (pos + segment.Length >= Program.config.MaxFilePathLength)
                             {
                                 context.Response.StatusCode = StatusCodes.Status414RequestUriTooLong;
                                 // Console.WriteLine("pos: " + pos + " | segment: " + segment.Length.ToString() + " | max: " + Program.config.MaxFilePathLength.ToString());
                                 return; // cancel if too long
                             }
                             // Copy segment
                             segment.AsSpan().CopyTo(filePathBuffer.Slice(pos));
                             pos += segment.Length;

                             // Add '/' between segments if not last
                             if (i < pathLen - 1)
                             {
                                 filePathBuffer[pos++] = '/';
                             }
                         }
                         // At this point filePathBuffer[..pos] contains the full path as a Span<char>
                         string FileToUse = filePathBuffer.Slice(0, pos).ToString();
                         if (!FileLead.TryGetValue(FileToUse, out var _Handler))
                         {
                             while (pathLen > 2)
                             {
                                 pathLen--;

                                 pos = 0;
                                 for (int i = 0; i < pathLen; i++)
                                 {
                                     string segment = pathBuffer[i];
                                     segment.AsSpan().CopyTo(filePathBuffer.Slice(pos));
                                     pos += segment.Length;

                                     if (i < pathLen - 1)
                                         filePathBuffer[pos++] = '/';
                                 }

                                 FileToUse = filePathBuffer.Slice(0, pos).ToString();

                                 if (FileLead.TryGetValue(FileToUse, out _Handler))
                                     break;
                             }
                         }

                         if (_Handler != null)
                         {
                             for (int i = 0; i < defaultHeaderCount; i++)
                             {
                                 context.Response.Headers[defaultHeaderKeys[i]] = defaultHeaderValues[i]; // perhaps not necessary in 404NotFound?
                             }
                             int dotIndex = FileToUse.LastIndexOf('.');
                             //string Ext = dotIndex >= 0 ? FileToUse[(dotIndex + 1)..] : "";
                             if (dotIndex >= 0)
                             {
                                 string Ext = FileToUse[(dotIndex + 1)..];
                                 if (Program.config.OptExtTypes.TryGetValue(Ext, out string[]? ctype))
                                 {
                                     for (int i = 0; i < ctype.Length; i += 2)
                                     {
                                         context.Response.Headers[ctype[i]] = ctype[i + 1];
                                     }
                                 }
                             }
                             await _Handler(context, FileToUse);
                             return;
                         }
                     }
#if DEBUG
                     catch (Exception e)
                     {
                         Console.WriteLine(context.Request.Path);
                         Console.WriteLine(context.Request.Headers.Range);
                         Console.WriteLine(string.Join("\n", context.Response.Headers.Select(h => h.Key + ": " + h.Value)));
                         Console.WriteLine(e);
                     }
#endif
                     finally
                     {
                         ArrayPool<string>.Shared.Return(pathBuffer, clearArray: true);
                     }

                     context.Response.StatusCode = StatusCodes.Status404NotFound;
                     await context.Response.WriteAsync(error404);
                 });
             });

                Reload();
                Task.Run(() =>
                {
                    IndexFiles(Program.BackendDir);
                    IndexDirectories(Program.BackendDir);
                    IndexErrorPages(Program.BackendDir);
                });
                SetupFileWatcher(Program.BackendDir);
            }
        }

        public void Reload()
        {
            foreach (KeyValuePair<string, string> ext in Program.config.ForwardExt)
            {
                Extensions[ext.Key] = (context, path) =>
                {
                    string targetUrl = ext.Value.Replace("{domain}", context.Request.Host.Value.Split(':')[0]) + context.Request.Path.Value + context.Request.QueryString.Value;
                    return ForwardRequestTo(context, targetUrl);
                };
            }
            Reload2();
        }
        public static void Reload2()
        {
            defaultHeaderKeys = new string[Program.config.DefaultHeaders.Count];
            defaultHeaderValues = new string[Program.config.DefaultHeaders.Count];
            int idx = 0;
            foreach (var kv in Program.config.DefaultHeaders)
            {
                defaultHeaderKeys[idx] = kv.Key;
                defaultHeaderValues[idx] = kv.Value;
                idx++;
            }
            defaultHeaderCount = defaultHeaderKeys.Length;

            foreach (string ext in Program.config.DownloadIfExtension) Extensions[ext] = DefDownload;
            if (Program.config.Enable_PHP)
            {
                FastCGI = new FastCGIClient(Program.config.PHP_FPM); //.Split(":")[0], int.Parse(Program.config.PHP_FPM.Split(":")[1]));
            }

            httpClient.Timeout = TimeSpan.FromSeconds(Program.config.HttpProxyTimeout);
            handler.SslProtocols = System.Security.Authentication.SslProtocols.Tls12;
            handler.AllowAutoRedirect = false;
            if (!Program.config.ForceTLS)
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
        public static List<string> GetDomainBasedPath(HttpContext context)
        {
            // Optionally, append the requested path if needed
            string[]? requestPath = context.Request.Path.Value?.Trim('/')?.Split("/")?.Where(str => str != "")?.ToArray();
            if (requestPath != null && requestPath.Contains("..")) requestPath = null;
            List<string> fullPath = [Program.BackendDir, (Program.config.FilterFromDomain != "" ? context.Request.Host.Value.Split(':')[0].Replace(Program.config.FilterFromDomain, Program.config.DomainFilterTo) : context.Request.Host.Value.Split(':')[0])];
            if (requestPath != null) fullPath.AddRange(requestPath);

            return fullPath;
        }
        public static void GetDomainBasedPath(HttpContext context, Span<string> buffer, out int length)
        {
            length = 0;

            // BackendDir
            buffer[length++] = Program.BackendDir;

            // Host processing
            string host = context.Request.Host.Value;
            int colonIndex = host.IndexOf(':');
            if (colonIndex != -1) host = host[..colonIndex];

            if (!string.IsNullOrEmpty(Program.config.FilterFromDomain))
                host = host.Replace(Program.config.FilterFromDomain, Program.config.DomainFilterTo);

            buffer[length++] = host;

            // Request path
            ReadOnlySpan<char> path = context.Request.Path.Value.AsSpan().Trim('/');
            int start = 0;
            while (start < path.Length)
            {
                int sep = path.Slice(start).IndexOf('/');
                if (sep == -1) sep = path.Length - start;

                ReadOnlySpan<char> part = path.Slice(start, sep);
                if (!part.SequenceEqual("..".AsSpan())) // prevent directory traversal
                    buffer[length++] = part.ToString(); // unavoidable allocation here if you store strings

                start += sep + 1;
            }
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
        private static async Task StreamFileUsingBodyWriter(HttpContext context, string file, long start, long length)
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
        private static async Task StreamFileChunked(HttpContext context, string file, long start, long length)
        {
            await using FileStream fileStream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read);
            fileStream.Seek(start, SeekOrigin.Begin);

            var buffer = new byte[8192];  // Chunk size
            int bytesRead;
            while ((bytesRead = await fileStream.ReadAsync(buffer)) > 0)
            {
                await context.Response.Body.WriteAsync(buffer, 0, bytesRead);

                // Ensure data is actually written to the client
                await context.Response.Body.FlushAsync();
            }
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
            string fn = "undefined";
            string[] pa = file.Split("/");
            if (pa.Length > 0) fn = pa[pa.Length - 1];
            context.Response.Headers["content-disposition"] = "attachment; filename=" + fn;
            await DefHandle(context, file);
        }
        private static HttpClientHandler handler = new HttpClientHandler {
            UseCookies = false
        };
        private static readonly HttpClient httpClient = new HttpClient(handler);
        private static readonly ClientWebSocket _proxyClient = new ClientWebSocket();
        private static bool IgnoreCert(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors)
        {
            return true;
        }
        private async Task ForwardRequestTo(HttpContext context, string targetUrl)
        {
            if (Program.config.MaxRequestBodySize != null && context.Request.ContentLength > Program.config.MaxRequestBodySize)
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
                    client.Options.KeepAliveInterval = TimeSpan.FromSeconds(Program.config.WebSocketEndpointTimeout);
                    websockethandler.ConnectTimeout = TimeSpan.FromSeconds(Program.config.WebSocketEndpointTimeout);
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
                    string Domain = context.Request.Host.Value.Split(":")[0];
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
                        
                        await client.ConnectAsync(new Uri(targetUrl.Replace("https:", "wss:").Replace("http:", "ws:")), invoker, new CancellationTokenSource(TimeSpan.FromSeconds(Program.config.WebSocketEndpointTimeout)).Token);
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
            string[] getExt = file.Split('.');
            string Ext = getExt[getExt.Length - 1];
            if (Program.config.Enable_CS)
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
            if (Program.config.Enable_PHP)
            {
                if (Ext == "php")
                {
                    try {
                        FileLead[file] = FastCGI.Run;
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
            if(Program.config.Enable_WASM)
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
                FileLead[file] = Handler;
                if (Handler == DefDownload) CacheFileInfo(file);
            }
            else
            {
                //string file2 = file;
                FileLead[file] = DefHandle;
                CacheFileInfo(file);
            }
        }
        public static void CacheFileInfo(string file) {
            try
            {
                FileInfo fileInfo = ThruSymlinks(file);
                if(fileInfo != null) FileIndex[file] = new long[] { ((DateTimeOffset)fileInfo.LastWriteTimeUtc).ToUnixTimeSeconds(), fileInfo.Length };
            }catch(Exception){
                FileLead.Remove(file, out _); // no func = error 404
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
                        if (target.StartsWith(Program.BackendDir))
                        {
                            target = target.Substring(Program.BackendDir.Length); // Resolve relative to the symlink's directory
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
            if (realFile.StartsWith(Program.BackendDir))
            {
                realFile = realFile.Substring(Program.BackendDir.Length); // Resolve relative to the symlink's directory
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
            bool Any = false;
            foreach (string File in Program.config.indexPriority)
            {
                string tmpfile = Path.Combine(Folder, File).Replace(Path.DirectorySeparatorChar, '/');
                if (FileLead.TryGetValue(tmpfile, out var Handler))
                {
                    string[] getExt = tmpfile.Split('.');
                    string Ext = getExt[getExt.Length - 1];
                    
                    if (Program.config.OptExtTypes.TryGetValue(Ext, out string[]? ctype))
                    {
                        FileLead[Folder] = (context, path) => { path = path + "/" + File; for (int i = 0; i < ctype.Length; i += 2){context.Response.Headers[ctype[i]] = ctype[i + 1];} return Handler(context, path); };
                    }else
                    {
                        FileLead[Folder] = (context, path) => { path = path + "/" + File; return Handler(context, path); };
                    }
                    Any = true;
                    break;
                }
            }
            if (!Any && FileLead.ContainsKey(Folder)) FileLead.Remove(Folder, out _);
        }
        public static void IndexErrorPages(string rootDirectory)
        {
            foreach (string Folder in Directory.EnumerateDirectories(rootDirectory, "*", SearchOption.TopDirectoryOnly)) // BackendDir: domain1, domain2, domain3
            {
                IndexErrorPage(Folder.Replace(Path.DirectorySeparatorChar, '/'));
            }
        }
        public static void IndexErrorPage(string Folder)
        {
            string tmpfile = Path.Combine(Folder, "error404.html").Replace(Path.DirectorySeparatorChar, '/');
            if (FileLead.ContainsKey(tmpfile) && !FileLead.ContainsKey(Folder)) // error404.html exists
            {
                // Since we currently loop backwards (at around line 150) rather than give 404 by default,
                // any time a 404 would be displayed is if /BackendDir/domain is not set.
                try
                {
                    string errcontent = File.ReadAllText(tmpfile);
                    FileLead[Folder] = async (context, path) => {
                        context.Response.StatusCode = StatusCodes.Status404NotFound;
                        await context.Response.WriteAsync(errcontent.Replace("${0}", context.Request.Headers.Referer != "" ? "<p>You came from <a href=\"" + context.Request.Headers.Referer + "\">" + context.Request.Headers.Referer + "</a>. Hmmm</p>" : ""));
                    };
                }
                catch (Exception) {}
            }
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
            if ((Program.config.Enable_CS && filePath.EndsWith("._csdll")) || (Program.config.Enable_PHP && filePath.EndsWith(".phpdll"))) filePath = filePath.Substring(0, filePath.Length - 3);
            FileIndex.TryRemove(filePath, out _);
            FileLead.TryRemove(filePath, out _);
            if (LiveAssemblies.TryGetValue(filePath, out HotReloadContext? ctx))
            {
                ctx?.Unload();
                LiveAssemblies.Remove(filePath);
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

                if (func != null) FileLead[filePath] = func;
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
                LiveAssemblies.Remove(toFile);
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

            FileLead[toFile] = func; // ._csdll -> ._cs
            LiveAssemblies[toFile] = context;
        }
        public static void LoadWasm(string file)
        {
            var module = Wasm.Load(file);
            FileLead[file] = async (context, path) =>
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
            };
        }

        public static void LoadPhpAssembly(string filePath)
        {
            Assembly assembly = Assembly.Load(File.ReadAllBytes(filePath + "dll"));

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

            FileLead[filePath] = phpFunction;
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
