using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.ResponseCompression;
using Microsoft.CodeAnalysis;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO.Compression;
using System.Net.WebSockets;
using System.Reflection;
using System.Net.Http.Headers;
using System.Net;
using Microsoft.AspNetCore.WebSockets;
using CSScriptLib;
using System.Buffers;
using System.Security.Authentication;
using CSScripting;
using System.Text;

namespace WebServer
{
    public class Startup
    {
        const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        string error404 = "<!DOCTYPE HTML><html><head><title>Err 404 - page not found</title><link href=\"/main.css\" rel=\"stylesheet\" /><meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" /></head><body><center><span style=\"font-size:24\">Error 404</span><h1 color=red>Page not found</h1><br />${0}<br /><p>Maybe we're working on adding this page.</p>${1}<br /><div style=\"display:inline-table;\"><iframe style=\"margin:auto\" src=\"https://discordapp.com/widget?id=473863639347232779&theme=dark\" width=\"350\" height=\"500\" allowtransparency=\"true\" frameborder=\"0\"></iframe><iframe style=\"margin:auto\" src=\"https://discordapp.com/widget?id=670549627455668245&theme=dark\" width=\"350\" height=\"500\" allowtransparency=\"true\" frameborder=\"0\"></iframe></div></center><br /><ul style=\"display:inline-block;float:right\"><li style='display:inline-block;background-image:url(\"/social-icons.png\");background-position:0px;'><a href=\"https://twitter.com/JonTVme\" style=\"display:block;text-indent:-9999px;width:25px;height:25px;\">Twitter</a></li><li style='display:inline-block;background-image:url(\"/social-icons.png\");background-position:--25px;'><a href=\"https://facebook.com/realJonTV\" style=\"display:block;text-indent:-9999px;width:25px;height:25px;\">Facebook</a></li><li style='display:inline-block;background-image:url(\"/social-icons.png\");background-position:-50px'><a href=\"https://reddit.com/r/JonTV\" style=\"display:block;text-indent:-9999px;width:25px;height:25px;\">Reddit</a></li><li style='display:inline-block;background-image:url(\"/social-icons.png\");background-position:-75px'><a href=\"https://discord.gg/4APyyak\" style=\"display:block;text-indent:-9999px;width:25px;height:25px;\">Discord server</a></li></ul><br /><sup><em>Did you know that you're old?</em></sup></body></html>";
        public static readonly ConcurrentDictionary<string, long[]> FileIndex = new ConcurrentDictionary<string, long[]>(StringComparer.OrdinalIgnoreCase);
        public static readonly ConcurrentDictionary<string, Func<HttpContext, string, Task>> FileLead = new ConcurrentDictionary<string, Func<HttpContext, string, Task>>(StringComparer.OrdinalIgnoreCase);
        public static ConcurrentDictionary<string, Dictionary<string,string>> Sessions = new ConcurrentDictionary<string, Dictionary<string,string>>(StringComparer.OrdinalIgnoreCase);
        private static readonly Dictionary<string, Func<HttpContext, string, Task>> Extensions = new Dictionary<string, Func<HttpContext, string, Task>>(StringComparer.OrdinalIgnoreCase);
        private static Timer _cleanupTimer = new Timer(_ => Sessions.Clear(), null, TimeSpan.Zero, TimeSpan.FromMinutes(Program.config.ClearSessEveryXMin));

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
        }
        public class DeflateCompressionProvider : ICompressionProvider
        {
            public string EncodingName => "deflate";

            public bool SupportsFlush => true;

            public Stream CreateStream(Stream outputStream)
            {
                return new DeflateStream(outputStream, CompressionLevel.Optimal, leaveOpen: true);
            }
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
            app.UseResponseCompression();
            if (Program.BackendDir != "")
            {
                app.UseWebSockets();
                app.UseRouting();
                app.UseEndpoints(endpoints =>
             {
                 endpoints.Map("/{**catchAll}", async context =>
                 {
                     if (Program.config.DomainAlias.TryGetValue(context.Request.Host.Value, out string? OtherDomain))
                     {
                         context.Request.Host = new HostString(OtherDomain);
                     }
                     if (Program.config.UrlAlias.TryGetValue(context.Request.Host.Value + context.Request.Path.Value, out string? NewPath))
                     {
                         context.Request.Path = new PathString(NewPath);
                     }
                     List<string> path = GetDomainBasedPath(context); // Extract the request path
                     if (path.Count > Program.config.MaxDirDepth)
                     {
                         context.Response.StatusCode = 414;
                         return;
                     }
                     foreach (KeyValuePair<string, string> header in Program.config.DefaultHeaders)
                     {
                         context.Response.Headers[header.Key] = header.Value;
                     }
                     string FileToUse = string.Join("/", path);
                     if (!FileLead.TryGetValue(FileToUse, out var _Handler) && (path[path.Count - 1].Length < 1 || path[path.Count - 1].Substring(path[path.Count - 1].Length - 1) != "/")) // linking directly to a file or a directory
                     {
                         while (!FileLead.TryGetValue((FileToUse = string.Join("/", path)), out _Handler) && path.Count > 2) // file does not exist
                         {
                             path.RemoveAt(path.Count - 1);
                         }
                     }
                     if (_Handler != null)
                     {
                         string[] getExt = FileToUse.Split('.');
                         string Ext = getExt[getExt.Length - 1];
                         if (Program.config.ExtTypes.TryGetValue(Ext, out string? ctype))
                         {
                             context.Response.Headers["content-type"] = ctype;
                         }
                         await _Handler(context, FileToUse);
                         return;
                     }

                     context.Response.StatusCode = 404;
                     await context.Response.WriteAsync(error404.Replace("${0}", path[1] == "jontvme" ? "<img src=\"/JonTV/JonTVplay_dark.svg\" class=\"spin\" />" : "<img src=\"//jonhosting.com/JonHost.png\" />").Replace("${1}", context.Request.Headers.Referer != "" ? "<p>You came from <a href=\"" + context.Request.Headers.Referer + "\">" + context.Request.Headers.Referer + "</a>. Hmmm</p>" : ""));
                 });
             });

                foreach (string ext in Program.config.DownloadIfExtension) Extensions[ext] = DefDownload;
                foreach (KeyValuePair<string, string> ext in Program.config.ForwardExt)
                {
                    Extensions[ext.Key] = (context, path) =>
                    {
                        string targetUrl = ext.Value.Replace("{domain}", context.Request.Host.Value.Split(':')[0]) + context.Request.Path.Value + context.Request.QueryString.Value;
                        return ForwardRequestTo(context, targetUrl);
                    };
                }

                httpClient.Timeout = TimeSpan.FromSeconds(300);
                handler.SslProtocols = System.Security.Authentication.SslProtocols.Tls12;
                handler.AllowAutoRedirect = false;

                IndexFiles(Program.BackendDir);
                IndexDirectories(Program.BackendDir);
                SetupFileWatcher(Program.BackendDir);
            }
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
        private static async Task StreamFileUsingBodyWriter(HttpContext context, string file, long start, long length)
        {
            const int bufferSize = 8192; // 8KB chunks
            System.IO.Pipelines.PipeWriter bodyWriter = context.Response.BodyWriter;

            await using FileStream fileStream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read);
            fileStream.Seek(start, SeekOrigin.Begin);

            long remaining = length;
            while (remaining > 0)
            {
                var memory = bodyWriter.GetMemory((int)Math.Min(bufferSize, remaining));
                int bytesRead = await fileStream.ReadAsync(memory);
                if (bytesRead == 0) break; // End of file

                bodyWriter.Advance(bytesRead);
                remaining -= bytesRead;

                var flushResult = await bodyWriter.FlushAsync();
                if (flushResult.IsCanceled || flushResult.IsCompleted) break;
            }

            await bodyWriter.CompleteAsync();
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

        private static async Task DefHandle(HttpContext context, string file)
        {
            if (FileIndex.TryGetValue(file, out long[]? LastMod))
            {
                context.Response.Headers["last-modified"] = DateTimeOffset.FromUnixTimeSeconds(LastMod[0]).ToString("R");
                context.Response.ContentLength = LastMod[1];
                if (long.TryParse(context.Request.Headers.IfModifiedSince, out long LM))
                {
                    if (LastMod[0] <= LM)
                    {
                        context.Response.StatusCode = 304;
                        return;
                    }
                }
                if (context.Request.Method == HttpMethods.Options) return;

                //long end = (LastMod[1] > 10485760 && !context.Request.Headers.UserAgent.ToString().Contains("Jon_Android") ? Math.Min(start + 8388608 - 1, LastMod[1] - 1) : LastMod[1] - 1);
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
                        if (contentLength != LastMod[1])
                        {
                            context.Response.StatusCode = StatusCodes.Status206PartialContent;
                            string protocol = context.Request.Protocol;

                            if (protocol == "HTTP/1.1")
                            {
                                context.Response.Headers.Remove("Content-Length");
                                context.Response.Headers["Transfer-Encoding"] = "chunked";
                                // Use Chunked Transfer Encoding
                                await StreamFileChunked(context, file, start, contentLength);
                            }
                            else
                            {
                                context.Response.Headers["Content-Range"] = "bytes " + start + "-" + end + "/" + LastMod[1];
                                context.Response.ContentLength = contentLength;

                                await StreamFileUsingBodyWriter(context, file, start, contentLength);
                            }
                            return;
                        }
                    }
                }
            }
            if (context.Request.Method == HttpMethods.Options) return;

            await context.Response.SendFileAsync(file);
        }
        private static async Task DefDownload(HttpContext context, string file)
        {
            /*if (FileIndex.TryGetValue(file, out long[]? LastMod))
            {
                context.Response.Headers["last-modified"] = DateTimeOffset.FromUnixTimeSeconds(LastMod[0]).ToString("R");
                context.Response.ContentLength = LastMod[1];
                if (long.TryParse(context.Request.Headers.IfModifiedSince, out long LM))
                {
                    if (LastMod[0] <= LM)
                    {
                        context.Response.StatusCode = 304;
                        return;
                    }
                }
            }*/
            string fn = "undefined";
            string[] pa = file.Split("/");
            if (pa.Length > 0) fn = pa[pa.Length - 1];
            context.Response.Headers["content-disposition"] = "attachment; filename=" + fn;
            await DefHandle(context, file);
            /*if (context.Request.Method == HttpMethods.Options) return;
            await context.Response.SendFileAsync(file);*/
        }
        private static HttpClientHandler handler = new HttpClientHandler();
        private static readonly HttpClient httpClient = new HttpClient(handler);
        private static readonly ClientWebSocket _proxyClient = new ClientWebSocket();
        SocketsHttpHandler websockethandler = new SocketsHttpHandler
        {
            SslOptions = { EnabledSslProtocols = SslProtocols.Tls12 }
        };
        private async Task ForwardRequestTo(HttpContext context, string targetUrl)
        {
            try
            {
                if (context.WebSockets.IsWebSocketRequest)
                {
                    WebSocket webSocket = await context.WebSockets.AcceptWebSocketAsync();
                    ClientWebSocket client = new ClientWebSocket();
                    client.Options.CollectHttpResponseDetails = true;
                    client.Options.HttpVersion = HttpVersion.Version20;
                    client.Options.HttpVersionPolicy = HttpVersionPolicy.RequestVersionOrLower;
                    client.Options.KeepAliveInterval = TimeSpan.FromSeconds(Program.config.WebSocketEndpointTimeout);
                    websockethandler.ConnectTimeout = TimeSpan.FromSeconds(Program.config.WebSocketEndpointTimeout);
                    websockethandler.CookieContainer = new CookieContainer();

                    context.Request.Headers.ForEach((header) => {
                        client.Options.SetRequestHeader(header.Key, header.Value);
                    });
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
                    }catch(Exception){}
                    context.Response.StatusCode = (int)client.HttpStatusCode;
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
                    context.Request.EnableBuffering();
                    context.Request.Body.Position = 0;
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
                requestMessage.Headers.TryAddWithoutValidation(":authority", requestMessage.RequestUri.Host.Split(":")[0]);
                requestMessage.Headers.TryAddWithoutValidation(":path", context.Request.Path + context.Request.QueryString);
                requestMessage.Headers.TryAddWithoutValidation(":method", context.Request.Method);
                requestMessage.Headers.TryAddWithoutValidation(":scheme", context.Request.Scheme);
                requestMessage.Headers.TryAddWithoutValidation("CF-Connecting-IP", context.Connection.RemoteIpAddress?.ToString());

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
                context.Response.StatusCode = 500;
                await context.Response.WriteAsync("Sorry. An error occurred.");
                Console.WriteLine(e);
                return;
            }
        }
        private async Task PipeSockets(WebSocket webSocket, ClientWebSocket clientWebSocket)
        {
            // Server to Client
            Task serverToClient = Task.Run(async () =>
            {
                ArraySegment<byte> buffer = new ArraySegment<byte>(new byte[8192]);
                while (webSocket.State == WebSocketState.Open && clientWebSocket.State == WebSocketState.Open)
                {
                    WebSocketReceiveResult result = await webSocket.ReceiveAsync(buffer, CancellationToken.None);

                    if (result.MessageType == WebSocketMessageType.Close)
                    {
                        await clientWebSocket.CloseAsync(WebSocketCloseStatus.NormalClosure, "Closed by client", CancellationToken.None);
                        break;
                    }

                    await clientWebSocket.SendAsync(buffer, result.MessageType, result.EndOfMessage, CancellationToken.None);
                }
                Console.WriteLine("Proxy webhook kestrel->endpoint closed.");
            });

            // Client to Server
            Task clientToServer = Task.Run(async () =>
            {
                ArraySegment<byte> buffer = new ArraySegment<byte>(new byte[8192]);
                while (webSocket.State == WebSocketState.Open && clientWebSocket.State == WebSocketState.Open)
                {
                    WebSocketReceiveResult result = await clientWebSocket.ReceiveAsync(buffer, CancellationToken.None);

                    if (result.MessageType == WebSocketMessageType.Close)
                    {
                        await webSocket.CloseAsync(WebSocketCloseStatus.NormalClosure, "Closed by server", CancellationToken.None);
                        break;
                    }

                    await webSocket.SendAsync(buffer, result.MessageType, result.EndOfMessage, CancellationToken.None);
                }
                Console.WriteLine("Proxy webhook endpoint->kestrel closed.");
            });

            // Wait for either direction to close.
            await Task.WhenAny(serverToClient, clientToServer);
        }

        public static void IndexFiles(string rootDirectory)
        {
            foreach (string file in Directory.EnumerateFiles(rootDirectory, "*.*", SearchOption.AllDirectories))
            {
                IndexFile(file);
            }
        }
        public static void IndexFile(string file)
        {
            string[] getExt = file.Split('.');
            string Ext = getExt[getExt.Length - 1];
            if (Program.config.Enable_CS)
            {
                if (Ext == "_cs")
                {
                    try { CompileAndAddFunction(file); } catch (Exception e) { Console.ForegroundColor = ConsoleColor.Red; Console.WriteLine(e); Console.ResetColor(); }
                    return;
                }
                else if (Ext == "_csdll")
                {
                    try { LoadCompiledFunc(file); } catch (Exception e) { Console.ForegroundColor = ConsoleColor.Red; Console.WriteLine(e); Console.ResetColor(); }
                    return;
                }
            }
            if (Program.config.Enable_PHP)
            {
                if (Ext == "php")
                {
                    try { if (GenPhpAssembly(file)) LoadPhpAssembly(file); } catch (Exception e) { Console.ForegroundColor = ConsoleColor.Red; Console.WriteLine(e); Console.ResetColor(); }
                    return;
                }
                else if (Ext == "phpdll")
                {
                    try { LoadPhpAssembly(file); } catch (Exception e) { Console.ForegroundColor = ConsoleColor.Red; Console.WriteLine(e); Console.ResetColor(); }
                    return;
                }
            }
            if (Extensions.TryGetValue(Ext, out var Handler))
            {
                FileLead[file.Replace(Path.DirectorySeparatorChar, '/')] = Handler;
            }
            else
            {
                string file2 = file.Replace(Path.DirectorySeparatorChar, '/');
                FileLead[file2] = DefHandle;
                FileInfo fileInfo = new FileInfo(file);
                FileIndex[file2] = new long[] { ((DateTimeOffset)fileInfo.LastWriteTimeUtc).ToUnixTimeSeconds(), fileInfo.Length };
            }
        }
        public static void IndexDirectories(string rootDirectory)
        {
            foreach (string Folder in Directory.EnumerateDirectories(rootDirectory, "*", SearchOption.AllDirectories))
            {
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
                    FileLead[Folder] = (context, path) => { path = Path.Combine(path, tmpfile).Replace(Path.DirectorySeparatorChar, '/'); return Handler(context, path); }; // Handler;
                    Any = true;
                    break;
                }
            }
            if (!Any && FileLead.TryGetValue(Folder, out _)) FileLead.Remove(Folder, out _);
        }

        static void SetupFileWatcher(string rootDirectory)
        {
            FileSystemWatcher watcher = new FileSystemWatcher
            {
                Path = rootDirectory,
                IncludeSubdirectories = true,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.CreationTime
            };
            watcher.Filter = "*.*";

            watcher.Created += (sender, e) => UpdateIndex(e.FullPath);
            watcher.Changed += (sender, e) => UpdateIndex(e.FullPath);
            watcher.Deleted += (sender, e) => RemoveFromIndex(e.FullPath);
            watcher.Renamed += (sender, e) =>
            {
                RemoveFromIndex(e.OldFullPath.Replace(Path.DirectorySeparatorChar, '/'));
                UpdateIndex(e.FullPath.Replace(Path.DirectorySeparatorChar, '/'));
            };

            watcher.EnableRaisingEvents = true;
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
        }

        public static void CompileAndAddFunction(string filePath)
        {
            // Read the code from the file
            string code = File.ReadAllText(filePath);

            dynamic script = CSScript.Evaluator
                         .LoadCode(code);
            Console.WriteLine(script);
            // Extract the function from the result
            Func<HttpContext, string, Task>? func = script.Run;
            if (func != null) FileLead[filePath.Replace(Path.DirectorySeparatorChar, '/')] = func;
        }

        public static void LoadCompiledFunc(string file)
        {
            Assembly assembly = Assembly.Load(File.ReadAllBytes(file));
            Type? type = assembly.GetType("Is_CsScript");
            if (type == null)
            {
                Console.WriteLine("Make sure to use the namespace/class Is_CsScript for ._csdll!");
                return;
            }
            MethodInfo? method = type.GetMethod("Run");
            if (method == null)
            {
                Console.WriteLine("Make a function called Run(HttpContext context, string path)");
                return;
            }
            Func<HttpContext, string, Task> func = (Func<HttpContext, string, Task>)Delegate.CreateDelegate(
    typeof(Func<HttpContext, string, Task>), method
);

            FileLead[file[..^3].Replace(Path.DirectorySeparatorChar, '/')] = func;
        }

        public static void LoadPhpAssembly(string filePath)
        {
            Assembly assembly = Assembly.Load(File.ReadAllBytes(filePath + "dll"));

            // Find a specific class or method (depending on how your PHP script is structured)
            Type? type = assembly.GetType("Is_PhpScript"); // Use the namespace/class name in your PHP file.
            if (type == null)
            {
                Console.WriteLine("Make sure to use the namespace Is_PhpScript for .phpdll-files!");
                return;
            }
            var method = type.GetMethod("Run"); // Assuming "Run" is the entry point.

            // Create a delegate for the method (this assumes it's compatible)
            Func<HttpContext, string, Task> phpFunction = (Func<HttpContext, string, Task>)Delegate.CreateDelegate(
                typeof(Func<HttpContext, string, Task>), method
            );

            FileLead[filePath.Replace(Path.DirectorySeparatorChar, '/')] = phpFunction;
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
                        Arguments = $"{filePath} -o {filePath}dll",
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
