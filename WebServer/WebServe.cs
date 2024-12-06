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

namespace WebServer
{
    public class Startup
    {
        const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        string error404 = "<!DOCTYPE HTML><html><head><title>Err 404 - page not found</title><link href=\"/main.css\" rel=\"stylesheet\" /><meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" /></head><body><center><span style=\"font-size:24\">Error 404</span><h1 color=red>Page not found</h1><br />${0}<br /><p>Maybe we're working on adding this page.</p>${1}<br /><div style=\"display:inline-table;\"><iframe style=\"margin:auto\" src=\"https://discordapp.com/widget?id=473863639347232779&theme=dark\" width=\"350\" height=\"500\" allowtransparency=\"true\" frameborder=\"0\"></iframe><iframe style=\"margin:auto\" src=\"https://discordapp.com/widget?id=670549627455668245&theme=dark\" width=\"350\" height=\"500\" allowtransparency=\"true\" frameborder=\"0\"></iframe></div></center><br /><ul style=\"display:inline-block;float:right\"><li style='display:inline-block;background-image:url(\"/social-icons.png\");background-position:0px;'><a href=\"https://twitter.com/JonTVme\" style=\"display:block;text-indent:-9999px;width:25px;height:25px;\">Twitter</a></li><li style='display:inline-block;background-image:url(\"/social-icons.png\");background-position:--25px;'><a href=\"https://facebook.com/realJonTV\" style=\"display:block;text-indent:-9999px;width:25px;height:25px;\">Facebook</a></li><li style='display:inline-block;background-image:url(\"/social-icons.png\");background-position:-50px'><a href=\"https://reddit.com/r/JonTV\" style=\"display:block;text-indent:-9999px;width:25px;height:25px;\">Reddit</a></li><li style='display:inline-block;background-image:url(\"/social-icons.png\");background-position:-75px'><a href=\"https://discord.gg/4APyyak\" style=\"display:block;text-indent:-9999px;width:25px;height:25px;\">Discord server</a></li></ul><br /><sup><em>Did you know that you're old?</em></sup></body></html>";
        public static readonly ConcurrentDictionary<string, long> FileIndex = new ConcurrentDictionary<string, long>();
        public static readonly ConcurrentDictionary<string, Func<HttpContext, string, Task>> FileLead = new ConcurrentDictionary<string, Func<HttpContext, string, Task>>();
        public static ConcurrentDictionary<string, Dictionary<string,string>> Sessions = new ConcurrentDictionary<string, Dictionary<string,string>>();
        private static readonly Dictionary<string, Func<HttpContext, string, Task>> Extensions = new Dictionary<string, Func<HttpContext, string, Task>>();
        private static Timer _cleanupTimer;

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
            app.UseWebSockets();
            app.UseRouting();
            if (Program.BackendDir != "") app.UseEndpoints(endpoints =>
            {
                endpoints.Map("/{**catchAll}", async context =>
                {
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
                        while (!FileLead.TryGetValue((FileToUse = string.Join("/", path)), out _Handler) && !FileLead.TryGetValue((FileToUse = string.Join("/", path.Append("index._cs"))), out _Handler) && !FileLead.TryGetValue((FileToUse = string.Join("/", path.Append("index.njs"))), out _Handler) && !FileLead.TryGetValue((FileToUse = string.Join("/", path.Append("index.bun"))), out _Handler) && !FileLead.TryGetValue((FileToUse = string.Join("/", path.Append("index.phpdll"))), out _Handler) && !FileLead.TryGetValue((FileToUse = string.Join("/", path.Append("index.html"))), out _Handler) && path.Count > 2) // file does not exist
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
            httpClient.Timeout = TimeSpan.FromSeconds(300);

            foreach (string ext in Program.config.DownloadIfExtension) Extensions[ext] = DefDownload;
            foreach (KeyValuePair<string, string> ext in Program.config.ForwardExt)
            {
                Extensions[ext.Key] = (context, path) => {
                    string targetUrl = ext.Value.Replace("{domain}", context.Request.Host.Value.Split(':')[0]) + context.Request.Path.Value + context.Request.QueryString.Value;
                    return ForwardRequestTo(context, targetUrl);
                };
            }
            _cleanupTimer = new Timer(_ => Sessions.Clear(), null, TimeSpan.Zero, TimeSpan.FromMinutes(Program.config.ClearSessEveryXMin));
            handler.SslProtocols = System.Security.Authentication.SslProtocols.Tls12;


            IndexFiles(Program.BackendDir);
            SetupFileWatcher(Program.BackendDir);
        }
        public static List<string> GetDomainBasedPath(HttpContext context)
        {
            // Optionally, append the requested path if needed
            string[]? requestPath = context.Request.Path.Value?.Trim('/')?.Split("/")?.Where(str => str != "")?.ToArray();
            if (requestPath != null && requestPath.Contains("..")) requestPath = null;
            List<string> fullPath = [Program.BackendDir, context.Request.Host.Value.Split(':')[0].Replace(Program.config.FilterFromDomain, Program.config.DomainFilterTo)];
            if (requestPath != null) fullPath.AddRange(requestPath);

            return fullPath;
        }
        private static async Task DefHandle(HttpContext context, string file)
        {
            if (FileIndex.TryGetValue(file, out long LastMod))
            {
                context.Response.Headers["last-modified"] = DateTimeOffset.FromUnixTimeSeconds(LastMod).ToString("R");
                if (long.TryParse(context.Request.Headers.IfModifiedSince, out long LM))
                {
                    if (LastMod <= LM)
                    {
                        context.Response.StatusCode = 304;
                        return;
                    }
                }
            }
            if (context.Request.Method == HttpMethods.Options) return;
            await context.Response.SendFileAsync(file);
        }
        private static async Task DefDownload(HttpContext context, string file)
        {
            if (FileIndex.TryGetValue(file, out long LastMod))
            {
                context.Response.Headers["last-modified"] = DateTimeOffset.FromUnixTimeSeconds(LastMod).ToString("R");
                if (long.TryParse(context.Request.Headers.IfModifiedSince, out long LM))
                {
                    if (LastMod <= LM)
                    {
                        context.Response.StatusCode = 304;
                        return;
                    }
                }
            }
            string fn = "undefined";
            string[] pa = file.Split("/");
            if (pa.Length > 0) fn = pa[pa.Length - 1];
            context.Response.Headers["content-disposition"] = "attachment; filename=" + fn;
            if (context.Request.Method == HttpMethods.Options) return;
            await context.Response.SendFileAsync(file);
        }
        private static HttpClientHandler handler = new HttpClientHandler();
        private static readonly HttpClient httpClient = new HttpClient(handler);
        private static readonly ClientWebSocket _proxyClient = new ClientWebSocket();
        private async Task ForwardRequestTo(HttpContext context, string targetUrl)
        {
            if (context.WebSockets.IsWebSocketRequest)
            {
                WebSocket webSocket = await context.WebSockets.AcceptWebSocketAsync();
                ClientWebSocket client = new ClientWebSocket();
                await client.ConnectAsync(new Uri(targetUrl), CancellationToken.None);
                await PipeSockets(webSocket, client);
                return;
            }
            try
            {
                HttpRequestMessage requestMessage = new HttpRequestMessage
                {
                    Method = new HttpMethod(context.Request.Method),
                    RequestUri = new Uri(targetUrl),
                    Version = HttpVersion.Version20,
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
            var buffer = new byte[8192]; // Adjust buffer size as needed.

            // Server to Client
            var serverToClient = Task.Run(async () =>
            {
                while (webSocket.State == WebSocketState.Open && clientWebSocket.State == WebSocketState.Open)
                {
                    var result = await webSocket.ReceiveAsync(new ArraySegment<byte>(buffer), CancellationToken.None);

                    if (result.MessageType == WebSocketMessageType.Close)
                    {
                        await clientWebSocket.CloseAsync(WebSocketCloseStatus.NormalClosure, "Closed by server", CancellationToken.None);
                        break;
                    }

                    await clientWebSocket.SendAsync(new ArraySegment<byte>(buffer, 0, result.Count), result.MessageType, result.EndOfMessage, CancellationToken.None);
                }
            });

            // Client to Server
            var clientToServer = Task.Run(async () =>
            {
                while (webSocket.State == WebSocketState.Open && clientWebSocket.State == WebSocketState.Open)
                {
                    var result = await clientWebSocket.ReceiveAsync(new ArraySegment<byte>(buffer), CancellationToken.None);

                    if (result.MessageType == WebSocketMessageType.Close)
                    {
                        await webSocket.CloseAsync(WebSocketCloseStatus.NormalClosure, "Closed by client", CancellationToken.None);
                        break;
                    }

                    await webSocket.SendAsync(new ArraySegment<byte>(buffer, 0, result.Count), result.MessageType, result.EndOfMessage, CancellationToken.None);
                }
            });

            // Wait for either direction to close.
            await Task.WhenAny(serverToClient, clientToServer);
        }

        public static void IndexFiles(string rootDirectory)
        {
            foreach (string file in Directory.EnumerateFiles(rootDirectory, "*.*", SearchOption.AllDirectories))
            {
                string[] getExt = file.Split('.');
                string Ext = getExt[getExt.Length - 1];
                if (Program.config.Enable_CS)
                {
                    if (Ext == "_cs")
                    {
                        try { CompileAndAddFunction(file); } catch (Exception) { }
                        continue;
                    }
                    else if (Ext == "_csdll")
                    {
                        try { LoadCompiledFunc(file); } catch (Exception) { }
                        continue;
                    }
                }
                if (Program.config.Enable_PHP)
                {
                    if (Ext == "php")
                    {
                        try { if (GenPhpAssembly(file)) LoadPhpAssembly(file); } catch (Exception) { }
                        continue;
                    }
                    else if (Ext == "phpdll")
                    {
                        try { LoadPhpAssembly(file); } catch (Exception) { }
                        continue;
                    }
                }
                if (Extensions.TryGetValue(Ext, out var Handler))
                {
                    FileLead[file] = Handler;
                }
                else
                {
                    FileLead[file] = DefHandle;
                    FileInfo fileInfo = new FileInfo(file);
                    FileIndex[file] = ((DateTimeOffset)fileInfo.LastWriteTimeUtc).ToUnixTimeSeconds();
                }
            }
        }

        static void SetupFileWatcher(string rootDirectory)
        {
            FileSystemWatcher watcher = new FileSystemWatcher
            {
                Path = rootDirectory,
                IncludeSubdirectories = true,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.CreationTime
            };

            watcher.Created += (sender, e) => UpdateIndex(e.FullPath);
            watcher.Changed += (sender, e) => UpdateIndex(e.FullPath);
            watcher.Deleted += (sender, e) => RemoveFromIndex(e.FullPath);
            watcher.Renamed += (sender, e) =>
            {
                RemoveFromIndex(e.OldFullPath);
                UpdateIndex(e.FullPath);
            };

            watcher.EnableRaisingEvents = true;
        }

        static void UpdateIndex(string filePath)
        {
            if (File.Exists(filePath))
            {
                string[] getExt = filePath.Split('.');
                string Ext = getExt[getExt.Length - 1];
                if (Program.config.Enable_CS)
                {
                    if (Ext == "_cs")
                    {
                        try { CompileAndAddFunction(filePath); } catch (Exception e) { Console.ForegroundColor = ConsoleColor.Red; Console.WriteLine(e); Console.ResetColor(); }
                        return;
                    }
                    else if (Ext == "_csdll")
                    {
                        try { LoadCompiledFunc(filePath); } catch (Exception e) { Console.ForegroundColor = ConsoleColor.Red; Console.WriteLine(e); Console.ResetColor(); }
                        return;
                    }
                }
                if (Program.config.Enable_PHP && Ext == "php")
                {
                    try { if (GenPhpAssembly(filePath)) LoadPhpAssembly(filePath); } catch (Exception) { }
                    return;
                }
                if (Extensions.TryGetValue(Ext, out var Handler))
                {
                    FileLead[filePath] = Handler;
                }
                else
                {
                    FileLead[filePath] = DefHandle;
                    FileInfo fileInfo = new FileInfo(filePath);
                    FileIndex[filePath] = ((DateTimeOffset)fileInfo.LastWriteTimeUtc).ToUnixTimeSeconds();
                }
            }
        }

        static void RemoveFromIndex(string filePath)
        {
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
            if (func != null) FileLead[filePath] = func;
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

            FileLead[file[..^3]] = func;
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
