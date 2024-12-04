using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Hosting;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Logging;
using System.Collections.Concurrent;
using Microsoft.CodeAnalysis;
using System.Diagnostics;
using Microsoft.AspNetCore.ResponseCompression;
using System.IO.Compression;
using static Startup;
using System.Text.Json.Nodes;
using Newtonsoft.Json;
using System.Net.Http.Headers;
using Microsoft.CodeAnalysis.CSharp.Scripting;
using Microsoft.CodeAnalysis.Scripting;
using System.Reflection;
using CSScriptLib;
using System.Reflection.Metadata;

public class Program
{
    public static bool act = true;
    public static string WWWdir = "";
    public static string BackendDir = "/var/www";
    public static Config config;
    static Dictionary<string, X509Certificate2> Certs = new Dictionary<string, X509Certificate2>(StringComparer.InvariantCultureIgnoreCase);
    public static void Main(string[] args)
    {
        config = Config.Load(Path.Combine(Directory.GetCurrentDirectory(), "JonCsWebConfig.json"));
        config.MinRequestBodyDataRate = new MinDataRate(bytesPerSecond: config.bytesPerSecond, gracePeriod: TimeSpan.FromSeconds(config.gracePeriod));
        string certPath = args.FirstOrDefault(arg => arg.StartsWith("--certPath"))?.Split("=")[1] ?? config.CertDir;
        WWWdir = args.FirstOrDefault(arg => arg.StartsWith("--webPath"))?.Split("=")[1] ?? config.WWWdir;
        BackendDir = args.FirstOrDefault(arg => arg.StartsWith("--backend"))?.Split("=")[1] ?? config.BackendDir;
        bool HelpCmd = args.FirstOrDefault(arg => arg.StartsWith("--help")) != null;
        if(HelpCmd)
        {
            Console.WriteLine("--help | Lists commands.\n" +
                "--certPath=/etc/letsencrypt/live/ | Specify folder with folders of certificates. In your folder there should be folders named domain.org-0001, which should contain privkey.pem and fullchain.pem.\n" +
                "--webPath=/var/www/ | Path for static files. HTML/CSS/JS, etc. This is disabled by default.\n" +
                "--backend=/var/www | Path for where backend files and dynamic files will be found. index.njs, index.bun, index._cs.\n" +
                "--ip=127.0.0.1 | Change the IP. Default value is any.\n" +
                "--httpPort=80,8080 | Change the port(s) for HTTP. Comma-seperated. Default value is 80.\n" +
                "--httpsPort=443,8443 | Change the port(s) for HTTPS. Comma-seperated. Default value is 443.");
        }
        LoadCerts(certPath);
        IHost web = CreateHostBuilder(args).Build();
        Task.Run(() =>
        {
            string? cmd;
            while ((cmd = Console.ReadLine()) != "" && act)
            {
                string[] Args = cmd.Split(" ");
                switch (Args[0])
                {
                    case "help":
                        {
                            Console.WriteLine("help\nlistfiles\ncountfiles\nindexfiles\nloadcerts\nclearcerts\nstats\ngc");
                            break;
                        }
                    case "listfiles":
                        {
                            if (Args.Length > 1)
                            {
                                foreach (string path in Startup.FileLead.Keys)
                                {
                                    if (path.Contains(Args[1])) Console.WriteLine(path);
                                }
                            }
                            else
                                foreach (string path in Startup.FileLead.Keys)
                                {
                                    Console.WriteLine(path);
                                }
                            break;
                        }
                    case "countfiles":
                        {
                            if (Args.Length > 1)
                            {
                                Console.WriteLine(Startup.FileLead.Keys.Where(str => str.Contains(Args[1])).Count().ToString());
                            }
                            else
                            {
                                Console.WriteLine(Startup.FileLead.Count.ToString());
                            }
                            break;
                        }
                    case "indexfiles":
                        {
                            Startup.IndexFiles(BackendDir);
                            Console.WriteLine("Indexxed " + BackendDir);
                            break;
                        }
                    case "loadcerts":
                        {
                            LoadCerts(certPath);
                            break;
                        }
                    case "clearcerts":
                        {
                            Certs.Clear();
                            break;
                        }
                    case "stats":
                    case "statistics":
                    case "status":
                        {
                            GetMemoryUsage();
                            GetCPUUsage();
                            break;
                        }
                    case "gc":
                        {
                            Console.WriteLine("Collecting..");
                            GC.Collect();
                            Console.WriteLine("Collected.");
                            break;
                        }
                    case "reload":
                        {
                            config = Config.Load(Path.Combine(Directory.GetCurrentDirectory(), "JonCsWebConfig.json"));
                            config.MinRequestBodyDataRate = new MinDataRate(bytesPerSecond: config.bytesPerSecond, gracePeriod: TimeSpan.FromSeconds(config.gracePeriod));
                            Console.WriteLine("Reloaded!");
                            break;
                        }
                    case "shutdown":
                        {
                            Console.WriteLine("Shutting down..");
                            web.StopAsync();
                            act = false;
                            break;
                        }
                }
            }
        });
        Console.WriteLine("NOTE: Files are indexed in a case-insensitive manner. Rename your files appropriately if needed. :)");
        web.Run();
        Console.ReadLine();
    }
    public static void GetCPUUsage()
    {
        var process = Process.GetCurrentProcess();
        var initialCpuTime = process.TotalProcessorTime;
        var initialTime = DateTime.Now;

        // Wait for a short period to calculate CPU usage
        Thread.Sleep(1000);

        var finalCpuTime = process.TotalProcessorTime;
        var finalTime = DateTime.Now;

        var cpuUsage = (finalCpuTime - initialCpuTime).TotalMilliseconds / (finalTime - initialTime).TotalMilliseconds * 100;
        Console.WriteLine($"CPU Usage: {cpuUsage}%");
    }
    public static void GetMemoryUsage()
    {
        var process = Process.GetCurrentProcess();
        Console.WriteLine($"Memory Usage: {process.WorkingSet64 / (1024 * 1024)} MB");
    }

    public static IHostBuilder CreateHostBuilder(string[] args) =>
        Host.CreateDefaultBuilder(args)
            .ConfigureWebHostDefaults(webBuilder =>
            {
                webBuilder.ConfigureServices(services => {
                    services.AddResponseCompression(options =>
                    {
                        options.EnableForHttps = true;
                        options.Providers.Add<GzipCompressionProvider>();
                        options.Providers.Add<BrotliCompressionProvider>();
                        options.Providers.Add<DeflateCompressionProvider>();
                    });

                    services.Configure<GzipCompressionProviderOptions>(options =>
                    {
                        options.Level = System.IO.Compression.CompressionLevel.Fastest;
                    });
                });
                webBuilder.ConfigureLogging(logging => {
                    logging.ClearProviders();
                });
                webBuilder.ConfigureKestrel((context, options) =>
                {
                    options.AddServerHeader = false;
                    options.Limits.MaxConcurrentConnections = config.MaxConcurrentConnections;
                    options.Limits.MaxConcurrentUpgradedConnections = config.MaxConcurrentUpgradedConnections;
                    options.Limits.MinRequestBodyDataRate = config.MinRequestBodyDataRate; // Disable request rate limits
                    options.Limits.MaxRequestBodySize = config.MaxRequestBodySize;    // Allow unlimited body size
                    //ThreadPool.SetMinThreads(1000, 1000);

                    options.ConfigureHttpsDefaults(adapterOptions =>
                    {
                        if (Certs.TryGetValue("fallback", out X509Certificate2? cert) && cert != null) adapterOptions.ServerCertificate = cert;
                    });

                    IPAddress Ipaddress = IPAddress.Any;
                    try
                    {
                        string? CustomIp = args.FirstOrDefault(arg => arg.StartsWith("--ip"))?.Split("=")[1];
                        if(CustomIp != null) Ipaddress = IPAddress.Parse(CustomIp) ?? IPAddress.Any;
                    }
                    catch (Exception ex) {
                        Console.WriteLine(ex.ToString());
                    }
                    List<ushort> HttpPorts = new List<ushort>{ 80 };
                    List<ushort> HttpsPorts = new List<ushort>{ 443 };
                    try { 
                        string? InHttpPort = args.FirstOrDefault(arg => arg.StartsWith("--httpPort"))?.Split("=")[1];
                        if (InHttpPort != null)
                        {
                            string[] split = InHttpPort.Split(',');
                            HttpPorts.Clear();
                            for (byte i = 0; i < split.Length; i++) {
                                if (ushort.TryParse(split[i], out ushort port))
                                {
                                    HttpPorts.Add(port);
                                }
                            }
                        }
                    } catch (Exception) { }
                    try
                    {
                        string? InHttpPort = args.FirstOrDefault(arg => arg.StartsWith("--httpsPort"))?.Split("=")[1];
                        if (InHttpPort != null)
                        {
                            string[] split = InHttpPort.Split(',');
                            HttpsPorts.Clear();
                            for (byte i = 0; i < split.Length; i++)
                            {
                                if (ushort.TryParse(split[i], out ushort port))
                                {
                                    HttpsPorts.Add(port);
                                }
                            }
                        }
                    }
                    catch (Exception) { }
                    // HTTP listener
                    for (byte i = 0; i < HttpPorts.Count; i++)
                    {
                        Console.WriteLine("Listening for HTTP on port " + HttpPorts[i].ToString());
                        options.Listen(Ipaddress, HttpPorts[i]);  // HTTP (non-secure)
                    }

                    // HTTPS listener with dynamic TLS based on SNI
                    for (byte i = 0; i < HttpsPorts.Count; i++) options.Listen(Ipaddress, HttpsPorts[i], listenOptions =>
                    {
                        Console.WriteLine("Listening for HTTPS on port " + HttpsPorts[i].ToString());
                        listenOptions.Protocols = HttpProtocols.Http1AndHttp2AndHttp3;
                        listenOptions.UseHttps(httpsOptions => {
                            httpsOptions.ServerCertificateSelector = (features, name) =>
                            {
                                return name != null ? GetCertificateForHost(name) : Certs["fallback"];
                            };
                        });  
                    });
                });
                webBuilder.UseStartup<Startup>();
            });

    static void LoadCerts(string certPath)
    {
        Console.ForegroundColor = ConsoleColor.DarkYellow;
        Console.WriteLine("Use --certPath=<dir> to change certificates folder.");
        Console.ForegroundColor = ConsoleColor.Red;
        try
        {
            foreach (string dom in Directory.GetDirectories(certPath))
            {
                string domain = Path.GetFileName(dom);
                bool removeEnd = int.TryParse(domain.Substring(domain.Length - 4), out _);
                if (removeEnd) domain = domain.Substring(0, domain.Length - 5); // -0000
                try
                {
                    X509Certificate2 cert = X509Certificate2.CreateFromPemFile(
                        Path.Combine(dom, "fullchain.pem"),
                        Path.Combine(dom, "privkey.pem")
                    );
                    Certs[domain] = cert;
                    if (!Certs.ContainsKey("fallback")) Certs["fallback"] = Certs[domain];
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error loading certificate for {domain}: {ex.Message}");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex);
        }
        Console.ResetColor();
    }

    private static X509Certificate2 GetCertificateForHost(string host)
    {
        return Certs.TryGetValue(host, out var cert) ? cert : Certs["fallback"];
    }

}

public class Startup
{
    const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    string error404 = "<!DOCTYPE HTML><html><head><title>Err 404 - page not found</title><link href=\"/main.css\" rel=\"stylesheet\" /><meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" /></head><body><center><span style=\"font-size:24\">Error 404</span><h1 color=red>Page not found</h1><br />${0}<br /><p>Maybe we're working on adding this page.</p>${1}<br /><div style=\"display:inline-table;\"><iframe style=\"margin:auto\" src=\"https://discordapp.com/widget?id=473863639347232779&theme=dark\" width=\"350\" height=\"500\" allowtransparency=\"true\" frameborder=\"0\"></iframe><iframe style=\"margin:auto\" src=\"https://discordapp.com/widget?id=670549627455668245&theme=dark\" width=\"350\" height=\"500\" allowtransparency=\"true\" frameborder=\"0\"></iframe></div></center><br /><ul style=\"display:inline-block;float:right\"><li style='display:inline-block;background-image:url(\"/social-icons.png\");background-position:0px;'><a href=\"https://twitter.com/JonTVme\" style=\"display:block;text-indent:-9999px;width:25px;height:25px;\">Twitter</a></li><li style='display:inline-block;background-image:url(\"/social-icons.png\");background-position:--25px;'><a href=\"https://facebook.com/realJonTV\" style=\"display:block;text-indent:-9999px;width:25px;height:25px;\">Facebook</a></li><li style='display:inline-block;background-image:url(\"/social-icons.png\");background-position:-50px'><a href=\"https://reddit.com/r/JonTV\" style=\"display:block;text-indent:-9999px;width:25px;height:25px;\">Reddit</a></li><li style='display:inline-block;background-image:url(\"/social-icons.png\");background-position:-75px'><a href=\"https://discord.gg/4APyyak\" style=\"display:block;text-indent:-9999px;width:25px;height:25px;\">Discord server</a></li></ul><br /><sup><em>Did you know that you're old?</em></sup></body></html>";
    public static readonly ConcurrentDictionary<string, DateTime> FileIndex = new ConcurrentDictionary<string, DateTime>();
    public static readonly ConcurrentDictionary<string, Func<HttpContext, string, Task>> FileLead = new ConcurrentDictionary<string, Func<HttpContext, string, Task>>();
    public static ConcurrentDictionary<string, JsonObject> Sessions = new ConcurrentDictionary<string, JsonObject>();
    private static readonly Dictionary<string, Func<HttpContext, string, Task>> Extensions = new Dictionary<string, Func<HttpContext, string, Task>>();
    private static Timer _cleanupTimer;

    public void ConfigureServices(IServiceCollection services)
    {
        services.AddRouting();
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
            options.Level = System.IO.Compression.CompressionLevel.Fastest;
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
        if(Program.WWWdir != "")
        {
            app.UseStaticFiles(new StaticFileOptions {
                FileProvider = new PhysicalFileProvider(Path.Combine(Program.WWWdir)) //,
                //RequestPath = "/"
            });
        }
        app.UseResponseCompression();
        app.UseRouting();
        if(Program.BackendDir != "") app.UseEndpoints(endpoints =>
        {
            endpoints.Map("/{**catchAll}", async context =>
            {
                List<string> path = GetDomainBasedPath(context); // Extract the request path
                if(path.Count > Program.config.MaxDirDepth)
                {
                    context.Response.StatusCode = 414;
                    return;
                }
                foreach (KeyValuePair<string, string> header in Program.config.DefaultHeaders)
                {
                    context.Response.Headers[header.Key] = header.Value;
                }
                if (DateTime.TryParse(context.Request.Headers.IfModifiedSince, out DateTime LM))
                {
                    if (FileIndex.TryGetValue(string.Join("/", path), out DateTime LastMod))
                    {
                        if (LastMod <= LM)
                        {
                            context.Response.StatusCode = 304;
                            return;
                        }
                    }
                }
                string FileToUse = string.Join("/", path);
                if (!FileLead.TryGetValue(FileToUse, out var _Handler) && (path[path.Count - 1].Length < 1 || path[path.Count-1].Substring(path[path.Count - 1].Length-1) != "/")) // linking directly to a file or a directory
                {
                    while(!FileLead.TryGetValue((FileToUse=string.Join("/", path)), out _Handler) && !FileLead.TryGetValue((FileToUse = string.Join("/", path.Append("index._cs"))), out _Handler) && !FileLead.TryGetValue((FileToUse = string.Join("/", path.Append("index.njs"))), out _Handler) && !FileLead.TryGetValue((FileToUse = string.Join("/", path.Append("index.bun"))), out _Handler) && !FileLead.TryGetValue((FileToUse = string.Join("/", path.Append("index.phpdll"))), out _Handler) && !FileLead.TryGetValue((FileToUse = string.Join("/", path.Append("index.html"))), out _Handler) && path.Count > 2) // file does not exist
                    {
                        path.RemoveAt(path.Count-1);
                    }
                }
                if (_Handler != null)
                {
                    if (FileIndex.TryGetValue(FileToUse, out DateTime LastMod)) {
                        context.Response.Headers["last-modified"] = LastMod.ToString("R");
                        if (LastMod <= LM)
                        {
                            context.Response.StatusCode = 304;
                            return;
                        }
                    }
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
                await context.Response.WriteAsync(error404.Replace("${0}", path[1] == "jontvme" ? "<img src=\"/JonTV/JonTVplay_dark.svg\" class=\"spin\" />" : "<img src=\"//jonhosting.com/JonHost.png\" />").Replace("${1}", context.Request.Headers.Referer != "" ? "<p>You came from <a href=\""+ context.Request.Headers.Referer + "\">"+ context.Request.Headers.Referer + "</a>. Hmmm</p>":""));
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
        string[]? requestPath = context.Request.Path.Value?.Trim('/')?.Split("/")?.Where(str=>str!="")?.ToArray();
        if (requestPath != null && requestPath.Contains("..")) requestPath = null;
        List<string> fullPath = [Program.BackendDir, context.Request.Host.Value.Split(':')[0].Replace(".", "")];
        if(requestPath != null) fullPath.AddRange(requestPath);

        return fullPath;
    }
    private static async Task DefHandle(HttpContext context, string file)
    {
        if (context.Request.Method == HttpMethods.Options) return;
        await context.Response.SendFileAsync(file);
    }
    private static async Task DefDownload(HttpContext context, string file)
    {
        string fn = "undefined";
        string[] pa = file.Split("/");
        if (pa.Length > 0) fn = pa[pa.Length - 1];
        context.Response.Headers["content-disposition"] = "attachment; filename=" + fn;
        if (context.Request.Method == HttpMethods.Options) return;
        await context.Response.SendFileAsync(file);
    }
    static async Task<JsonObject?> GetSess(string? id) {
        if(id == null)
        {
            string nid = GenerateRandomId();
            byte attempt = 0;
            while(!Sessions.ContainsKey(id) && attempt < 5 && !File.Exists(Path.Combine(Program.config.SessDir, id)))
            {
                if (nid.Length > 128)
                {
                    nid = string.Empty;
                    attempt++;
                }
                nid += GenerateRandomId();
            }
            if (nid != string.Empty)
            {
                JsonObject ob = new JsonObject();
                ob.Add("id", nid);
                Sessions[nid] = ob;
                return ob;
            }
            return null;
        }
        if (Sessions.TryGetValue(id, out JsonObject? gg)) return gg;
        try
        {
            string Sess = await File.ReadAllTextAsync(Path.Combine(Program.config.SessDir, id));
            gg = JsonNode.Parse(Sess) as JsonObject;
            if (gg != null) Sessions[id] = gg;
            return gg;
        }
        catch (Exception)
        {
            return null;
        }
    }
    static string GenerateRandomId(int length = 8)
    {
        Random random = new Random();
        return new string(Enumerable.Range(0, length).Select(_ => chars[random.Next(chars.Length)]).ToArray());
    }
    private static HttpClientHandler handler = new HttpClientHandler();
    private static readonly HttpClient httpClient = new HttpClient(handler);
    private async Task ForwardRequestTo(HttpContext context, string targetUrl)
    {
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
        }catch(Exception e)
        {
            context.Response.StatusCode = 500;
            await context.Response.WriteAsync("Sorry. An error occurred.");
            Console.WriteLine(e);
            return;
        }
    }

    public static void IndexFiles(string rootDirectory)
    {
        foreach (string file in Directory.EnumerateFiles(rootDirectory, "*.*", SearchOption.AllDirectories))
        {
            string[] getExt = file.Split('.');
            string Ext = getExt[getExt.Length - 1];
            if (Ext == "_cs" && Program.config.Enable_CS)
            {
                try { CompileAndAddFunction(file); } catch (Exception) { }
                continue;
            }
            else if (Program.config.Enable_PHP)
            {
                if (Ext == "php")
                {
                    try { if(GenPhpAssembly(file)) LoadPhpAssembly(file); } catch (Exception) { }
                    continue;
                }else if(Ext == "phpdll")
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
                FileIndex[file] = fileInfo.LastWriteTimeUtc;
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
            if (Ext == "_cs" && Program.config.Enable_CS)
            {
                try { CompileAndAddFunction(filePath); } catch (Exception e) { Console.ForegroundColor = ConsoleColor.Red; Console.WriteLine(e); Console.ResetColor(); }
                return;
            }
            else if (Program.config.Enable_PHP && Ext == "php")
            {
                try { if(GenPhpAssembly(filePath)) LoadPhpAssembly(filePath); } catch (Exception) { }
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
                FileIndex[filePath] = fileInfo.LastWriteTimeUtc;
            }
        }
    }

    static void RemoveFromIndex(string filePath)
    {
        FileIndex.TryRemove(filePath, out _);
        FileLead.TryRemove(filePath, out _);
    }

    public static async void CompileAndAddFunction(string filePath)
    {
        // Read the code from the file
        string code = File.ReadAllText(filePath);
        // Define assembly paths for HttpContext and Task
        var taskAssembly = typeof(System.Threading.Tasks.Task).Assembly;
        var taskAssemblyLocation = taskAssembly.Location;  // This works even in packed scenarios
        var metadataReference = MetadataReference.CreateFromFile(taskAssemblyLocation);

        var references = new[]
{
    MetadataReference.CreateFromFile(typeof(object).Assembly.Location),
    MetadataReference.CreateFromFile(typeof(System.Threading.Tasks.Task).Assembly.Location), // Adds System.Threading.Tasks
    MetadataReference.CreateFromFile(typeof(System.Net.Http.HttpClient).Assembly.Location) // Adds other dependencies like HttpClient
};
        ScriptOptions options = ScriptOptions.Default.WithReferences(
        MetadataReference.CreateFromFile(Program.config.ThreadingDll),
        MetadataReference.CreateFromFile(Program.config.HttpDll)
    ).WithImports("System.Threading.Tasks", "Microsoft.AspNetCore.Http");
        // Create a script and compile it
        var script = CSharpScript.Create<Func<HttpContext, string, Task>>(code, options);
        script.Compile();
        var result = await script.RunAsync();
        // Add to the dictionary
        FileLead[filePath] = result.ReturnValue;
    }

    public static void LoadPhpAssembly(string filePath)
    {
        var assembly = Assembly.Load(File.ReadAllBytes(filePath+"dll"));

        // Find a specific class or method (depending on how your PHP script is structured)
        var type = assembly.GetType("Is_PhpScript"); // Use the namespace/class name in your PHP file.
        var method = type.GetMethod("Run"); // Assuming "Run" is the entry point.

        // Create a delegate for the method (this assumes it's compatible)
        Func<HttpContext, string, Task> phpFunction = (Func<HttpContext, string, Task>)Delegate.CreateDelegate(
            typeof(Func<HttpContext, string, Task>), method
        );

        // Add the delegate to your dictionary
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
        catch (Exception ex)
        {
            return false;
        }
    }
}
public class Globals
{
    public HttpContext context;
    public string path;
}


public class BackgroundTaskQueue
{
    private readonly SemaphoreSlim _signal = new SemaphoreSlim(0);
    private readonly Queue<Func<CancellationToken, Task>> _tasks = new Queue<Func<CancellationToken, Task>>();

    public void Enqueue(Func<CancellationToken, Task> task)
    {
        if (task == null) throw new ArgumentNullException(nameof(task));
        lock (_tasks)
        {
            _tasks.Enqueue(task);
        }
        _signal.Release();
    }

    public async Task<Func<CancellationToken, Task>> DequeueAsync(CancellationToken cancellationToken)
    {
        await _signal.WaitAsync(cancellationToken);
        lock (_tasks)
        {
            return _tasks.Dequeue();
        }
    }
}

// Worker Service
public class Worker : BackgroundService
{
    private readonly BackgroundTaskQueue _taskQueue;

    public Worker(BackgroundTaskQueue taskQueue)
    {
        _taskQueue = taskQueue;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            var task = await _taskQueue.DequeueAsync(stoppingToken);
            await task(stoppingToken);
        }
    }
}

public class Config
{
    public bool Enable_PHP { get; set; }
    public bool Enable_CS { get; set; }
    public long? MaxConcurrentConnections { get; set; }
    public long? MaxConcurrentUpgradedConnections { get; set; }
    public long? MaxRequestBodySize { get; set;}
    public double bytesPerSecond { get; set; }
    public int gracePeriod { get; set; }
    public int ClearSessEveryXMin { get; set; }
    public ushort MaxDirDepth { get; set; }
    public string CertDir { get; set; }
    public string WWWdir { get; set; }
    public string BackendDir { get; set; }
    public string SessDir { get; set; }
    public string Rand_Alphabet { get; set; }
    public string ThreadingDll { get; set; }
    public string HttpDll { get; set; }
    public List<string> DownloadIfExtension { get; set; }
    public Dictionary<string,string> ExtTypes { get; private set; } = new Dictionary<string, string>();
    public Dictionary<string, string> ForwardExt { get; private set; } = new Dictionary<string, string>();
    public Dictionary<string, string> DefaultHeaders { get; private set; } = new Dictionary<string, string>();

    [JsonIgnore]
    public MinDataRate? MinRequestBodyDataRate { get; set; }

    public void LoadDefaults()
    {
        Enable_PHP = false;
        Enable_CS = true;
        MaxConcurrentConnections = null;
        MaxConcurrentUpgradedConnections = 10000;
        MaxRequestBodySize = 30000000;
        bytesPerSecond = 240;
        gracePeriod = 5;
        ClearSessEveryXMin = 5;
        MaxDirDepth = 15;
        CertDir = "/etc/letsencrypt/live/";
        WWWdir = "";
        BackendDir = "/var/www";
        SessDir = "/var/sess/";
        Rand_Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        ThreadingDll = "./System.Threading.Tasks.dll";
        HttpDll = "./Microsoft.AspNetCore.Http.dll";
        DownloadIfExtension = new List<string>() {
            "zip",
            "jar",
            "dll",
            "exe"
        };
        ExtTypes = new Dictionary<string, string>()
        {
            ["html"] = "text/html",
            ["txt"] = "text/plain",
            ["log"] = "text/plain",
            ["css"] = "text/css",
            ["js"] = "application/javascript",
            ["json"] = "application/json",
            ["pdf"] = "application/pdf",
            ["jpg"] = "image/jpeg",
            ["svg"] = "image/svg+xml",
            ["mp3"] = "audio/mpeg",
        };
        ForwardExt = new Dictionary<string, string>()
        {
            ["njs"] = "http://{domain}:3000",
            ["bun"] = "http://{domain}:3000"
        };
        foreach (string g in new string[] { "wav", "ogg" })
        {
            ExtTypes[g] = "audio/" + g;
        }
        foreach (string g in new string[] { "mp4", "flv", "mkv", "wmf", "avi", "webm" })
        {
            ExtTypes[g] = "video/" + g;
        }
        DefaultHeaders["Server"] = "JH";
        DefaultHeaders["vary"] = "Accept-Encoding";
        DefaultHeaders["Accept-Ranges"] = "bytes";
        DefaultHeaders["Access-Control-Allow-Origin"] = "*";
        DefaultHeaders["cache-control"] = "max-age=31536000";

        MinRequestBodyDataRate = new MinDataRate(bytesPerSecond: bytesPerSecond, gracePeriod: TimeSpan.FromSeconds(gracePeriod));
    }
    public static Config Load(string filePath)
    {
        if (!File.Exists(filePath))
        {
            Config config = new Config();
            config.LoadDefaults();
            File.WriteAllText(filePath, JsonConvert.SerializeObject(config, Newtonsoft.Json.Formatting.Indented));
            return config;
        }

        string json = File.ReadAllText(filePath);
        return JsonConvert.DeserializeObject<Config>(json);
    }

    public async void Save(string filePath)
    {
        string json = JsonConvert.SerializeObject(this, Newtonsoft.Json.Formatting.Indented);
        await File.WriteAllTextAsync(filePath, json);
    }
}