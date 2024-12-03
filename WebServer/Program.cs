using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Hosting;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Collections.Generic;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.AspNetCore.Http;
using System.Runtime.ConstrainedExecution;
using Microsoft.Extensions.FileProviders;
using System.Runtime.CompilerServices;
using Microsoft.Extensions.Logging;
using System.Collections.Concurrent;
using System.Reflection;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis;
using System.Diagnostics;
using Microsoft.AspNetCore.ResponseCompression;
using System.IO.Compression;
using static Startup;

public class Program
{
    public static bool act = true;
    public static string WWWdir = "";
    public static string BackendDir = "/var/www";
    public static string NjsEndpoint = "http://{domain}:3000";
    public static string BunEndpoint = "http://{domain}:3000";
    static Dictionary<string, X509Certificate2> Certs = new Dictionary<string, X509Certificate2>(StringComparer.InvariantCultureIgnoreCase);
    public static void Main(string[] args)
    {
        string certPath = args.FirstOrDefault(arg => arg.StartsWith("--certPath"))?.Split("=")[1] ?? "/etc/letsencrypt/live/";
        WWWdir = args.FirstOrDefault(arg => arg.StartsWith("--webPath"))?.Split("=")[1] ?? "";
        BackendDir = args.FirstOrDefault(arg => arg.StartsWith("--backend"))?.Split("=")[1] ?? "/var/www";
        NjsEndpoint = args.FirstOrDefault(arg => arg.StartsWith("--njsEndpoint"))?.Split("=")[1] ?? "http://{domain}:3000";
        BunEndpoint = args.FirstOrDefault(arg => arg.StartsWith("--bunEndpoint"))?.Split("=")[1] ?? "http://{domain}:3000";
        bool HelpCmd = args.FirstOrDefault(arg => arg.StartsWith("--help")) != null;
        if(HelpCmd)
        {
            Console.WriteLine("--help | Lists commands.\n" +
                "--certPath=/etc/letsencrypt/live/ | Specify folder with folders of certificates. In your folder there should be folders named domain.org-0001, which should contain privkey.pem and fullchain.pem.\n" +
                "--webPath=/var/www/ | Path for static files. HTML/CSS/JS, etc. This is disabled by default.\n" +
                "--backend=/var/www | Path for where backend files and dynamic files will be found. index.njs, index.bun, index._cs.\n" +
                "--ip=127.0.0.1 | Change the IP. Default value is any.\n" +
                "--httpPort=80,8080 | Change the port(s) for HTTP. Comma-seperated. Default value is 80.\n" +
                "--httpsPort=443,8443 | Change the port(s) for HTTPS. Comma-seperated. Default value is 443.\n" +
                "--njsEndpoint=http://{domain}:3000 | Set the endpoint for .njs files.\n" +
                "--bunEndpoint=http://{domain}:3000 | Set the endpoint for .bun files.");
        }
        LoadCerts(certPath);
        IHost web = CreateHostBuilder(args).Build();
        Task.Run(() =>
        {
            string? cmd;
            while ((cmd = Console.ReadLine()) != "" && act)
            {
                string[] Args = cmd.Split(" ");
                if (Args[0] == "help")
                {
                    Console.WriteLine("help\nlistfiles\ncountfiles\nindexfiles\nloadcerts\nclearcerts\nstats\ngc");
                }
                else
                if (Args[0] == "listfiles")
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
                }
                else
                if (Args[0] == "countfiles")
                {
                    if (Args.Length > 1)
                    {
                        Console.WriteLine(Startup.FileLead.Keys.Where(str => str.Contains(Args[1])).Count().ToString());
                    }
                    else
                    {
                        Console.WriteLine(Startup.FileLead.Count.ToString());
                    }
                }
                else
                if (Args[0] == "indexfiles")
                {
                    Startup.IndexFiles(BackendDir);
                }
                else if (Args[0] == "shutdown")
                {
                    Console.WriteLine("Shutting down..");
                    web.StopAsync();
                    act = false;
                }
                else if (Args[0] == "loadcerts")
                {
                    LoadCerts(certPath);
                }else if (Args[0] == "clearcerts")
                {
                    Certs.Clear();
                }else if (Args[0] == "stats")
                {
                    GetMemoryUsage();
                    GetCPUUsage();
                }else if (Args[0] == "gc")
                {
                    Console.WriteLine("Collecting..");
                    GC.Collect();
                    Console.WriteLine("Collected.");
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
                    //options.Limits.MaxConcurrentConnections = 100000;
                    options.Limits.MaxConcurrentUpgradedConnections = 10000;
                    //options.Limits.MinRequestBodyDataRate = null; // Disable request rate limits
                    //options.Limits.MaxRequestBodySize = null;    // Allow unlimited body size
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
        Console.WriteLine("Use --certPath <dir> to modify the certificates folder.");
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
    string error404 = "<!DOCTYPE HTML><html><head><title>Err 404 - page not found</title><link href=\"/main.css\" rel=\"stylesheet\" /><meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" /></head><body><center><span style=\"font-size:24\">Error 404</span><h1 color=red>Page not found</h1><br />${0}<br /><p>Maybe we're working on adding this page.</p>${1}<br /><div style=\"display:inline-table;\"><iframe style=\"margin:auto\" src=\"https://discordapp.com/widget?id=473863639347232779&theme=dark\" width=\"350\" height=\"500\" allowtransparency=\"true\" frameborder=\"0\"></iframe><iframe style=\"margin:auto\" src=\"https://discordapp.com/widget?id=670549627455668245&theme=dark\" width=\"350\" height=\"500\" allowtransparency=\"true\" frameborder=\"0\"></iframe></div></center><br /><ul style=\"display:inline-block;float:right\"><li style='display:inline-block;background-image:url(\"/social-icons.png\");background-position:0px;'><a href=\"https://twitter.com/JonTVme\" style=\"display:block;text-indent:-9999px;width:25px;height:25px;\">Twitter</a></li><li style='display:inline-block;background-image:url(\"/social-icons.png\");background-position:--25px;'><a href=\"https://facebook.com/realJonTV\" style=\"display:block;text-indent:-9999px;width:25px;height:25px;\">Facebook</a></li><li style='display:inline-block;background-image:url(\"/social-icons.png\");background-position:-50px'><a href=\"https://reddit.com/r/JonTV\" style=\"display:block;text-indent:-9999px;width:25px;height:25px;\">Reddit</a></li><li style='display:inline-block;background-image:url(\"/social-icons.png\");background-position:-75px'><a href=\"https://discord.gg/4APyyak\" style=\"display:block;text-indent:-9999px;width:25px;height:25px;\">Discord server</a></li></ul><br /><sup><em>Did you know that you're old?</em></sup></body></html>";
    public static readonly ConcurrentDictionary<string, DateTime> FileIndex = new ConcurrentDictionary<string, DateTime>();
    public static readonly ConcurrentDictionary<string, Func<HttpContext, string, Task>> FileLead = new ConcurrentDictionary<string, Func<HttpContext, string, Task>>();
    public static readonly Dictionary<string, string> ExtTypes = new Dictionary<string, string>();
    private static readonly Dictionary<string, Func<HttpContext, string, Task>> Extensions = new Dictionary<string, Func<HttpContext, string, Task>>();
    
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
        app.UseEndpoints(endpoints =>
        {
            endpoints.Map("/{**catchAll}", async context =>
            {
                context.Response.Headers["Server"] = "JH";
                context.Response.Headers["vary"] = "Accept-Encoding";
                context.Response.Headers["Accept-Ranges"] = "bytes";
                context.Response.Headers["Access-Control-Allow-Origin"] = "*";
                context.Response.Headers["cache-control"] = "max-age=31536000";

                List<string> path = GetDomainBasedPath(context); // Extract the request path
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
                    while(!FileLead.TryGetValue((FileToUse=string.Join("/", path)), out _Handler) && !FileLead.TryGetValue((FileToUse = string.Join("/", path.Append("index.njs"))), out _Handler) && !FileLead.TryGetValue((FileToUse = string.Join("/", path.Append("index.html"))), out _Handler) && path.Count > 2) // file does not exist
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
                    if (ExtTypes.TryGetValue(FileToUse, out string? ctype))
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
        Extensions["njs"] = ForwardRequestToNodeJs;
        Extensions["bun"] = ForwardRequestToBunJs;
        Extensions["zip"] = DefDownload;
        Extensions["jar"] = DefDownload;
        Extensions["dll"] = DefDownload;
        Extensions["exe"] = DefDownload;
        ExtTypes["html"] = "text/html";
        ExtTypes["txt"] = "text/plain";
        ExtTypes["log"] = "text/plain";
        ExtTypes["css"] = "text/css";
        ExtTypes["js"] = "application/javascript";
        ExtTypes["json"] = "application/json";
        ExtTypes["pdf"] = "application/pdf";
        foreach (string g in new string[]{ "jpeg", "png", "gif", "webp", "ico"}) {
            ExtTypes[g] = "image/" + g;
        }
        ExtTypes["jpg"] = "image/jpeg";
        ExtTypes["svg"] = "image/svg+xml";
        foreach (string g in new string[] { "wav", "ogg" })
        {
            ExtTypes[g] = "audio/" + g;
        }
        ExtTypes["mp3"] = "audio/mpeg";
        foreach (string g in new string[] { "mp4", "flv", "mkv", "wmf", "avi", "webm" })
        {
            ExtTypes[g] = "video/" + g;
        }

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
        await context.Response.SendFileAsync(file);
    }
    private static async Task DefDownload(HttpContext context, string file)
    {
        string fn = "undefined";
        string[] pa = file.Split("/");
        if (pa.Length > 0) fn = pa[pa.Length - 1];
        context.Response.Headers["content-disposition"] = "attachment; filename=" + fn;
        await context.Response.SendFileAsync(file);
    }
    private static readonly HttpClient httpClient = new HttpClient();
    private async Task ForwardRequestToNodeJs(HttpContext context, string backendFilePath)
    {
        string targetUrl = $"{Program.NjsEndpoint.Replace("{domain}", context.Request.Host.Value)}{backendFilePath}";
        await ForwardRequestTo(context, targetUrl);
    }
    private async Task ForwardRequestTo(HttpContext context, string targetUrl)
    {
        try
        {
            HttpRequestMessage requestMessage = new HttpRequestMessage
            {
                Method = new HttpMethod(context.Request.Method),
                RequestUri = new Uri(targetUrl + context.Request.Path + context.Request.QueryString),
                Content = new StreamContent(context.Request.Body)
            };
            foreach (var header in context.Request.Headers)
            {
                requestMessage.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray());
            }
            var responseMessage = await httpClient.SendAsync(requestMessage, HttpCompletionOption.ResponseHeadersRead);
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

            return;
        }catch(Exception)
        {
            context.Response.StatusCode = 500;
            await context.Response.WriteAsync("Sorry. An error occurred.");
            return;
        }
    }
    private async Task ForwardRequestToBunJs(HttpContext context, string backendFilePath)
    {
        string targetUrl = $"{Program.BunEndpoint.Replace("{domain}", context.Request.Host.Value)}{backendFilePath}";
        await ForwardRequestTo(context, targetUrl);
    }

    public static void IndexFiles(string rootDirectory)
    {
        foreach (string file in Directory.EnumerateFiles(rootDirectory, "*.*", SearchOption.AllDirectories))
        {
            string[] getExt = file.Split('.');
            string Ext = getExt[getExt.Length - 1];
            if(Ext == "_cs") {
                try { CompileAndAddFunction(file); }catch(Exception) { }
                return;
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
            if (Ext == "_cs")
            {
                try { CompileAndAddFunction(filePath); } catch (Exception) { }
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

    public static void CompileAndAddFunction(string filePath)
    {
        string sourceCode = File.ReadAllText(filePath);

        // Compile the code
        SyntaxTree syntaxTree = CSharpSyntaxTree.ParseText(sourceCode);
        var compilation = CSharpCompilation.Create(
            assemblyName: Path.GetFileNameWithoutExtension(filePath),
            syntaxTrees: new[] { syntaxTree },
            references: new[]
            {
            MetadataReference.CreateFromFile(typeof(object).Assembly.Location), // Core assemblies
            MetadataReference.CreateFromFile(typeof(HttpContext).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Task).Assembly.Location)
            },
            options: new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));

        using (var ms = new MemoryStream())
        {
            var result = compilation.Emit(ms);

            if (!result.Success)
            {
                foreach (var diagnostic in result.Diagnostics)
                    Console.WriteLine(diagnostic.ToString());
                return; // Compilation failed
            }

            // Load the assembly
            ms.Seek(0, SeekOrigin.Begin);
            Assembly assembly = System.Reflection.Assembly.Load(ms.ToArray());

            // Assuming a class "DynamicCode" with a method "Run"
            Type? type = assembly.GetType("DynamicCode");
            MethodInfo? method = type?.GetMethod("Run");

            if (method == null || !(method.CreateDelegate(typeof(Func<HttpContext, string, Task>)) is Func<HttpContext, string, Task>))
            {
                Console.WriteLine($"Invalid function signature in file {filePath}");
                return;
            }

            // Add to the dictionary
            Func<HttpContext, string, Task> func = (Func<HttpContext, string, Task>)method.CreateDelegate(typeof(Func<HttpContext, string, Task>));
            FileLead[filePath] = func;
        }
    }
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
