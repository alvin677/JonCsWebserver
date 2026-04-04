using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.ResponseCompression;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.CodeAnalysis;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml.Linq;
using WebServer;

public class Program
{
    public static bool act = true;
    public static ulong totalRequests = 0;
    public static ulong[] requestMetrics = new ulong[3]; // second, minute, hour
    public static string[] wordMetrics = new string[3] { "second", "minute", "hour" };
    // public static string WWWdir = "";
    // public static string BackendDir = "/var/www";
    // public static string LocalIP = IPFinder.GetLocalIPAddress();
    // public static Config config = new Config();
    public static CancellationTokenSource MetricsCts = new CancellationTokenSource();
    static Dictionary<string, X509Certificate2> Certs = new Dictionary<string, X509Certificate2>(StringComparer.OrdinalIgnoreCase);
    static X509Certificate2? fallbackCert = null;
    public static void Main(string[] args)
    {
        Startup.config = Config.Load(Path.Combine(Directory.GetCurrentDirectory(), "JonCsWebConfig.json"));
        Startup.config.FriendlyHeadersToOptimized();
        Startup.config.MinRequestBodyDataRate = new MinDataRate(bytesPerSecond: Startup.config.bytesPerSecond, gracePeriod: TimeSpan.FromSeconds(Startup.config.gracePeriod));
        string certPath = args.FirstOrDefault(arg => arg.StartsWith("--certPath"))?.Split("=")[1] ?? Startup.config.CertDir;
        Startup.WWWdir = args.FirstOrDefault(arg => arg.StartsWith("--webPath"))?.Split("=")[1] ?? Startup.config.WWWdir;
        Startup.BackendDir = args.FirstOrDefault(arg => arg.StartsWith("--backend"))?.Split("=")[1] ?? Startup.config.BackendDir;
        bool TestSess = args.FirstOrDefault(arg => arg.StartsWith("--testSess")) != null;
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
        if (TestSess) {
            Dictionary<string,string>? data = Session.GetSess(Startup.config.SessionCookieName).Result;
            if(data != null) _ = Session.SaveSess(data["id"], data);
        }
        LoadCerts(certPath);
        IHost web = CreateHostBuilder(args).Build();
        Task.Run(async () =>
        {
            string? cmd;
            while (act && (cmd = Console.ReadLine()) != null)
            {
                string[] Args = cmd.Split(' ');
                switch (Args[0])
                {
                    case "help":
                        {
                            Console.WriteLine("Commands:\nhelp\nlistfiles [Optional search]\ncountfiles [Optional search]\nindexfiles [/subpath]\nloadcerts\nclearcerts\nlistcerts\nstats (RAM and CPU usage)\ngc (manually trigger garbage collector)");
                            break;
                        }
                    case "listfiles":
                        {
                            if(Startup.FileLead.Count < 10) {
                                Console.WriteLine("There are " + Startup.FileLead.Count.ToString() + " files indexed.");
                            }
                            if (Args.Length > 1)
                            {
                                foreach (var entry in Startup.FileLead.Values)
                                {
                                    if (entry.FilePath.Contains(Args[1])) Console.WriteLine(entry.FilePath);
                                }
                            }
                            else
                                foreach (var entry in Startup.FileLead.Values)
                                {
                                    Console.WriteLine(entry.FilePath);
                                }
                            break;
                        }
                    case "countfiles":
                        {
                            if (Args.Length > 1)
                            {
                                Console.WriteLine(Startup.FileLead.Values.Where(entry => entry.FilePath.Contains(Args[1])).Count().ToString());
                            }
                            else
                            {
                                Console.WriteLine(Startup.FileLead.Count.ToString());
                            }
                            break;
                        }
                    case "indexfiles":
                        {
                            string indx = Startup.BackendDir + String.Join(' ', Args.Skip(1));
                            _ = Task.Run(()=>
                            {
                                Startup.IndexFiles(indx);
                                Startup.IndexDirectories(indx);
                                Startup.IndexErrorPages(Startup.BackendDir);
                                Console.WriteLine("Indexed " + indx);
                            }); // prevent stalling + prevent crashing from invalid path
                            Console.WriteLine("Indexing " + indx);
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
                            fallbackCert = null;
                            break;
                        }
                    case "listcerts":
                        {
                            Console.WriteLine("There are " + Certs.Count.ToString() + " certificates in cache.");
                            foreach (string certDom in Certs.Keys) {
                                Console.WriteLine(certDom);
                            }
                            break;
                        }
                    case "stats":
                    case "statistics":
                    case "status":
                        {
                            DisplayMetrics();
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
                    case "memleak":
                        {
                            Console.WriteLine("FileLead: "+Startup.FileLead.Count);
                            Console.WriteLine("FileIndex: "+Startup.FileIndex.Count);
                            Console.WriteLine("Sessions: "+Startup.Sessions.Count);
                            break;
                        }
                    case "reload":
                        {
                            Startup.config = Config.Load(Path.Combine(Directory.GetCurrentDirectory(), "JonCsWebConfig.json"));
                            Startup.config.FriendlyHeadersToOptimized();
                            Startup.config.MinRequestBodyDataRate = new MinDataRate(bytesPerSecond: Startup.config.bytesPerSecond, gracePeriod: TimeSpan.FromSeconds(Startup.config.gracePeriod));
                            _ = Task.Run(()=>Startup.Reload2());
                            Console.WriteLine("Reloaded!");
                            break;
                        }
                    case "shutdown":
                        {
                            Console.WriteLine("Shutting down JonCsWebServer..");
                            MetricsCts.Cancel();
                            MetricsCts.Dispose();
                            _ = web.StopAsync();
                            act = false;
                            break;
                        }
                    case "restart":
                        {
                            await web.StopAsync();
                            Console.WriteLine("Successfully shutdown. Starting now..");
                            _ = web.StartAsync();
                            web.Run();
                            break;
                        }
                    default:
                        {
                            Console.WriteLine("Unknown command. Type 'help' for help.");
                            break;
                        }
                }
            }
        });
        Console.WriteLine("NOTE: Files are indexed in a case-insensitive manner. Rename your files appropriately if needed.");
        StartMetricsTimer();
        web.Run();
        Console.WriteLine("Press enter to exit..");
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
    private static ulong _lastSecond = 0, _lastMinute = 0, _lastHour = 0;
    private static int _secondTick = 0, _minuteTick = 0;
    public static void StartMetricsTimer()
    {
        if (!Startup.config.ServerMetrics) return;
        _ = Task.Run(async () =>
        {
            Console.WriteLine("Metrics timer started.");
            while (!MetricsCts.Token.IsCancellationRequested)
            {
                await Task.Delay(1000, MetricsCts.Token).ConfigureAwait(false);
                ulong current = Volatile.Read(ref totalRequests);

                // per second
                requestMetrics[0] = current - _lastSecond;
                _lastSecond = current;

                // per minute (every 60 ticks)
                if (++_secondTick >= 60)
                {
                    requestMetrics[1] = current - _lastMinute;
                    _lastMinute = current;
                    _secondTick = 0;
                }

                // per hour (every 60 minute ticks)
                if (++_minuteTick >= 3600)
                {
                    requestMetrics[2] = current - _lastHour;
                    _lastHour = current;
                    _minuteTick = 0;
                }
            }
        });
    }
    public static void DisplayMetrics()
    {
        if (!Startup.config.ServerMetrics) return;
        Console.WriteLine("Total since startup: " + totalRequests);
        for (int i = 0; i < requestMetrics.Length; i++)
        {
            Console.WriteLine(requestMetrics[i] + " req/" + wordMetrics[i]);
        }
    }
    public static IHostBuilder CreateHostBuilder(string[] args) =>
        Host.CreateDefaultBuilder(args)
            .ConfigureWebHostDefaults(webBuilder =>
            {
                webBuilder.ConfigureServices(services => {
                    services.AddResponseCompression(options =>
                    {
                        /*
                        options.MimeTypes = ResponseCompressionDefaults.MimeTypes.Except(new[]{
                            "video/mp4", "video/webm", "audio/mpeg",
                            "image/jpeg", "image/png", "image/webp", "image/gif"
                        });
                        */
                        // options.ExcludedMimeTypes = new[] {"video/mp4", "video/webm", "audio/mpeg", "image/jpeg", "image/png", "image/webp", "image/gif"}; // this one exists
                        options.EnableForHttps = true;
                        options.Providers.Add<GzipCompressionProvider>();
                        options.Providers.Add<BrotliCompressionProvider>();
                        options.Providers.Add<Startup.DeflateCompressionProvider>();
                    });

                    services.Configure<GzipCompressionProviderOptions>(options =>
                    {
                        options.Level = Startup.config.CompressionLevel;
                    });
                });
                webBuilder.ConfigureLogging(logging => {
                    logging.ClearProviders();
                });
                webBuilder.ConfigureKestrel((context, options) =>
                {
                    options.AddServerHeader = false;
                    options.Limits.MaxConcurrentConnections = Startup.config.MaxConcurrentConnections;
                    options.Limits.MaxConcurrentUpgradedConnections = Startup.config.MaxConcurrentUpgradedConnections;
                    options.Limits.MinRequestBodyDataRate = Startup.config.MinRequestBodyDataRate;
                    options.Limits.MaxRequestBodySize = Startup.config.MaxRequestBodySize;
                    options.Limits.KeepAliveTimeout = TimeSpan.FromSeconds(Startup.config.KeepAliveTimeout); // 130
                    options.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(Startup.config.RequestHeadersTimeout); // 30
                    options.AllowSynchronousIO = Startup.config.AllowSynchronousIO;
                    //ThreadPool.SetMinThreads(1000, 1000);

                    options.ConfigureHttpsDefaults(adapterOptions =>
                    {
                        adapterOptions.ServerCertificate = fallbackCert;
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
                    List<ushort> HttpPorts = new List<ushort>(Startup.config.HttpPorts);
                    List<ushort> HttpsPorts = new List<ushort>(Startup.config.HttpsPorts);
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
                        Console.WriteLine("Listening for HTTP on IP " + Ipaddress + " and port " + HttpPorts[i].ToString());
                        options.Listen(Ipaddress, HttpPorts[i]);  // HTTP (non-secure)
                    }

                    // HTTPS listener with dynamic TLS based on SNI
                    for (byte i = 0; i < HttpsPorts.Count; i++) options.Listen(Ipaddress, HttpsPorts[i], listenOptions =>
                    {
                        Console.WriteLine("Listening for HTTPS on IP " + Ipaddress + " and port " + HttpsPorts[i].ToString());
                        listenOptions.Protocols = HttpProtocols.Http1AndHttp2AndHttp3;
                        listenOptions.UseHttps(httpsOptions => {
                            httpsOptions.ServerCertificateSelector = (features, name) =>
                            {
                                if (Certs.TryGetValue(name!, out X509Certificate2? Cert))
                                    return Cert;
                                return fallbackCert;
                            };
                        });  
                    });
                });
                webBuilder.UseStartup<Startup>();
            });
    public static void LoadCerts(string certPath)
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

                    if (fallbackCert == null) fallbackCert = cert;

                    List<string> domains = GetDomainsFromCertificate(cert);
                    for (int i = 0; i < domains.Count; i++)
                    {
                        string d = domains[i];

                        if (!Certs.TryGetValue(d, out X509Certificate2? Cert) || Cert.NotAfter < cert.NotAfter)
                        {
                            Cert = cert;
                            Certs[d] = Cert;
                        }
                    }
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
    private static List<string> GetDomainsFromCertificate(X509Certificate2 cert)
    {
        var domains = new List<string>();

        foreach (var ext in cert.Extensions)
        {
            if (ext.Oid?.Value == "2.5.29.17") // Subject Alternative Name
            {
                AsnEncodedData asnData = new AsnEncodedData(ext.Oid, ext.RawData);
                string sanString = asnData.Format(false);
                string[] parts = sanString.Split(new[] { ", " }, StringSplitOptions.RemoveEmptyEntries);
                foreach (var part in parts)
                {
                    if (part.StartsWith("DNS Name="))
                        domains.Add(part.Substring(9));
                }
            }
        }

        return domains;
    }
}