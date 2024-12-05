using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Hosting;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Logging;
using Microsoft.CodeAnalysis;
using System.Diagnostics;
using Microsoft.AspNetCore.ResponseCompression;
using WebServer;
using System.Collections.Immutable;

public class Program
{
    public static bool act = true;
    public static string WWWdir = "";
    public static string BackendDir = "/var/www";
    public static Config config = new Config();
    static Dictionary<string, X509Certificate2> Certs = new Dictionary<string, X509Certificate2>(StringComparer.InvariantCultureIgnoreCase);
    public static void Main(string[] args)
    {
        config = Config.Load(Path.Combine(Directory.GetCurrentDirectory(), "JonCsWebConfig.json"));
        config.MinRequestBodyDataRate = new MinDataRate(bytesPerSecond: config.bytesPerSecond, gracePeriod: TimeSpan.FromSeconds(config.gracePeriod));
        string certPath = args.FirstOrDefault(arg => arg.StartsWith("--certPath"))?.Split("=")[1] ?? config.CertDir;
        WWWdir = args.FirstOrDefault(arg => arg.StartsWith("--webPath"))?.Split("=")[1] ?? config.WWWdir;
        BackendDir = args.FirstOrDefault(arg => arg.StartsWith("--backend"))?.Split("=")[1] ?? config.BackendDir;
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
            Dictionary<string,string>? data = Session.GetSess("Test").Result;
            if(data != null) _ = Session.SaveSess(data["id"], data);
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
                        options.Providers.Add<Startup.DeflateCompressionProvider>();
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