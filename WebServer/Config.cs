using Microsoft.AspNetCore.Server.Kestrel.Core;
using Newtonsoft.Json;
using System.Net;

namespace WebServer
{
    public class Config
    {
        public bool Enable_PHP { get; set; }
        public bool Enable_CS { get; set; }
        public long? MaxConcurrentConnections { get; set; }
        public long? MaxConcurrentUpgradedConnections { get; set; }
        public long? MaxRequestBodySize { get; set; }
        public double bytesPerSecond { get; set; }
        public int gracePeriod { get; set; }
        public uint ClearSessEveryXMin { get; set; }
        public uint WebSocketTimeout { get; set; }
        public uint WebSocketEndpointTimeout { get; set; }
        public ushort MaxDirDepth { get; set; }
        public string CertDir { get; set; } = "";
        public string WWWdir { get; set; } = "";
        public string BackendDir { get; set; } = "";
        public string SessionsDir { get; set; } = "";
        public string SessionCookieName { get; set; } = "";
        public string Rand_Alphabet { get; set; } = "";
        public string FilterFromDomain { get; set; } = "";
        public string DomainFilterTo { get; set; } = "";
        // public string PHP_FPM { get; set; } = "";
        public string ThreadingDll { get; set; } = "";
        public string HttpDll { get; set; } = "";
        public string[] indexPriority { get; set; } = [];
        public string[] DownloadIfExtension { get; set; } = [];
        public ushort[] HttpsPorts { get; set; } = [];
        public ushort[] HttpPorts { get; set; } = [];
        public System.IO.Compression.CompressionLevel CompressionLevel { get; set; }
        public Dictionary<string, string> ExtTypes { get; private set; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, string> ForwardExt { get; private set; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, string> DefaultHeaders { get; private set; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, string> DomainAlias { get; private set; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, string> UrlAlias { get; private set; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

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
            WebSocketTimeout = 300;
            WebSocketEndpointTimeout = 30;
            MaxDirDepth = 15;
            HttpsPorts = [ 443 ];
            HttpPorts = [ 80 ];
            CertDir = "/etc/letsencrypt/live/";
            WWWdir = "";
            BackendDir = "/var/www";
            SessionsDir = "/var/sess/";
            SessionCookieName = "SSID";
            FilterFromDomain = ".";
            DomainFilterTo = "";
            // PHP_FPM = IPAddress.Loopback.ToString() + ":9001";
            Rand_Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            ThreadingDll = "./System.Threading.Tasks.dll";
            HttpDll = "./Microsoft.AspNetCore.Http.dll";
            indexPriority = ["index._csdll", "index._cs", "index.phpdll", "index.php", "index.njs", "index.bun", "index.html", "index.htm"];
            CompressionLevel = System.IO.Compression.CompressionLevel.Optimal;
            DownloadIfExtension = [
            "zip",
            "jar",
            "dll",
            "exe"
            ];
            ExtTypes = new Dictionary<string, string>()
            {
                ["html"] = "text/html",
                ["txt"] = "text/plain",
                ["log"] = "text/plain",
                ["css"] = "text/css",
                ["jpg"] = "image/jpeg",
                ["svg"] = "image/svg+xml",
                ["mp3"] = "audio/mpeg",
            };
            ForwardExt = new Dictionary<string, string>()
            {
                ["njs"] = "http://{domain}:3000",
                ["bun"] = "http://{domain}:3000"
            };
            ExtTypes["js"] = "application/javascript";
            foreach (string g in new string[] { "json", "pdf", "zip", "jar", "dll", "exe" })
            {
                ExtTypes[g] = "application/" + g;
            }
            foreach (string g in new string[] { "png", "jpeg", "gif", "webp", "ico" })
            {
                ExtTypes[g] = "image/" + g;
            }
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

            DomainAlias = new Dictionary<string, string>()
            {
                ["www.jonhosting.com"] = "jonhosting.com",
                ["www.jontv.me"] = "jontv.me"
            };

            UrlAlias = new Dictionary<string, string>()
            {
                ["jonhosting.com/testing1234"] = "/test2_maybe_use_symlink_instead/useDomainAlias_for_changing_domain_virtually"
            };

            // MinRequestBodyDataRate = new MinDataRate(bytesPerSecond: bytesPerSecond, gracePeriod: TimeSpan.FromSeconds(gracePeriod));
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
}