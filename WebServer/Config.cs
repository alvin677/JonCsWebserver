using Microsoft.AspNetCore.Server.Kestrel.Core;
using Newtonsoft.Json;

namespace WebServer
{
    public class Config
    {
        public bool Enable_PHP { get; set; }
        public bool Enable_CS { get; set; }
        public bool ForceTLS { get; set; }
        public bool BufferFastCGIResponse { get; set; }
        public long? MaxConcurrentConnections { get; set; }
        public long? MaxConcurrentUpgradedConnections { get; set; }
        public long? MaxRequestBodySize { get; set; }
        public double HttpProxyTimeout { get; set; }
        public double bytesPerSecond { get; set; }
        public int gracePeriod { get; set; }
        public int FCGI_ReceiveTimeout { get; set; }
        public int FCGI_SendTimeout { get; set; }
        public uint ClearSessEveryXMin { get; set; }
        public uint WebSocketTimeout { get; set; }
        public uint WebSocketEndpointTimeout { get; set; }
        public uint PHP_MaxPoolSize { get; set; }
        public ushort MaxDirDepth { get; set; }
        public ushort[] HttpsPorts { get; set; } = [];
        public ushort[] HttpPorts { get; set; } = [];
        public string CertDir { get; set; } = "";
        public string WWWdir { get; set; } = "";
        public string BackendDir { get; set; } = "";
        public string SessionsDir { get; set; } = "";
        public string SessionCookieName { get; set; } = "";
        public string Rand_Alphabet { get; set; } = "";
        public string FilterFromDomain { get; set; } = "";
        public string DomainFilterTo { get; set; } = "";
        public string PHP_FPM { get; set; } = "";
        public string[] indexPriority { get; set; } = [];
        public string[] DownloadIfExtension { get; set; } = [];
        public System.IO.Compression.CompressionLevel CompressionLevel { get; set; }
        public Dictionary<string, string[]> ExtTypes { get; private set; } = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);

        [JsonIgnore]
        public Dictionary<string, string[]> OptExtTypes { get; set; } = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);

        public Dictionary<string, string> ForwardExt { get; private set; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, string> DefaultHeaders { get; private set; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, string> DomainAlias { get; private set; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, string> UrlAlias { get; private set; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        [JsonIgnore]
        public MinDataRate? MinRequestBodyDataRate { get; set; }

        public void FriendlyHeadersToOptimized()
        {
            foreach (var kvp in ExtTypes)
            {
                string[] list = kvp.Value;
                List<string> parsed = new List<string>(list.Length * 2);

                foreach (var header in list)
                {
                    int sep = header.IndexOf(':');
                    if (sep == -1)
                    {
                        Console.WriteLine("[Config] Malformed header entry in '" + kvp.Key + "': \"" + header + "\" (missing ':' between header key and header value).");
                        continue;
                    }
                    parsed.Add(header[..sep].Trim());
                    parsed.Add(header[(sep + 1)..].Trim());
                }

                OptExtTypes[kvp.Key] = parsed.ToArray();
            }
        }
        public void LoadDefaults()
        {
            Enable_PHP = false;
            Enable_CS = true;
            ForceTLS = false;
            BufferFastCGIResponse = false;
            MaxConcurrentConnections = null;
            MaxConcurrentUpgradedConnections = 10000;
            MaxRequestBodySize = 3_000_000_000;
            HttpProxyTimeout = 300;
            bytesPerSecond = 240;
            gracePeriod = 5;
            FCGI_ReceiveTimeout = 300000;
            FCGI_SendTimeout = 300000;
            ClearSessEveryXMin = 5;
            WebSocketTimeout = 300;
            WebSocketEndpointTimeout = 30;
            PHP_MaxPoolSize = 15;
            MaxDirDepth = 15;
            HttpsPorts = [ 443 ];
            HttpPorts = [ 80 ];
            CertDir = "/etc/letsencrypt/live/";
            WWWdir = "";
            BackendDir = "/var/www";
            SessionsDir = "/var/sess/";
            SessionCookieName = "SSID";
            FilterFromDomain = "";
            DomainFilterTo = "";
            PHP_FPM = "127.0.0.1:9000";
            Rand_Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            indexPriority = ["index._csdll", "index._cs", "index.phpdll", "index.php", "index.njs", "index.bun", "index.html", "index.htm"];
            CompressionLevel = System.IO.Compression.CompressionLevel.Optimal;
            DownloadIfExtension = [
            "zip", "tar", "gz",
            "jar",
            "dll",
            "exe", "bat", "bash", "sh", "x86_64"
            ];
            ExtTypes = new Dictionary<string, string[]>() // "Content-Type", "text/html" so we don't have to split string or anything during runtime, can just do a for loop using i+=2
            {
                ["html"] = ["Content-Type: text/html", "Cache-Control: max-age=86400"], 
                ["php"] = ["Content-Type: text/html"],
                ["txt"] = ["Content-Type: text/plain"],
                ["log"] = ["Content-Type: text/plain"],
                ["css"] = ["Content-Type: text/css"],
                ["jpg"] = ["Content-Type: image/jpeg"],
                ["svg"] = ["Content-Type: image/svg+xml"],
                ["mp3"] = ["Content-Type: audio/mpeg"],
            };
            ForwardExt = new Dictionary<string, string>()
            {
                ["njs"] = "http://{domain}:3000",
                ["bun"] = "http://{domain}:3000"
            };
            ExtTypes["js"] = ["Content-Type: application/javascript"];
            foreach (string g in new string[] { "json", "pdf", "zip", "jar", "dll", "exe" })
            {
                ExtTypes[g] = ["Content-Type: application/" + g];
            }
            foreach (string g in new string[] { "png", "jpeg", "gif", "webp", "ico" })
            {
                ExtTypes[g] = ["Content-Type: image/" + g];
            }
            foreach (string g in new string[] { "wav", "ogg" })
            {
                ExtTypes[g] = ["Content-Type: audio/" + g];
            }
            foreach (string g in new string[] { "mp4", "flv", "mkv", "wmf", "avi", "webm" })
            {
                ExtTypes[g] = ["Content-Type: video/" + g];
            }
            DefaultHeaders["Server"] = "JH";
            DefaultHeaders["vary"] = "Accept-Encoding";
            DefaultHeaders["Accept-Ranges"] = "bytes";
            DefaultHeaders["Access-Control-Allow-Origin"] = "*";
            DefaultHeaders["cache-control"] = "max-age=31536000";

            DomainAlias = new Dictionary<string, string>()
            {
                ["www.example.com"] = "example.com",
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