﻿using Microsoft.AspNetCore.Server.Kestrel.Core;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

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
        public ushort MaxDirDepth { get; set; }
        public string CertDir { get; set; } = "";
        public string WWWdir { get; set; } = "";
        public string BackendDir { get; set; } = "";
        public string SessDir = "";
        public string Rand_Alphabet = "";
        public string FilterFromDomain = "";
        public string DomainFilterTo = "";
        public string ThreadingDll { get; set; } = "";
        public string HttpDll { get; set; } = "";
        public List<string> DownloadIfExtension { get; set; } = new List<string>();
        public Dictionary<string, string> ExtTypes { get; private set; } = new Dictionary<string, string>();
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
            WebSocketTimeout = 300;
            MaxDirDepth = 15;
            CertDir = "/etc/letsencrypt/live/";
            WWWdir = "";
            BackendDir = "/var/www";
            SessDir = "/var/sess/";
            FilterFromDomain = ".";
            DomainFilterTo = "";
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
}
