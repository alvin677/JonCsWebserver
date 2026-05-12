# JonCsWebserver
Performance-focused C# web server, with backend file scripting support and customizable.<br>
Simply drop-in this webserver in-place of i.e. Apache and get a free performance boost (more than double the performance out-of-the-box)! PHP support, static file support, and more.<br>
Feel free to fork, modify the code and send push requests to make it more performant! :)

Try it out live: https://api.jonhosting.com

Launch:

`./WebServer_linux --httpPort=80 --httpsPort=443 --backend=/var/www/dynamic_files --help`<br/>
`./WebServer_linux --httpPort=80,8080 --httpsPort=443,8443 --backend=/var/www/dynamic_files`<br/>
The args you don't send through command are loaded from config instead.
## Configuration
<details>
  <summary>JonCsWebConfig.json</summary>

The json below contains comments about what each option does. The out-of-the-box settings should be very similar.<br>
**DO NOT USE! IT WILL BREAK JSON SYNTAX.**
```json
{
  "Logging": false,
  "DebugPages": false, // Show error pages when webserver errors
  "ServerMetrics": false, // Tracks total requests, and latest rps, rpm, rph
  "LoopFindEndpoint": false, // If true, it tracks backwards until it finds an index (otherwise err404): /path1/path2/index.html -> /path1/path2 -> /path1 -> /
  "EnableHtaccess": false, // .htaccess-support
  "Enable_CS": true, // C#/._csdll-backend support
  "Enable_WASM": false, // ._wasm-backend support
  "AllowSynchronousIO": false,
  "ForceTLS": false, // Force TLS when proxying?
  "BufferFastCGIResponse": false, // Tweak PHP performance depending on high/low scale
  "MaxConcurrentConnections": null, // Max global concurrent HTTP(S)-connections
  "MaxConcurrentUpgradedConnections": 10000, // Max global concurrent WS(S)-connections
  "MaxRequestBodySize": 8000000000, // Max POST-length
  "HttpProxyTimeout": 300.0,
  "bytesPerSecond": 1.0, // Minimum bytes-per-second before WebServer temporarily blocks user. Set it low to avoid false-positives from skimming through videofiles.
  "gracePeriod": 5,
  "MaxBytesPerSecond": 0, // Limit outbound bandwidth per-client-IP
  "RequestTimeout": 0,
  "KeepAliveTimeout": 130,
  "RequestHeadersTimeout": 30,
  "RateLimitTime": 1, // 1 second. CF default: 10
  "RateLimitReq": 0, // Amount of requests within RateLimitTime before it ratelimits specific IP. Recommended: 500
  "RateLimitRefill": 100,
  "RateLimitQueue": 0,
  "MaxFilePathLength": 512,
  "FCGI_ReceiveTimeout": 300000,
  "FCGI_SendTimeout": 300000,
  "FCGI_MaxPoolSize": 20,
  "ClearSessEveryXMin": 5,
  "WebSocketTimeout": 300,
  "WebSocketEndpointTimeout": 30,
  "MaxDirDepth": 15, // Max amount of slashes in the URL. /path1/path2/path3...
  "HttpsPorts": [ // --httpsPort=443,8443
    443, 8443
  ],
  "HttpPorts": [ // --httpPort=80,8080
    80, 8080
  ],
  "CertDir": "certs/", // certs -> domain1, domain2 -> privkey.pem, fullchain.pem // override with --certPath=/etc/letsencrypt/live/
  "WWWdir": "", // Static-files exclusive mode // --webPath=/var/www
  "BackendDir": "www", // Hybrid mode (Static files + backend) // --backend=/var/www
  "SessionsDir": "sess/", // Used in C#-endpoints for saving/loading sessions from.
  "SessionCookieName": "SSID",
  "Rand_Alphabet": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", // Letters used for randomizing i.e. SSID
  "FilterFromDomain": "", // Optional: "."
  "DomainFilterTo": "", // If set to "", it will replace all "." with "" 
  "indexPriority": [ // Every directory tries to "copy" endpoint from the first file found within this list
    "index._csdll",
    "index._cs",
    "index.php",
    "index._wasm",
    "index.njs",
    "index.bun",
    "index.html"
  ],
  "DownloadIfExtension": [ // These file extensions tell client to download (through headers)
    "zip", "tar", "gz",
    "jar", "apk",
    "dll",
    "exe", "bat", "bash", "sh", "x86_64"
  ],
  "CompressionLevel": 0, // "Optimal" / 0, "Fastest" / 1, "NoCompression" / 2, "SmallestSize" / 3
  "ExtTypes": { // Set headers per-file extension
    "html,htm,xhtml": [
      "Content-Type: text/html",
      "Cache-Control: max-age=86400"
    ],
    "php": [
      "Content-Type: text/html"
    ],
    "txt,log": [
      "Content-Type: text/plain"
    ],
    "css": [
      "Content-Type: text/css"
    ],
    "svg": [
      "Content-Type: image/svg+xml"
    ],
    "mp3": [
      "Content-Type: audio/mpeg"
    ],
    "js": [
      "Content-Type: application/javascript"
    ],
    "json": [
      "Content-Type: application/json"
    ],
    "pdf": [
      "Content-Type: application/pdf"
    ],
    "zip": [
      "Content-Type: application/zip"
    ],
    "jar": [
      "Content-Type: application/jar"
    ],
    "dll": [
      "Content-Type: application/dll"
    ],
    "exe": [
      "Content-Type: application/exe"
    ],
    "apk": ["Content-Type: application/vnd.android.package-archive"],
    "wasm": ["Content-Type: application/wasm"],
    "png": [
      "Content-Type: image/png"
    ],
    "jpeg,jpg": [
      "Content-Type: image/jpeg"
    ],
    "gif": [
      "Content-Type: image/gif"
    ],
    "webp": [
      "Content-Type: image/webp"
    ],
    "ico": [
      "Content-Type: image/ico"
    ],
    "wav": [
      "Content-Type: audio/wav"
    ],
    "ogg": [
      "Content-Type: audio/ogg"
    ],
    "mp4": [
      "Content-Type: video/mp4"
    ],
    "flv": [
      "Content-Type: video/flv"
    ],
    "mkv": [
      "Content-Type: video/mkv"
    ],
    "wmf": [
      "Content-Type: video/wmf"
    ],
    "avi": [
      "Content-Type: video/avi"
    ],
    "webm": [
      "Content-Type: video/webm"
    ],
    "srt,vtt": ["Content-Type: text/plain; charset=utf-8"]
  },
  "ForwardExt": { // Reverse-proxy and FastCGI-support
    "njs": "http://{domain}:7001",
    "bun": "http://{domain}:3000",
    "php": "fcgi://127.0.0.1:9000"
  },
  "DefaultHeaders": { // Default headers for all non-404 requests
    "Server": "JH",
    "vary": "Accept-Encoding",
    "Accept-Ranges": "bytes",
    "Access-Control-Allow-Origin": "*",
    "cache-control": "max-age=300"
  },
  "DomainAlias": { // Lead www.domain to domain, etc.
    "www.example.com": "example.com",
    "127.0.0.1": "localhost",
    "www.jonhosting.com": "jonhosting.com",
    "www.jontv.me": "jontv.me"
  },
  "UrlAlias": {
    // "jonhosting.com/testing1234": "/test2_maybe_use_symlink_instead/useDomainAlias_for_changing_domain_virtually"
  }
}
```
</details>

## CLI
<details><summary>Command-line interface</summary>

`[]` = optional
```
listfiles [path] | Lists full filePaths of every file that has been indexed.
countfiles [path] | Same as listfiles, but returns a number.
indexfiles [path] | Manually index from a directory. Can be useful in-case of any FileWatcher bugs.
clearcerts | Clears cached certificates
loadcerts | Loads certs (use clearcerts + loadcerts to reload certificates live)
listcerts | Lists domains that has certificates
reload | Reload from config file. You may want to use indexfiles after this if you changed ExtTypes or DownloadIfExtension
stats | Shows memory (RAM) and CPU usage. If ServerMetrics is turned on in config, it tells you total requests, and latest rps, rpm, rph.
gc | Manually force GC
shutdown | Shuts down the webserver
```
</details>

## Static files
<details>
<summary>This webserver *should* be excellent for static files.</summary>
  
The default mode (using `--backend` / BackendDir) works excellently with static files. However, if you *only* want to serve static files, you can use the config file to set the "WWWdir" to a directory.
Or you can use the `--webPath` startup arg: `./WebServer_linux --httpPort=80,8080 --httpsPort=443,8443 --webPath=/staticfiles`<br/>
</details>

## Proxy
<details>
<summary>Need to redirect specific files to another endpoint, such as node or bun? You can do that in the `JonCsWebConfig.json`!</summary>
  
```json
  "ForwardExt": {
    "deno": "https://{domain}:8443",
    "bun": "http://{domain}:3000",
    "php": "fcgi:///run/php/php8.2-fpm.sock"
  }
```
In the example above, `files.deno` would be proxied to https://sameDomain:8443/samePath?sameQuery, and `files.bun` would be proxied to http://sameDomain:3000/samePath?sameQuery<br/>
Also supports proxying websockets. It automatically replaces http:// with ws:// and https:// with wss:// when a websocket connection is made.
</details>

## C# backend (Enable_CS: true)
<details>
<summary>You can compile C# files for backend (._csdll) since v0.76</summary><br/>
  
(**works since version 0.76**) You can use pre-compiled .dll C# library files, rename the extension from `.dll` to `._csdll`:
<br>Example 1:
```cs
using Microsoft.AspNetCore.Http;
public class Is_CsScript {
  public static async Task Run(HttpContext context, string path) {
    context.Response.ContentType = "text/plain";
    await context.Response.WriteAsync($"Hello there! Path: {path}");
  }
}
```
Example 2:
```cs
using Microsoft.AspNetCore.Http;
public class Is_CsScript
{
    static int count = 0;
    public static async Task Run(HttpContext context, string path)
    {
// lock(count) {
        count++;
// }
        context.Response.ContentType = "text/plain";
        await context.Response.WriteAsync(count.ToString());
    }
}
```
Example 3:
```cs
using Microsoft.AspNetCore.Http;
public class Is_CsScript
{
    const string newurl = "https://tmspk.gg/phMyXgKV";
    public static Task Run(HttpContext context, string path)
    {
        context.Response.StatusCode = StatusCodes.Status301MovedPermanently;
        context.Response.Headers.Location = newurl;
        return Task.CompletedTask;
    }
}
```
```cs
using Microsoft.AspNetCore.Http;
public class Is_CsScript
{
    public static async Task Run(HttpContext context, string path)
    {
        context.Response.StatusCode = 301;
        context.Response.Headers["Location"] = "https://discord.gg/RZvRp6u8yq";
        await context.Response.WriteAsync(context.Response.Headers["Location"]);
    }
}
```
(WhatsMyIp) Example 4:
```cs
using Microsoft.AspNetCore.Http;
public class Is_CsScript
{
    public static async Task Run(HttpContext context, string path)
    {
        await context.Response.WriteAsync(context.Connection.RemoteIpAddress.ToString());
    }
}
```
More advanced backend example:
```cs
global using System;
global using System.IO;
global using System.Linq;
global using System.Collections.Generic;
global using System.Threading.Tasks;
global using Microsoft.AspNetCore.Http;
global using Microsoft.Extensions.Primitives;

using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;
using System.Text.Json;
using System.IO;
using WebServer; // WebServer.Startup, WebServer.Session
public class Is_CsScript
{
    static Is_CsScript() // runs on "load", triggered on first request. index._cs/index._csdll is loaded through HotReloadContext.
    {
        // Startup.RemoveFromFileLead(ToKey("/path/send")); // can be used to remove an endpoint at anytime
        Startup.AddToFileLead(ToKey("/path/send"), ExampleManuallyAddedEndpoint); // "native" would be: /path/send/index._cs, but by adding it manually here we have better and easier cross-control. // can be used anytime to add fast-fetch endpoints.
    }
    public static async Task Run(HttpContext context, string path) // "native", runs per-request at e.g. /index._cs
    {
        await context.Response.WriteAsync("example");
    }
    static async Task ExampleManuallyAddedEndpoint(HttpContext ctx, string path)
    {
        ctx.Response.Headers.CacheControl = "max-age=1";
        ctx.Response.ContentType = "application/json";
        await ctx.Response.WriteAsync("{}");
    }
    static readonly string _domainPrefix = Path.GetFileName(Path.GetDirectoryName(typeof(Is_CsScript).Assembly.Location)!);
    static string ToKey(string p) => Startup.BackendDir + _domainPrefix + p;
}
```
</details>
<details>
  <summary>Quick C# -> .dll compile</summary>

  ```bash
# Ubuntu/Debian example
wget https://dot.net/v1/dotnet-install.sh -O dotnet-install.sh
bash dotnet-install.sh --channel 10.0
export PATH=$HOME/.dotnet:$PATH
```
```bash
mkdir MyLibrary
cd MyLibrary
dotnet new classlib -n MyLibrary
```
```bash
cd MyLibrary
dotnet add package Microsoft.AspNetCore.Http.Abstractions
mkdir libs
wget https://github.com/alvin677/JonCsWebserver/releases/download/1.64/WebServer.dll -O libs/WebServer.dll
dotnet add reference libs/WebServer.dll
nano Class1.cs
```
```cs
using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;
// using WebServer;
public class Is_CsScript
{
    public static async Task Run(HttpContext context, string path)
    {
/*
        _ = context.Request.Cookies.TryGetValue(Program.config.SessionCookieName, out string? sessID);
        Dictionary<string, System.Text.Json.JsonElement>? session = await WebServer.Session.GetSess(sessID);
        if (session == null)
        {
            context.Response.StatusCode = StatusCodes.Status500InternalServerError;
            return;
        }
        sessID = session["id"].GetString();
        context.Response.Headers.SetCookie = Program.config.SessionCookieName + "=" + sessID + "; Secure; Httponly; Path=/; SameSite=Lax; Expires=" + DateTime.UtcNow.AddDays(31);
        session["m"] = "mail@jontv.me";
        await WebServer.Session.SaveSess(sessID, session);
*/
        await context.Response.WriteAsync(context.Connection.RemoteIpAddress.ToString());
    }
}
```
```bash
dotnet build -c Release
```
```bash
mv bin/Release/net10.0/MyLibrary.dll /var/www/localhost/example/index._csdll
```
</details>
<details>
  <summary>You can write C# files for backend (._cs) since v1.73</summary>
  
(**Works since version 1.73**) 
For direct compilation write files ending with `._cs`:
```cs
using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;
// using WebServer;
public class Is_CsScript {
  public static async Task Run(HttpContext context, string path) {
    context.Response.ContentType = "text/plain";
    await context.Response.WriteAsync($"Hello there, kiddo! Path: {path}");
  }
}
```
Manual proxying rather than relying on config (works if `LoopFindEndpoint` is set to `true`, otherwise you would need to manually place it at every endpoint):
```cs
using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;
using WebServer;
public class Is_CsScript {
  const string target = "http://localhost:8000";
  public static Task Run(HttpContext context, string path) { // We can skip 'async' in this specific case, a tiny micro-opt.
    string targetUrl = target
      + context.Request.Path.Value
      + context.Request.QueryString.Value;
    return Startup.ForwardRequestTo(context, targetUrl); // (Otherwise awaitable. Works similar to CloudFlare, adding the same ip-header.)
  }
}
```
</details>
<details>
  <summary>Issues</summary>

Did `dotnet add reference libs/WebServer.dll` not work?
  `nano MyLibrary.csproj`

```xml
  <ItemGroup>
    <PackageReference Include="Microsoft.AspNetCore.Http" Version="2.3.9" />
  </ItemGroup>
  <ItemGroup>
    <Reference Include="WebServer">
      <HintPath>libs/WebServer.dll</HintPath>
    </Reference>
  </ItemGroup>
</Project>
```
</details>

## PHP/FastCGI backend
<details>
<summary>PHP is a very popular backend language.</summary>  
  
To support PHP, install php-fpm with `apt install php-fpm` (Manual: https://www.php.net/downloads.php), make sure PHP-FPM is up and running, and set IP & Port to your PHP-FPM instance. Add/modify `"ForwardExt": { "php": "fcgi:///run/php/php8.2-fpm.sock" }` in the `JonCsWebConfig.json` config file.<br/>
1. `nano /etc/php*/*/fpm/pool.d/*.conf`
2. If possible, use `listen = /run/php/php8.2-fpm.sock` (replace `php8.2-fpm` with your version). If not possible to use Unix socket, set port under `listen =` (so `listen = 9000` for example) (Unix socket has significantly lower latency and improved throughput compared to TCP on localhost)
3. While you are editing that file, we recommend to set `pm.max_children` to the amount of cores you have. Use your own settings if you know what you are doing.
4. `systemctl restart php8.2-fpm` (replace `php8.2` with your php-fpm version)
5. `JonCsWebConfig.json`:
-  Find `"ForwardExt":`,
-  add/modify `"php": "fcgi://endpoint"`, where `endpoint` set to the correct Unix socket OR ip:port (`/run/php/php8.2-fpm.sock` for Unix socket, or `127.0.0.1:9000` if you set port in step 2, for example)
</details>

## Benchmarks / Speedtests / Stresstests
<details>
  <summary>Test how much traffic the webserver can handle.</summary>

  ### [Intel Xeon E5-2680 v4](https://ark.intel.com/content/www/us/en/ark/products/91754/intel-xeon-processor-e5-2680-v4-35m-cache-2-40-ghz.html)	| Linux debian 6.1.0-26-amd64 6.1.112-1 (2024-09-30) | Tests done using `k6`
  All benchmarks for this one were done with wrk and webserver running on the same system.
  Roughly 500% CPU utilization (2x CPUs = 28 cores) (~2000% k6 usage)
  ```bash
     execution: local
        script: test-kestrel.js
        output: -

     scenarios: (100.00%) 1 scenario, 2800 max VUs, 1m0s max duration (incl. graceful stop):
              * default: 2800 looping VUs for 30s (gracefulStop: 30s)

     data_received..................: 779 MB  26 MB/s
     data_sent......................: 287 MB  9.6 MB/s
     http_req_blocked...............: avg=51.63µs  min=1.95µs  med=4.34µs  max=1.12s    p(90)=5.87µs   p(95)=6.65µs
     http_req_connecting............: avg=37.34µs  min=0s      med=0s      max=1.12s    p(90)=0s       p(95)=0s
     http_req_duration..............: avg=3.68ms   min=68.04µs med=1.88ms  max=161.31ms p(90)=8.55ms   p(95)=16.23ms
       { expected_response:true }...: avg=3.68ms   min=68.04µs med=1.88ms  max=161.31ms p(90)=8.55ms   p(95)=16.23ms
     http_req_failed................: 0.00%   0 out of 3120073
     http_req_receiving.............: avg=162.24µs min=11.84µs med=27.96µs max=92.37ms  p(90)=43.46µs  p(95)=160.79µs
     http_req_sending...............: avg=197.31µs min=5.78µs  med=11.72µs max=159.44ms p(90)=263.26µs p(95)=626.81µs
     http_req_tls_handshaking.......: avg=0s       min=0s      med=0s      max=0s       p(90)=0s       p(95)=0s
     http_req_waiting...............: avg=3.32ms   min=45.66µs med=1.72ms  max=96.93ms  p(90)=7.53ms   p(95)=14.58ms
     http_reqs......................: 3120073 103913.05041/s
     iteration_duration.............: avg=25.53ms  min=20.12ms med=22.82ms max=1.14s    p(90)=35.19ms  p(95)=41.54ms
     iterations.....................: 3120073 103913.05041/s
     vus............................: 2800    min=2800         max=2800
     vus_max........................: 2800    min=2800         max=2800


running (0m30.0s), 0000/2800 VUs, 3120073 complete and 0 interrupted iterations
```
Serving 11.5KB html file (Kestrel's SendFileAsync):
```bash
     execution: local
        script: test-kestrel.js
        output: -

     scenarios: (100.00%) 1 scenario, 2800 max VUs, 1m0s max duration (incl. graceful stop):
              * default: 2800 looping VUs for 30s (gracefulStop: 30s)

     data_received..................: 27 GB   903 MB/s
     data_sent......................: 182 MB  6.1 MB/s
     http_req_blocked...............: avg=466.72µs min=2.04µs   med=4.56µs  max=1.21s   p(90)=6.35µs   p(95)=7.2µs
     http_req_connecting............: avg=441.64µs min=0s       med=0s      max=1.21s   p(90)=0s       p(95)=0s
     http_req_duration..............: avg=11.44ms  min=128.29µs med=6.43ms  max=4.54s   p(90)=27.24ms  p(95)=34.06ms
       { expected_response:true }...: avg=11.44ms  min=128.29µs med=6.43ms  max=4.54s   p(90)=27.24ms  p(95)=34.06ms
     http_req_failed................: 0.00%   0 out of 2273265
     http_req_receiving.............: avg=888.65µs min=18.18µs  med=43.55µs max=89.57ms p(90)=278.64µs p(95)=2.97ms
     http_req_sending...............: avg=330.24µs min=5.68µs   med=11.54µs max=87.95ms p(90)=200.72µs p(95)=694.79µs
     http_req_tls_handshaking.......: avg=0s       min=0s       med=0s      max=0s      p(90)=0s       p(95)=0s
     http_req_waiting...............: avg=10.22ms  min=83.61µs  med=5.86ms  max=4.54s   p(90)=25.29ms  p(95)=30.16ms
     http_reqs......................: 2273265 75703.775946/s
     iteration_duration.............: avg=34.91ms  min=20.19ms  med=29.02ms max=4.57s   p(90)=52.57ms  p(95)=62.07ms
     iterations.....................: 2273265 75703.775946/s
     vus............................: 2800    min=2800         max=2800
     vus_max........................: 2800    min=2800         max=2800


running (0m30.0s), 0000/2800 VUs, 2273265 complete and 0 interrupted iterations
```
Serving 11.5KB html file (after new update, using our custom function):
```bash
    HTTP
    http_req_duration..............: avg=6.26ms  min=102.88µs med=2.78ms  max=212.74ms p(90)=16.98ms p(95)=23.04ms
      { expected_response:true }...: avg=6.26ms  min=102.88µs med=2.78ms  max=212.74ms p(90)=16.98ms p(95)=23.04ms
    http_req_failed................: 0.00%   0 out of 2495642
    http_reqs......................: 2495642 83127.390574/s
    EXECUTION
    iteration_duration.............: avg=30.03ms min=20.16ms  med=25.35ms max=1.41s    p(90)=44.75ms p(95)=53.44ms
    iterations.....................: 2495642 83127.390574/s
    vus............................: 2800    min=2800         max=2800
    vus_max........................: 2800    min=2800         max=2800
    NETWORK
    data_received..................: 31 GB   1.0 GB/s
    data_sent......................: 185 MB  6.2 MB/s
running (0m30.0s), 0000/2800 VUs, 2495642 complete and 0 interrupted iterations
```
  ### [Intel Xeon E5-2680 v4](https://ark.intel.com/content/www/us/en/ark/products/91754/intel-xeon-processor-e5-2680-v4-35m-cache-2-40-ghz.html)	| Linux debian 6.1.0-26-amd64 6.1.112-1 (2024-09-30) | Tests done using `wrk`
  All benchmarks for this one were done with wrk and webserver running on the same system.
  Roughly 2000% CPU utilization (2x CPUs = 28 cores) (~500% wrk usage)
  
  HTTP
  ```bash
  13 threads and 1050 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency     1.49ms    1.73ms  39.91ms   92.93%
    Req/Sec    54.54k     3.66k   63.21k    85.44%
  10583469 requests in 15.08s, 2.46GB read
Requests/sec: 701933.31
Transfer/sec:    167.35MB
  12 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency     1.39ms    1.31ms  45.49ms   91.38%
    Req/Sec    57.51k     2.88k   64.64k    78.56%
  20601020 requests in 30.06s, 4.80GB read
Requests/sec: 685322.41
Transfer/sec:    163.39MB
```
HTTPS
```
  12 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency     8.89ms   54.04ms   1.04s    98.33%
    Req/Sec    28.76k     4.56k   37.73k    92.40%
  9983873 requests in 30.08s, 2.32GB read
Requests/sec: 331865.18
Transfer/sec:     79.13MB
```
HTTP Serving 11.5KB html file
```bash
  13 threads and 1050 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency     4.27ms    3.17ms  62.28ms   80.17%
    Req/Sec    19.07k     2.10k   44.66k    77.63%
  3692692 requests in 15.10s, 42.13GB read
Requests/sec: 244550.53
Transfer/sec:      2.79GB
```
HTTPS Serving 11.5KB html file
```bash
  13 threads and 1050 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    11.74ms   39.53ms 634.41ms   97.48%
    Req/Sec    13.07k     2.63k   18.25k    92.04%
  2471917 requests in 15.09s, 28.21GB read
Requests/sec: 163807.69
Transfer/sec:      1.87GB
```
HTTP Serving PHP
```bash
  13 threads and 1050 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency   121.99ms  226.64ms   2.00s    91.43%
    Req/Sec     5.32k     2.28k   16.86k    74.95%
  1000140 requests in 15.08s, 4.64GB read
  Socket errors: connect 0, read 0, write 0, timeout 938
Requests/sec:  66330.42
Transfer/sec:    315.34MB
  13 threads and 1050 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    89.70ms  128.11ms 876.89ms   83.27%
    Req/Sec     7.26k     3.33k   34.70k    77.32%
  1392383 requests in 15.07s, 418.28MB read
Requests/sec:  92405.25
Transfer/sec:     27.76MB
```
HTTPS Serving PHP
```bash
  13 threads and 1050 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency   151.53ms  251.11ms   2.00s    87.23%
    Req/Sec     4.09k     1.60k   12.84k    75.47%
  778966 requests in 15.10s, 3.62GB read
  Socket errors: connect 0, read 0, write 0, timeout 679
Requests/sec:  51588.78
Transfer/sec:    245.27MB
  13 threads and 1050 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency   106.42ms  203.36ms   2.00s    91.59%
    Req/Sec     5.86k     2.43k   15.13k    73.61%
  1095477 requests in 15.07s, 329.09MB read
  Socket errors: connect 0, read 0, write 0, timeout 969
Requests/sec:  72701.71
Transfer/sec:     21.84MB
```
How does it handle mixed workloads running at the same time?
```bash
Running 10s test @ https://jonhosting.com/bmp.png # 14K
  8 threads and 1050 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    30.09ms   31.24ms 510.85ms   86.01%
    Req/Sec     4.91k     1.54k    9.83k    72.52%
  366570 requests in 10.08s, 4.68GB read
Requests/sec:  36350.19
Transfer/sec:    475.20MB
Running 10s test @ http://api.jonhosting.com/t.txt # 2 bytes
  8 threads and 1050 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    24.87ms   33.34ms 509.58ms   89.69%
    Req/Sec     6.65k     2.35k   18.50k    74.64%
  513731 requests in 10.10s, 132.77MB read
  Socket errors: connect 0, read 1, write 0, timeout 0
Requests/sec:  50880.32
Transfer/sec:     13.15MB
Running 10s test @ http://api.jonhosting.com/hash?i=input # Simple hashing string->ulong
  8 threads and 1050 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    28.52ms   45.38ms 512.95ms   94.63%
    Req/Sec     6.97k     2.39k   19.63k    75.48%
  541631 requests in 10.08s, 131.20MB read
Requests/sec:  53758.77
Transfer/sec:     13.02MB
Running 10s test @ http://jonhosting.com/test.njs # singlethreaded nodejs backend (one running on https - additional overhead)
  8 threads and 1050 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency   272.01ms   75.80ms 724.72ms   80.67%
    Req/Sec   520.62    318.93     1.34k    66.67%
  37595 requests in 10.06s, 33.06MB read
Requests/sec:   3735.72
Transfer/sec:      3.28MB
Running 10s test @ https://jontube.jonhosting.com/test.php # FCGI over UnixSocket to PHP-FPM
  8 threads and 1050 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency   228.88ms   45.96ms 582.41ms   78.39%
    Req/Sec   558.20    178.08     1.85k    77.42%
  41725 requests in 10.09s, 12.54MB read
Requests/sec:   4134.38
Transfer/sec:      1.24MB
```
  ### [AMD Ryzen 5 5600X](https://www.amd.com/en/products/processors/desktops/ryzen/5000-series/amd-ryzen-5-5600x.html)	| ArchLinux (2026-03-31) | Tests done using `wrk`
  Roughly 500% (~44%) CPU utilization (6 cores) (~300%, or ~25%, wrk usage)

HTTP
```
  14 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency     1.97ms    1.01ms  45.76ms   86.27%
    Req/Sec    34.70k     1.90k   70.50k    77.07%
  29020259 requests in 1.00m, 6.76GB read
Requests/sec: 482886.09
Transfer/sec:    115.13MB
  10 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency     1.94ms    0.95ms 206.74ms   84.79%
    Req/Sec    47.25k     4.71k   59.14k    91.13%
  14121794 requests in 30.07s, 3.28GB read
Requests/sec: 469667.13
Transfer/sec:    111.62MB
```
</details>
