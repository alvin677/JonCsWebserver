# JonCsWebserver
Performance-focused C# web server, with backend file scripting support and customizable.<br>
Simply drop-in this webserver in-place of i.e. Apache and get a free performance boost (more than double the performance out-of-the-box)! PHP support, static file support, and more.<br>
Feel free to fork, modify the code and send push requests to make it more performant! :)

`./WebServer_linux --httpPort=80 --httpsPort=443 --backend=/var/www/dynamic_files --help`<br/>
`./WebServer_linux --httpPort=80,8080 --httpsPort=443,8443 --backend=/var/www/dynamic_files`<br/>
The args you don't send through command are loaded from config instead.
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
<summary>You can write C# files for backend.</summary><br/>
  
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
(**broken**) For direct compilation write files ending with `._cs`:
```cs
using Microsoft.AspNetCore.Http;
public class script {
 public static async System.Threading.Tasks.Task Run(HttpContext context, string path) {
  context.Response.ContentType = "text/plain";
  await context.Response.WriteAsync($"Hello there! Path: {path}");
 }
}
return new script();
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
        Dictionary<string,string>? session = await WebServer.Session.GetSess(sessID);
        if (session == null)
        {
            context.Response.StatusCode = StatusCodes.Status500InternalServerError;
            return;
        }
        sessID = session["id"];
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
  ### [Intel Xeon E5-2680 v4](https://ark.intel.com/content/www/us/en/ark/products/91754/intel-xeon-processor-e5-2680-v4-35m-cache-2-40-ghz.html)	| Linux debian 6.1.0-26-amd64 6.1.112-1 (2024-09-30) | Tests done using `wrk`
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
  14 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency     5.16ms    4.21ms  81.64ms   80.31%
    Req/Sec    14.90k     1.43k   43.24k    82.12%
  3116959 requests in 15.10s, 34.95GB read
Requests/sec: 206433.14
Transfer/sec:      2.31GB
```
HTTPS Serving 11.5KB html file
```bash
  12 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    14.77ms   55.77ms 969.29ms   98.24%
    Req/Sec    10.70k     2.10k   21.32k    88.11%
  3784179 requests in 30.10s, 42.00GB read
Requests/sec: 125716.92
Transfer/sec:      1.40GB
```
HTTP Serving PHP
```bash
  12 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency   623.44us    4.45ms 261.87ms   99.82%
    Req/Sec     6.30k     6.03k   24.15k    88.17%
  1129265 requests in 20.10s, 5.24GB read
Requests/sec:  56189.62
Transfer/sec:    267.13MB
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
