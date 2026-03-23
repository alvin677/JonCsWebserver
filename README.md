# JonCsWebserver
Performance-focused C# web server, with backend file scripting support and customizable.<br>
Simply drop-in this webserver in-place of e.g. Apache and get a free performance boost (more than double the performance out-of-the-box)! PHP support, static file support, and more.<br>
Feel free to fork, modify the code and send push requests to make it more performant! :)

`./WebServer_linux --httpPort=80 --httpsPort=443 --backend=/var/www/dynamic_files --help`<br/>
`./WebServer_linux --httpPort=80,8080 --httpsPort=443,8443 --backend=/var/www/dynamic_files`<br/>
The args you don't send through command are loaded from config instead.
## Static files
<details>
<summary>This webserver *should* be excellent for static files.</summary>
  
If you *only* want to serve static files you can use the config file to set the "WWWdir" to a directory.
You can also use the `--webPath` startup arg: `./WebServer_linux --httpPort=80,8080 --httpsPort=443,8443 --webPath=/staticfiles`<br/>
Using our `--backend` works very well for serving static files too.
</details>

## Proxy
<details>
<summary>Need to redirect specific files to another endpoint, such as node or bun? You can do that in the `JonCsWebConfig.json`!</summary>
  
```json
  "ForwardExt": {
    "deno": "https://{domain}:8443",
    "bun": "http://{domain}:3000"
  }
```
In the example above, files.deno would be proxied to https://sameDomain:8443/samePath?sameQuery, and files.bun would be proxied to http://sameDomain:3000/samePath?sameQuery<br/>
Also supports proxying websockets, it automatically replaces http:// with ws:// and https:// with wss:// when a websocket connection is made.
</details>

## C# backend (Enable_CS: true)
<details>
<summary>You can write C# files for backend.</summary><br/>
  
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
(**works since version 0.76**) You can also use pre-compiled .dll C# library files, rename the extension from `.dll` to `._csdll`:
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
</details>

## PHP backend (Enable_PHP: true)
<details>
<summary>PHP is a very popular backend language.</summary>  
  
To support PHP, install php-fpm with `apt install php-fpm` (depending on your OS), make sure PHP-FPM is up and running, and set IP & Port to your PHP-FPM instance. Set `"Enable_PHP": true` in the `JonCsWebConfig.json` config file.<br/>
1. `nano /etc/php*/*/fpm/pool.d/*.conf`
2. If possible, use `listen = /run/php/php8.2-fpm.sock` (replace `php8.2-fpm` with your version). If not possible to use Unix socket, set port under `listen =` (so `listen = 9000` for example) (Unix socket ~40 ms lower latency compared to TCP on localhost)
3. While you are editing that file, we recommend to set `pm.max_children` from `5` -> `28` (the amount of cores you have, preferebly), and `pm.start_servers` from `2` -> `3`. Use your own settings if you know what you are doing.
4. `systemctl restart php8.2-fpm` (replace `php8.2` with your php-fpm version)
5. `JonCsWebConfig.json`:
-  set `Enable_PHP` to true,
-  make sure the `PHP_FPM` is set to the correct Unix socket OR ip:port (`/run/php/php8.2-fpm.sock` for Unix socket, or `127.0.0.1:9000` if you set port, for example)
</details>

## Speedtests / stresstests
<details>
  <summary>Test how much traffic the webserver can handle.</summary>

  ### [Intel Xeon E5-2680 v4](https://ark.intel.com/content/www/us/en/ark/products/91754/intel-xeon-processor-e5-2680-v4-35m-cache-2-40-ghz.html)	| Linux debian 6.1.0-17-amd64 6.1.69-1 (2023-12-30) | Tests done using `k6`
  Roughly 500% CPU utilization (2x CPUs = 28 cores)
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
  ### [Intel Xeon E5-2680 v4](https://ark.intel.com/content/www/us/en/ark/products/91754/intel-xeon-processor-e5-2680-v4-35m-cache-2-40-ghz.html)	| Linux debian 6.1.0-17-amd64 6.1.69-1 (2023-12-30) | Tests done using `k6`
  Roughly 2000% CPU utilization (2x CPUs = 28 cores)
  ```bash
  12 threads and 2000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency     4.95ms    6.75ms 247.07ms   84.70%
    Req/Sec    35.68k    10.25k   60.65k    64.51%
  12730391 requests in 30.09s, 2.96GB read
Requests/sec: 423098.10
Transfer/sec:    100.87MB
```
Serving 11.5KB html file
```bash
  12 threads and 2000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    12.39ms    9.80ms  86.20ms   72.16%
    Req/Sec    13.91k     2.15k   32.69k    72.46%
  4976075 requests in 30.09s, 55.22GB read
Requests/sec: 165351.84
Transfer/sec:      1.84GB
```
</details>
