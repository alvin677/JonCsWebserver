# JonCsWebserver
Performance-focused C# web server, with backend file scripting support and customizable.
Feel free to modify the code to make it more performant :)

`./WebServer_linux --httpPort=80 --httpsPort=443 --backend=/var/www/dynamic_files --help`<br/>
`./WebServer_linux --httpPort=80,8080 --httpsPort=443,8443 --backend=/var/www/dynamic_files`<br/>
The args you don't send through command are loaded from config instead.

## Static files
This webserver *should* be excellent for static files. If you *only* want to serve static files you can use the config file to set the "WWWdir" to a directory.
You can also use the `--webPath` startup arg: `./WebServer_linux --httpPort=80,8080 --httpsPort=443,8443 --webPath=/staticfiles`<br/>
Using our `--backend` works very well for serving static files too.

## Proxy
Need to redirect specific files to another endpoint, such as node or bun? You can do that in the `JonCsWebConfig.json`!
```json
  "ForwardExt": {
    "deno": "https://{domain}:8443",
    "bun": "http://{domain}:3000"
  }
```
In the example above, files.deno would be proxied to https://sameDomain:8443/samePath?sameQuery, and files.bun would be proxied to http://sameDomain:3000/samePath?sameQuery<br/>
Also supports proxying websockets, it automatically replaces http:// with ws:// and https:// with wss:// when a websocket connection is made.

## C# backend (Enable_CS: true)
You can write C# files for backend.<br/>
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

## PHP backend (Enable_PHP: true)
PHP is a very popular backend language.  
To support PHP, install php-fpm with `apt install php-fpm` (depending on your OS), make sure PHP-FPM is up and running, and set IP & Port to your PHP-FPM instance + set `Enable_PHP = true` in the `JonCsWebConfig.json` config file.<br/>
How to setup?
1. `nano /etc/php*/*/fpm/pool.d/*.conf`
2. If possible, use `listen = /run/php/php8.2-fpm.sock` (replace php8.2-fpm with your version). If not possible to use Unix socket, set port under `listen =` (so `listen = 9000` for example) (Unix socket ~40 ms lower latency compared to TCP on localhost)
3. Also while you are editing that file, we recommend to set `pm.max_children` from `5` -> `28` (or whatever amount of cores you have, preferebly), and `pm.start_servers` from `2` -> `3` (for starters, use your own settings if you know what you are doing).
4. `systemctl restart php8.2-fpm` (modify `php8.2` with your php-fpm version)
5. `JonCsWebConfig.json`:
-  turn `Enable_PHP` to true,
-  and make sure the `PHP_FPM` is set to the correct Unix socket OR ip:port (`/run/php/php8.2-fpm.sock` for Unix socket, or `127.0.0.1:9000` if you set port, for example)
