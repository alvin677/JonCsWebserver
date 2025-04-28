# JonCsWebserver
Performance-focused C# web server, with backend file scripting support and customizable.
Feel free to modify the code to make it more performant :)

`./WebServer_linux --httpPort=80 --httpsPort=443 --backend=/var/www/dynamic_files --help`<br/>
`./WebServer_linux --httpPort=80,8080 --httpsPort=443,8443 --backend=/var/www/dynamic_files`<br/>
The args you don't send through command are loaded from config instead.

## Static files
This webserver *should* be excellent for static files. If you only want to serve static files you can use the config file to set the "WWWdir" to a directory.
You can also use the `--webPath` startup arg: `./WebServer_linux --httpPort=80,8080 --httpsPort=443,8443 --webPath=/staticfiles`

## Proxy
Need to redirect specific files to another endpoint, such as node or bun? You can do that in the `JonCsWebConfig.json`!

## C# backend (Enable_CS: true)
You can write C# files for backend.<br/>
(**broken**) For direct compilation write files ending with `._cs`:
```cs
public class script {
 public static async System.Threading.Tasks.Task Run(Microsoft.AspNetCore.Http.HttpContext context, string path) {
  context.Response.ContentType = "text/plain";
  await context.Response.WriteAsync($"Hello there! Path: {path}");
 }
}
return new script();
```
(**works since version 0.76**) You can also use pre-compiled .dll C# library files, rename the extension from `.dll` to `._csdll`:
<br>Example 1:
```cs
public class Is_CsScript {
  public static async Task Run(Microsoft.AspNetCore.Http.HttpContext context, string path) {
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

## PHP backend (Enable_PHP: true)
PHP is a very popular backend language.  
To support PHP, install php-fpm with `apt install php-fpm` (depending on your OS), make sure PHP-FPM is up and running, and set IP & Port to your PHP-FPM instance + set `Enable_PHP = true` in the `JonCsWebConfig.json` config file.<br/>
How to setup?
1. `nano /etc/php*/*/fpm/pool.d/*.conf`
2. Set port
3. `systemctl restart php8.2-fpm` (modify `php8.2` with your php-fpm version)
4. `JonCsWebConfig.json`:
-  turn `Enable_PHP` to true,
-  and make sure the `PHP_FPM` is set to the correct ip:port (`127.0.0.1:9000` for example)
