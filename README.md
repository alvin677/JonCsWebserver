# JonCsWebserver
Performance-focused C# web server, with backend file scripting support and customizable.
Feel free to modify the code to make it more performant :)

`./WebServer_linux --httpPort=80 --httpsPort=443 --backend=/var/www/dynamic_files`<br/>
`./WebServer_linux --httpPort=80,8080 --httpsPort=443,8443 --backend=/var/www/dynamic_files`<br/>
The args you don't send through command are loaded from config instead.

## Static files
This webserver *should* be excellent for static files. If you only want to serve static files you can use the config file to set the "WWWdir" to a directory.
`./WebServer_linux --httpPort=80,8080 --httpsPort=443,8443 --webPath=/staticfiles`

## Proxy
Need to redirect specific files to another endpoint, such as node or bun? You can do that in the `JonCsWebConfig.json`!

## C# backend
You can write C# files for backend, write files ending with `._cs`:
```cs
public static async Task Run(HttpContext context, string path) {
  context.Response.ContentType = "text/plain";
  await context.Response.WriteAsync($"Hello there! Path: {path}");
}
```

## PHP backend
PHP is a very popular backend language, so you can write `.php` files like the following and they will be compiled using **PeachPie**, so they shall not affect performance significantly:
```php
<?php
namespace Is_PhpScript;

function Run($context, $path) {
    // Custom PHP logic
    return "Processed: " . $path;
}
?>
```
To support PHP, run `dotnet tool install --global Peachpie.Compiler.Tools` (and Enable_PHP = true in config file)
