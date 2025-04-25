using Microsoft.AspNetCore.Http;
using System.Collections.Concurrent;
using System.Net.Sockets;
using System.Text;

public static class FastCGIConstants
{
    public const byte VERSION = 1;
    public const byte BEGIN_REQUEST = 1;
    public const byte PARAMS = 4;
    public const byte STDIN = 5;
    public const byte STDOUT = 6;
    public const byte STDERR = 7;
    public const byte END_REQUEST = 3;

    public const byte ROLE_RESPONDER = 1;
}

public class FastCGIClient
{
    private readonly string _host;
    private readonly int _port;
    private readonly ConcurrentQueue<TcpClient> _connectionPool = new ConcurrentQueue<TcpClient>();
    // private const int MaxPoolSize = Program.config.PHP_MaxPoolSize; // Adjust based on usage scenario

    public FastCGIClient(string host = "127.0.0.1", int port = 9000)
    {
        _host = host;
        _port = port;
    }

    public async Task Run(HttpContext context, string path)
    {
        // ---- PARAMS
        var env = new Dictionary<string, string>
        {
            { "GATEWAY_INTERFACE", "FastCGI/1.0" },
            { "REQUEST_METHOD", context.Request.Method },
            { "SCRIPT_FILENAME", path },
            { "SCRIPT_NAME", Path.GetFileName(path) },
            { "QUERY_STRING", context.Request.QueryString.HasValue ? context.Request.QueryString.Value.TrimStart('?') : "" },
            { "SERVER_SOFTWARE", "JonCsWebServer" },
            { "REMOTE_ADDR", context.Connection.RemoteIpAddress != null ? context.Connection.RemoteIpAddress.ToString() : "127.0.0.1" },
            { "REMOTE_PORT", context.Connection.RemotePort.ToString() },
            { "SERVER_ADDR", context.Request.Host.Host },
            { "SERVER_PORT", context.Request.Host.Port.HasValue ? context.Request.Host.Port.Value.ToString() : "80" },
            { "SERVER_NAME", context.Request.Host.Host },
            { "SERVER_PROTOCOL", context.Request.Protocol },
            { "CONTENT_LENGTH", context.Request.ContentLength.HasValue ? context.Request.ContentLength.Value.ToString() : "0" }
        };
        foreach (var header in context.Request.Headers)
        {
            if (string.IsNullOrEmpty(header.Value)) continue;
            var headerName = "HTTP_" + header.Key.ToUpper().Replace('-', '_');
#pragma warning disable CS8601 // Possible null reference assignment.
            env[headerName] = header.Value;
#pragma warning restore CS8601 // Possible null reference assignment.
        }

        await ExecutePhpScriptAsyncStream(context, path, env);
    }

    public async Task ExecutePhpScriptAsyncStream(HttpContext context, string scriptFilename, Dictionary<string, string> env = null)
    {
        // Try to get an existing connection from the pool
        if (!_connectionPool.TryDequeue(out TcpClient? client))
        {
            client = new TcpClient();
            await client.ConnectAsync(_host, _port);
        }

        var stream = client.GetStream();

        ushort requestId = 1;
        var buffer = new List<byte>();

        // ---- BEGIN_REQUEST
        buffer.AddRange(BuildHeader(FastCGIConstants.BEGIN_REQUEST, requestId, 8));
        buffer.AddRange(new byte[] { 0x00, FastCGIConstants.ROLE_RESPONDER, 0x00, 0x00, 0x00, 0x00, 0x00 });

        var paramData = new List<byte>();
        foreach (var kv in env)
            paramData.AddRange(EncodeNameValuePair(kv.Key, kv.Value));

        buffer.AddRange(BuildHeader(FastCGIConstants.PARAMS, requestId, (ushort)paramData.Count));
        buffer.AddRange(paramData);

        // End of PARAMS (empty)
        buffer.AddRange(BuildHeader(FastCGIConstants.PARAMS, requestId, 0));

        await stream.WriteAsync(buffer.ToArray(), 0, buffer.Count);
        await stream.FlushAsync();

        // ----- Now stream POST body
        if (context.Request.Method != HttpMethods.Get &&
            context.Request.Method != HttpMethods.Head &&
            context.Request.Method != HttpMethods.Options)
        {
            context.Request.EnableBuffering(); // Allow re-reading the stream
            context.Request.Body.Position = 0;

            var tempBuffer = new byte[8192];
            int bytesRead;

            while ((bytesRead = await context.Request.Body.ReadAsync(tempBuffer, 0, tempBuffer.Length)) > 0)
            {
                var chunkHeader = BuildHeader(FastCGIConstants.STDIN, requestId, (ushort)bytesRead);
                await stream.WriteAsync(chunkHeader, 0, chunkHeader.Length);
                await stream.WriteAsync(tempBuffer, 0, bytesRead);
            }

            // Final empty STDIN
            var endStdin = BuildHeader(FastCGIConstants.STDIN, requestId, 0);
            await stream.WriteAsync(endStdin, 0, endStdin.Length);
            await stream.FlushAsync();
        }

        // ---- Read response
        try
        {
            while (true)
            {
                byte[] header = await ReadExactAsync(stream, 8);
                if (header.Length < 8)
                    break;

                byte type = header[1];
                ushort contentLength = (ushort)((header[4] << 8) + header[5]);
                byte paddingLength = header[6];

                byte[] content = contentLength > 0 ? await ReadExactAsync(stream, contentLength) : new byte[0];
                if (paddingLength > 0)
                    await ReadExactAsync(stream, paddingLength); // skip

                switch (type)
                {
                    case FastCGIConstants.STDOUT:
                        if (content.Length > 0)
                            await context.Response.Body.WriteAsync(content, 0, content.Length);
                        break;

                    case FastCGIConstants.STDERR:
                        var err = Encoding.UTF8.GetString(content);
                        Console.Error.WriteLine("[PHP STDERR] " + err);
                        break;

                    case FastCGIConstants.END_REQUEST:
                        return;
                }
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error reading response from FastCGI: {ex.Message}");
        }
        finally
        {
            // Return the TcpClient back to the pool
            if (_connectionPool.Count < Program.config.PHP_MaxPoolSize)
            {
                _connectionPool.Enqueue(client);
            }
            else
            {
                client.Close(); // Optionally, close the connection if the pool size limit is reached
            }
        }
    }

    private static byte[] BuildHeader(byte type, ushort requestId, ushort contentLength)
    {
        byte paddingLength = (byte)((8 - (contentLength % 8)) % 8);
        return new byte[]
        {
            FastCGIConstants.VERSION,
            type,
            (byte)(requestId >> 8),
            (byte)(requestId & 0xFF),
            (byte)(contentLength >> 8),
            (byte)(contentLength & 0xFF),
            paddingLength,
            0x00 // reserved
        };
    }

    private static IEnumerable<byte> EncodeNameValuePair(string name, string value)
    {
        var nameBytes = Encoding.UTF8.GetBytes(name);
        var valueBytes = Encoding.UTF8.GetBytes(value);

        var buffer = new List<byte>();

        void EncodeLength(int len)
        {
            if (len < 128)
            {
                buffer.Add((byte)len);
            }
            else
            {
                buffer.Add((byte)((len >> 24) | 0x80));
                buffer.Add((byte)(len >> 16));
                buffer.Add((byte)(len >> 8));
                buffer.Add((byte)(len));
            }
        }

        EncodeLength(nameBytes.Length);
        EncodeLength(valueBytes.Length);
        buffer.AddRange(nameBytes);
        buffer.AddRange(valueBytes);

        return buffer;
    }

    private static async Task<byte[]> ReadExactAsync(Stream stream, int length)
    {
        byte[] buffer = new byte[length];
        int offset = 0;
        while (offset < length)
        {
            int bytesRead = await stream.ReadAsync(buffer, offset, length - offset);
            if (bytesRead <= 0)
                break;
            offset += bytesRead;
        }
        return buffer;
    }
}
