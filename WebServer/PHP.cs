﻿using Microsoft.AspNetCore.Http;
using System.Buffers;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using WebServer;

public static class FastCGIConstants
{
    public const byte VERSION = 1;
    public const byte BEGIN_REQUEST = 1;
    public const byte PARAMS = 4;
    public const byte STDIN = 5;
    public const byte STDOUT = 6;
    public const byte STDERR = 7;
    public const byte END_REQUEST = 3;
    public const byte ROLE_RESPONDER = 0x01;
    public const byte FCGI_KEEP_CONN = 0x01;
}

public class FastCGIClient
{
    private ushort requestId = 0;
    //private readonly int _port;
    //private readonly string _host;
    public ConnectionInfo connect;
    private readonly ConcurrentQueue<TcpUnixClient> _connectionPool = new ConcurrentQueue<TcpUnixClient>();
    // private const int MaxPoolSize = Program.config.PHP_MaxPoolSize; // Adjust based on usage scenario
    /*public FastCGIClient(string host = "127.0.0.1", int port = 9000)
    {
        connect = ParseEndpoint(host + ":" + port.ToString());
        _host = host;
        _port = port;
    }*/
    public FastCGIClient(string conn = "127.0.0.1:9000")
    {
        connect = ParseEndpoint(conn);
    }
    public enum EndpointType
    {
        IP,
        Unix
    }

    public class ConnectionInfo
    {
        public EndpointType Type { get; init; }
        public IPEndPoint? IpEndPoint { get; init; }
        public UnixDomainSocketEndPoint? UnixEndPoint { get; init; }
    }
    public static ConnectionInfo ParseEndpoint(string endpoint)
    {
        if (endpoint.Contains(':'))
        {
            var parts = endpoint.Split(':', 2);
            if (!IPAddress.TryParse(parts[0], out var ip))
                ip = Dns.GetHostAddresses(parts[0])[0];

            int port = int.Parse(parts[1]);
            return new ConnectionInfo
            {
                Type = EndpointType.IP,
                IpEndPoint = new IPEndPoint(ip, port)
            };
        }
        else
        {
            return new ConnectionInfo
            {
                Type = EndpointType.Unix,
                UnixEndPoint = new UnixDomainSocketEndPoint(endpoint)
            };
        }
    }

    public async Task Run(HttpContext context, string path)
    {
        if (Program.config.MaxRequestBodySize != null && context.Request.ContentLength > Program.config.MaxRequestBodySize)
        {
            context.Response.StatusCode = StatusCodes.Status413PayloadTooLarge;
            return;
        }
        string docRoot = Path.Combine(Program.BackendDir, path.Substring(Program.BackendDir.Length).TrimStart('/').Split("/")[0]); // /var/www/examplecom/test/index.php -> /var/www/examplecom
        string reqpath = path.Substring(docRoot.Length); // takes the file's path and slices to after the docRoot, so /var/www/examplecom/test/index.php -> /test/index.php
        // ---- PARAMS
        var env = new Dictionary<string, string>
        {
            { "GATEWAY_INTERFACE", "FastCGI/1.0" },
            { "REQUEST_METHOD", context.Request.Method },
            { "REQUEST_SCHEME", context.Request.Scheme },
            { "REQUEST_URI", reqpath + context.Request.QueryString },
            { "SCRIPT_FILENAME", path },
            { "SCRIPT_NAME", reqpath },
            { "DOCUMENT_ROOT", docRoot },
            { "QUERY_STRING", context.Request.QueryString.HasValue ? context.Request.QueryString.Value.TrimStart('?') : "" },
            { "SERVER_SOFTWARE", "JonCsWebServer" },
            { "REMOTE_ADDR", context.Connection.RemoteIpAddress != null ? context.Connection.RemoteIpAddress.ToString() : "127.0.0.1" },
            { "REMOTE_PORT", context.Connection.RemotePort.ToString() },
            { "SERVER_ADDR", Program.LocalIP },
            { "SERVER_PORT", context.Request.Host.Port.HasValue ? context.Request.Host.Port.Value.ToString() : "80" },
            { "SERVER_NAME", context.Request.Host.Host },
            { "SERVER_PROTOCOL", context.Request.Protocol },
            { "REDIRECT_STATUS", "200" },
            { "CONTENT_LENGTH", context.Request.ContentLength.HasValue ? context.Request.ContentLength.Value.ToString() : "0" }
        };
        if (context.Request.Headers.TryGetValue("Content-Type", out var contentType))
        {
            env["CONTENT_TYPE"] = contentType.ToString();
        }
        foreach (var header in context.Request.Headers)
        {
            var headerValue = header.Value.ToString();
            if (string.IsNullOrEmpty(headerValue)) continue;
            var headerName = "HTTP_" + header.Key.ToUpper().Replace('-', '_');
            env[headerName] = headerValue;
        }
#if DEBUG
        foreach (var item in env)
        {
            Console.WriteLine("env " + item.Key + " = " + item.Value);
        }
#endif
        await ExecutePhpScriptAsyncStream(context, path, GetRequestId(), env);
    }

    public ushort GetRequestId()
    {
        requestId++;
        return requestId == 0 ? ++requestId : requestId;
    }

    public async Task ExecutePhpScriptAsyncStream(HttpContext context, string scriptFilename, ushort requestId, Dictionary<string, string> env)
    {
        // Try to get an existing connection from the pool
        if (!_connectionPool.TryDequeue(out TcpUnixClient? client) || !client.Connected)
        {
            client?.Close();
            client = await TcpUnixClient.Create();
#if DEBUG
            Console.WriteLine("Connecting new TcpClient.");
#endif
            client.ReceiveTimeout = Program.config.FCGI_ReceiveTimeout;
            client.SendTimeout = Program.config.FCGI_SendTimeout;
            //await client.ConnectAsync(_host, _port);
        }
#if DEBUG
        Console.WriteLine("Connected.");
#endif
        var stream = client.Stream;

        // --- Step 1: Prepare BEGIN + PARAMS ---
        IStreamWriter fastCgiStream = Program.config.BufferFastCGIResponse ? new BufferedStreamWriter(stream) : new DirectStreamWriter(stream);

        // BEGIN_REQUEST
        await SendRecord(fastCgiStream, FastCGIConstants.BEGIN_REQUEST, requestId, new byte[] { 0x00, FastCGIConstants.ROLE_RESPONDER, FastCGIConstants.FCGI_KEEP_CONN, 0x00, 0x00, 0x00, 0x00, 0x00 });
        // await fastCgiStream.WriteAsync(BuildHeader(FastCGIConstants.BEGIN_REQUEST, requestId, 8));
        // await fastCgiStream.WriteAsync(new byte[] { 0x00, FastCGIConstants.ROLE_RESPONDER, FastCGIConstants.FCGI_KEEP_CONN, 0x00, 0x00, 0x00, 0x00, 0x00 });

        // PARAMS
        var paramData = new List<byte>();
        foreach (var kv in env)
            paramData.AddRange(EncodeNameValuePair(kv.Key, kv.Value));
        //await fastCgiStream.WriteAsync(BuildHeader(FastCGIConstants.PARAMS, requestId, (ushort)paramData.Count));
        //await fastCgiStream.WriteAsync(paramData.ToArray());

        await SendRecord(fastCgiStream, FastCGIConstants.PARAMS, requestId, paramData.ToArray());
        await SendRecord(fastCgiStream, FastCGIConstants.PARAMS, requestId, ReadOnlyMemory<byte>.Empty); // Empty PARAMS

        // Empty PARAMS
        //await fastCgiStream.WriteAsync(BuildHeader(FastCGIConstants.PARAMS, requestId, 0));

        // --- Step 2: Send the setup ---
        await fastCgiStream.FlushAsync(); // Only flush, wrapper handles the rest. Will use the stream var below since loading POST to memory would take a lot of RAM, which would be impractical.

        // --- Step 2: Stream the body (POST data etc) ---
        if (context.Request.Method != HttpMethods.Get &&
            context.Request.Method != HttpMethods.Head &&
            context.Request.Method != HttpMethods.Options)
        {
            //context.Request.EnableBuffering();
            //context.Request.Body.Position = 0;

            var tempBuffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = await context.Request.Body.ReadAsync(tempBuffer, 0, tempBuffer.Length)) > 0)
            {
                await SendRecord(stream, FastCGIConstants.STDIN, requestId, tempBuffer.AsMemory(0, bytesRead));
                //await stream.WriteAsync(BuildHeader(FastCGIConstants.STDIN, requestId, (ushort)bytesRead));
                //await stream.WriteAsync(tempBuffer.AsMemory(0, bytesRead));
            }
            await stream.FlushAsync();
        }

        // Final empty STDIN
        await SendRecord(stream, FastCGIConstants.STDIN, requestId, ReadOnlyMemory<byte>.Empty);
        //await stream.WriteAsync(BuildHeader(FastCGIConstants.STDIN, requestId, 0));
        await stream.FlushAsync(); // ensure all data is sent.

        // --- Step 3: Read FastCGI Response ---
        try
        {
            bool headersSent = false;
            using var stdoutBuffer = new MemoryStream();
            byte[] header = new byte[8];
            while (true)
            {
                bool success = await ReadExactAsync(stream, header, 8);

#if DEBUG
                Console.WriteLine("Received CGI header of size: " + header.Length.ToString());
#endif
                if (!success) break; // connection closed prematurely

                byte type = header[1];
                ushort contentLength = (ushort)((header[4] << 8) | header[5]);
#if DEBUG
                Console.WriteLine("Based of header[4] (" + header[4] + ") and header[5] (" + header[5] + "), contentLength = " + contentLength.ToString());
#endif
                byte paddingLength = header[6];

                byte[] content = contentLength > 0 ? await ReadExactAsync(stream, contentLength) : Array.Empty<byte>();
                if (paddingLength > 0)
                    await ReadExactAsync(stream, paddingLength); // skip padding

                switch (type)
                {
                    case FastCGIConstants.STDOUT:
#if DEBUG
                        Console.WriteLine("FastCGI STDOUT length: " + content.Length.ToString());
                        Console.WriteLine("FastCGI STDOUT byte[] content = " + content);
#endif
                        if (content.Length == 0) continue;

                        if (!headersSent)
                        {
                            stdoutBuffer.Write(content, 0, content.Length);
                            var headerBytes = stdoutBuffer.GetBuffer();
                            int headerEnd = FindDoubleCRLF(headerBytes.AsSpan(0, (int) stdoutBuffer.Length));

                            if (headerEnd != -1)
                            {
                                var headersPart = Encoding.UTF8.GetString(headerBytes, 0, headerEnd);
                                var lines = headersPart.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);
                                foreach (var line in lines)
                                {
                                    var separatorIndex = line.IndexOf(':');
                                    if (separatorIndex > 0)
                                    {
                                        var key = line[..separatorIndex].Trim();
                                        var value = line[(separatorIndex + 1)..].Trim();

                                        if (string.Equals(key, "Status", StringComparison.OrdinalIgnoreCase))
                                        {
                                            if (int.TryParse(value.Split(' ')[0], out int statusCode))
                                                context.Response.StatusCode = statusCode;
                                        }
                                        else
                                        {
                                            context.Response.Headers[key] = value;
                                        }
                                    }
                                }

                                headersSent = true;
                                var bodyStart = headerEnd + 4;
                                if (bodyStart < headerBytes.Length)
                                    await context.Response.Body.WriteAsync(headerBytes.AsMemory(bodyStart, headerBytes.Length - bodyStart));
                            }
                        }
                        else
                        {
                            await context.Response.Body.WriteAsync(content.AsMemory(0, content.Length));
                        }
                        break;

                    case FastCGIConstants.STDERR:
                        var err = Encoding.UTF8.GetString(content);
                        Console.Error.WriteLine("[PHP STDERR] " + err);
                        break;

                    case FastCGIConstants.END_REQUEST:
                        _ = context.Response.CompleteAsync();
                        return;
                }
            }
        }
        catch (IOException ex)
        {
            // Handle the IO errors (connection resets, timeouts)
            Console.Error.WriteLine($"FastCGI IO error occurred: {ex.Message}");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error reading response from FastCGI: {ex.Message}");
        }
        finally
        {
            // Return TcpClient to pool
            if (_connectionPool.Count < Program.config.PHP_MaxPoolSize && client.Connected)
            {
                _connectionPool.Enqueue(client);
#if DEBUG
                Console.WriteLine("TcpClient was put back to queue..");
#endif
            }
            else
            {
                client.Close();
                client.Dispose();
#if DEBUG
                Console.WriteLine("TcpClient was closed..");
#endif
            }
        }
    }

    private static async Task SendRecord(Stream stream, byte type, ushort requestId, ReadOnlyMemory<byte> content)
    {
        ushort contentLength = (ushort)content.Length;
        byte paddingLength = (byte)((8 - (contentLength % 8)) % 8);
        byte[] header = BuildHeader(type, requestId, contentLength, paddingLength);

        await stream.WriteAsync(header);
        if (contentLength > 0)
            await stream.WriteAsync(content);
        if (paddingLength > 0)
            await stream.WriteAsync(new byte[paddingLength]);
    }
    private static async Task SendRecord(IStreamWriter stream, byte type, ushort requestId, ReadOnlyMemory<byte> content)
    {
        ushort contentLength = (ushort)content.Length;
        byte paddingLength = (byte)((8 - (contentLength % 8)) % 8);
        var header = BuildHeader(type, requestId, contentLength, paddingLength);

        await stream.WriteAsync(header);
        if (contentLength > 0)
            await stream.WriteAsync(content);
        if (paddingLength > 0)
            await stream.WriteAsync(new byte[paddingLength]);
    }
    
    private static byte[] BuildHeader(byte type, ushort requestId, ushort contentLength, byte paddingLength)
    {
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
        byte[] buffer = ArrayPool<byte>.Shared.Rent(length);
        int offset = 0;
        while (offset < length)
        {
            int bytesRead = await stream.ReadAsync(buffer, offset, length - offset);
            if (bytesRead <= 0)
                break;
            offset += bytesRead;
        }

        var result = buffer.Take(offset).ToArray(); // Copy only used part
        ArrayPool<byte>.Shared.Return(buffer);
        return result;
    }
    private static async Task<bool> ReadExactAsync(Stream stream, byte[] buffer, int length)
    {
        int offset = 0;
        while (offset < length)
        {
            int read = await stream.ReadAsync(buffer, offset, length - offset);
            if (read == 0)
            {
                // Connection closed before reading expected amount
                return false;
            }
            offset += read;
        }
        return true;
    }
    public static async ValueTask<bool> ReadExactAsync(Stream stream, Memory<byte> buffer, int size)
    {
        int totalRead = 0;
        while (totalRead < size)
        {
            int read = await stream.ReadAsync(buffer.Slice(totalRead, size - totalRead));
            if (read == 0)
                return false; // Closed early
            totalRead += read;
        }
        return true;
    }

    private int FindDoubleCRLF(Span<byte> data)
    {
        for (int i = 0; i < data.Length - 3; i++)
        {
            if (data[i] == '\r' && data[i + 1] == '\n' &&
                data[i + 2] == '\r' && data[i + 3] == '\n')
            {
                return i;
            }
        }
        return -1;
    }
    private int FindDoubleCRLF(byte[] data)
    {
        for (int i = 0; i < data.Length - 3; i++)
        {
            if (data[i] == '\r' && data[i + 1] == '\n' &&
                data[i + 2] == '\r' && data[i + 3] == '\n')
            {
                return i;
            }
        }
        return -1;
    }
}
