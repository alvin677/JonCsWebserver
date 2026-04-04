using Microsoft.AspNetCore.Http;
using System.Buffers;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
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
    private static readonly int MinParamBufferSize = 16 * 1024; // 16KB, tune if needed
    //private readonly int _port;
    //private readonly string _host;
    public ConnectionInfo connect;
    private readonly ConcurrentQueue<TcpUnixClient> _connectionPool = new ConcurrentQueue<TcpUnixClient>();
    private static readonly string LocalIP = IPFinder.GetLocalIPAddress();
    // private const int MaxPoolSize = Startup.config.PHP_MaxPoolSize; // Adjust based on usage scenario
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
        if (Startup.config.MaxRequestBodySize != null && context.Request.ContentLength > Startup.config.MaxRequestBodySize)
        {
            context.Response.StatusCode = StatusCodes.Status413PayloadTooLarge;
            return;
        }
        // Better — span-based, zero allocation
        var relative = path.AsSpan(Startup.BackendDir.Length).TrimStart('/');
        int slash = relative.IndexOf('/');
        var firstSegment = slash < 0 ? relative : relative[..slash];
        string docRoot = Path.Combine(Startup.BackendDir, firstSegment.ToString());
        //string docRoot = Path.Combine(Startup.BackendDir, path.Substring(Startup.BackendDir.Length).TrimStart('/').Split("/")[0]); // /var/www/examplecom/test/index.php -> /var/www/examplecom
        string reqpath = path.Substring(docRoot.Length); // takes the file's path and slices to after the docRoot, so /var/www/examplecom/test/index.php -> /test/index.php
        // ---- PARAMS
        int envCapacity = 18 + context.Request.Headers.Count;
        var env = new Dictionary<string, string>(envCapacity)
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
            { "SERVER_ADDR", LocalIP },
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
            var headerName = string.Create(5 + header.Key.Length, header.Key, static (span, key) =>
            {
                span[0] = 'H'; span[1] = 'T'; span[2] = 'T'; span[3] = 'P'; span[4] = '_';
                for (int i = 0; i < key.Length; i++)
                {
                    char c = key[i];
                    span[5 + i] = c == '-' ? '_' :
                        (c >= 'a' && c <= 'z') ? (char)(c - 32) : c;
                }
            });
            env[headerName] = headerValue;
        }
#if DEBUG
        foreach (var item in env)
        {
            Console.WriteLine("env " + item.Key + " = " + item.Value);
        }
#endif
        await ExecutePhpScriptAsyncStream(context, GetRequestId(), env);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public ushort GetRequestId()
    {
        ushort id = ++requestId;
        return id != 0 ? id : ++requestId;
    }
    // Static readonly — allocated once at startup, never again
    private static readonly ReadOnlyMemory<byte> BeginRequestBody = new byte[]
    {
    0x00, FastCGIConstants.ROLE_RESPONDER, FastCGIConstants.FCGI_KEEP_CONN,
    0x00, 0x00, 0x00, 0x00, 0x00
    };
    public async Task ExecutePhpScriptAsyncStream(HttpContext context, ushort requestId, Dictionary<string, string> env)
    {
        // Try to get an existing connection from the pool
        if (!_connectionPool.TryDequeue(out TcpUnixClient? client) || !client.Connected)
        {
            client?.Close();
            client = await TcpUnixClient.Create();
#if DEBUG
            Console.WriteLine("Connecting new TcpClient.");
#endif
            client.ReceiveTimeout = Startup.config.FCGI_ReceiveTimeout;
            client.SendTimeout = Startup.config.FCGI_SendTimeout;
            //await client.ConnectAsync(_host, _port);
        }
#if DEBUG
        Console.WriteLine("Connected.");
#endif
        var stream = client.Stream;

        // --- Step 1: Prepare BEGIN + PARAMS ---
        IStreamWriter fastCgiStream = Startup.config.BufferFastCGIResponse ? new BufferedStreamWriter(stream) : new DirectStreamWriter(stream);

        // Rent all buffers upfront — single ArrayPool interaction block
        byte[] paramBuf = ArrayPool<byte>.Shared.Rent(MinParamBufferSize);
        byte[] contentBuf = ArrayPool<byte>.Shared.Rent(65535);
        byte[] postBuf = ArrayPool<byte>.Shared.Rent(8192);
        // 8-byte FCGI record header — stackalloc avoids any heap interaction
        byte[] recordHeader = ArrayPool<byte>.Shared.Rent(8);

        try
        {
            // STEP 1: BEGIN_REQUEST
            await SendRecord(fastCgiStream, FastCGIConstants.BEGIN_REQUEST, requestId, BeginRequestBody);
            // await fastCgiStream.WriteAsync(new byte[] { 0x00, FastCGIConstants.ROLE_RESPONDER, FastCGIConstants.FCGI_KEEP_CONN, 0x00, 0x00, 0x00, 0x00, 0x00 });

            // STEP 2: PARAMS
            int paramLen = 0;
            foreach (var kv in env)
                paramLen += EncodeNameValuePair(kv.Key, kv.Value, paramBuf.AsSpan(paramLen));

            await SendRecord(fastCgiStream, FastCGIConstants.PARAMS, requestId, paramBuf.AsMemory(0, paramLen));
            await SendRecord(fastCgiStream, FastCGIConstants.PARAMS, requestId, ReadOnlyMemory<byte>.Empty); // Empty PARAMS
            await fastCgiStream.FlushAsync(); // Only flush, wrapper handles the rest. Will use the stream var below since loading POST to memory would take a lot of RAM, which would be impractical.

            // --- Step 3: STDIN / Stream the body (POST data etc) ---
            if (context.Request.Method != HttpMethods.Get &&
                context.Request.Method != HttpMethods.Head &&
                context.Request.Method != HttpMethods.Options)
            {
                int bytesRead;
                while ((bytesRead = await context.Request.Body.ReadAsync(postBuf)) > 0)
                    await SendRecord(stream, FastCGIConstants.STDIN, requestId, postBuf.AsMemory(0, bytesRead));
                await stream.FlushAsync();
            }

            // Final empty STDIN
            await SendRecord(stream, FastCGIConstants.STDIN, requestId, ReadOnlyMemory<byte>.Empty);
            await stream.FlushAsync(); // ensure all data is sent.

            // --- Step 4: Read FastCGI Response ---
            bool headersSent = false;
            var stdoutBuffer = new ArrayBufferWriter<byte>(4096);
            while (true)
            {
                if (!await ReadExactAsync(stream, recordHeader, 8)) break; // connection closed prematurely

                byte type = recordHeader[1];
                ushort contentLen = (ushort)((recordHeader[4] << 8) | recordHeader[5]);
                byte paddingLen = recordHeader[6];

#if DEBUG
                Console.WriteLine($"header[4]={recordHeader[4]}, header[5]={recordHeader[5]}, contentLen={contentLen}");
#endif
                if (contentLen > 0 && !await ReadExactAsync(stream, contentBuf, contentLen)) break;
                if (paddingLen > 0) await ReadExactAsync(stream, PaddingSkipBuf, paddingLen); // skip padding

                switch (type)
                {
                    case FastCGIConstants.STDOUT:
#if DEBUG
                        Console.WriteLine($"FastCGI STDOUT length: {contentLen}");
#endif
                        if (contentLen == 0) continue;

                        if (!headersSent)
                        {
                            stdoutBuffer.Write(contentBuf.AsSpan(0, contentLen));
                            var written = stdoutBuffer.WrittenSpan;
                            int headerEnd = FindDoubleCRLF(written);

                            if (headerEnd != -1)
                            {
                                ParseAndApplyHeaders(written[..headerEnd], context);
                                headersSent = true;

                                int bodyStart = headerEnd + 4;
                                if (bodyStart < written.Length)
                                    await context.Response.Body.WriteAsync(
                                        stdoutBuffer.WrittenMemory[bodyStart..]);
                            }
                        }
                        else
                        {
                            await context.Response.Body.WriteAsync(contentBuf.AsMemory(0, contentLen));
                        }
                        break;

                    case FastCGIConstants.STDERR:
#if DEBUG
                        Console.Error.WriteLine("[PHP STDERR] " + Encoding.UTF8.GetString(contentBuf, 0, contentLen));
#endif
                        break;

                    case FastCGIConstants.END_REQUEST:
                        await context.Response.CompleteAsync();
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
            ArrayPool<byte>.Shared.Return(paramBuf);
            ArrayPool<byte>.Shared.Return(contentBuf);
            ArrayPool<byte>.Shared.Return(postBuf);
            ArrayPool<byte>.Shared.Return(recordHeader);
            // Return TcpClient to pool
            if (_connectionPool.Count < Startup.config.PHP_MaxPoolSize && client.Connected)
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
    // Extracted to keep the hot loop clean — parses PHP-FPM response headers directly from span
    private static void ParseAndApplyHeaders(ReadOnlySpan<byte> headerSpan, HttpContext context)
    {
        int lineStart = 0;
        while (lineStart < headerSpan.Length)
        {
            var remaining = headerSpan[lineStart..];
            int lineEnd = remaining.IndexOf((byte)'\n');
            var line = lineEnd < 0 ? remaining : remaining[..lineEnd];

            // Trim \r
            if (line.Length > 0 && line[^1] == '\r') line = line[..^1];

            int sep = line.IndexOf((byte)':');
            if (sep > 0)
            {
                // Decode key/value only — unavoidable string alloc for ASP.NET header API
                var key = Encoding.UTF8.GetString(line[..sep]).Trim();
                var value = Encoding.UTF8.GetString(line[(sep + 1)..]).Trim();

                if (string.Equals(key, "Status", StringComparison.OrdinalIgnoreCase))
                {
                    int spaceIdx = value.IndexOf(' ');
                    if (int.TryParse(spaceIdx > 0 ? value[..spaceIdx] : value, out int code))
                        context.Response.StatusCode = code;
                }
                else
                {
                    context.Response.Headers[key] = value;
                }
            }

            lineStart += (lineEnd < 0 ? remaining.Length : lineEnd + 1);
        }
    }
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static async Task<bool> ReadExactAsync(Stream stream, byte[] buffer, int length)
    {
        int offset = 0;
        while (offset < length)
        {
            int read = await stream.ReadAsync(buffer.AsMemory(offset, length - offset));
            if (read == 0) return false;
            offset += read;
        }
        return true;
    }

    private static readonly byte[] ZeroPadding = new byte[8]; // SendRecord: write padding out
    private static readonly byte[] PaddingSkipBuf = new byte[8]; // ReadExactAsync: discard incoming padding
    private static async Task SendRecord(Stream stream, byte type, ushort requestId, ReadOnlyMemory<byte> content)
    {
        ushort contentLength = (ushort)content.Length;
        byte paddingLength = (byte)((8 - (contentLength % 8)) % 8);

        byte[] headerBuf = ArrayPool<byte>.Shared.Rent(8);
        headerBuf[0] = FastCGIConstants.VERSION;
        headerBuf[1] = type;
        headerBuf[2] = (byte)(requestId >> 8);
        headerBuf[3] = (byte)(requestId & 0xFF);
        headerBuf[4] = (byte)(contentLength >> 8);
        headerBuf[5] = (byte)(contentLength & 0xFF);
        headerBuf[6] = paddingLength;
        headerBuf[7] = 0x00;

        await stream.WriteAsync(headerBuf.AsMemory(0, 8));
        ArrayPool<byte>.Shared.Return(headerBuf);

        if (contentLength > 0)
            await stream.WriteAsync(content);
        if (paddingLength > 0)
            await stream.WriteAsync(ZeroPadding.AsMemory(0, paddingLength));
    }
    private static async Task SendRecord(IStreamWriter stream, byte type, ushort requestId, ReadOnlyMemory<byte> content)
    {
        ushort contentLength = (ushort)content.Length;
        byte paddingLength = (byte)((8 - (contentLength % 8)) % 8);

        byte[] headerBuf = ArrayPool<byte>.Shared.Rent(8);
        headerBuf[0] = FastCGIConstants.VERSION;
        headerBuf[1] = type;
        headerBuf[2] = (byte)(requestId >> 8);
        headerBuf[3] = (byte)(requestId & 0xFF);
        headerBuf[4] = (byte)(contentLength >> 8);
        headerBuf[5] = (byte)(contentLength & 0xFF);
        headerBuf[6] = paddingLength;
        headerBuf[7] = 0x00; // reserved

        await stream.WriteAsync(headerBuf.AsMemory(0, 8));
        ArrayPool<byte>.Shared.Return(headerBuf);

        if (contentLength > 0)
            await stream.WriteAsync(content);
        if (paddingLength > 0)
            await stream.WriteAsync(ZeroPadding.AsMemory(0, paddingLength));
    }
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int EncodeLength(int len, Span<byte> dest)
    {
        if (len < 128)
        {
            dest[0] = (byte)len;
            return 1;
        }
        dest[0] = (byte)((len >> 24) | 0x80);
        dest[1] = (byte)(len >> 16);
        dest[2] = (byte)(len >> 8);
        dest[3] = (byte)len;
        return 4;
    }
    private static int EncodeNameValuePair(string name, string value, Span<byte> dest)
    {
        int nameLen = Encoding.UTF8.GetByteCount(name);
        int valueLen = Encoding.UTF8.GetByteCount(value);

        int pos = 0;
        pos += EncodeLength(nameLen, dest[pos..]);
        pos += EncodeLength(valueLen, dest[pos..]);
        pos += Encoding.UTF8.GetBytes(name, dest[pos..]);
        pos += Encoding.UTF8.GetBytes(value, dest[pos..]);
        return pos;
    }

    private static int FindDoubleCRLF(ReadOnlySpan<byte> data)
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
