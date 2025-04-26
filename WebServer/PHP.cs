using Microsoft.AspNetCore.Http;
using System.Buffers;
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
    private ushort requestId = 0;
    private readonly int _port;
    private readonly string _host;
    private readonly ConcurrentQueue<TcpClient> _connectionPool = new ConcurrentQueue<TcpClient>();
    
    // private const int MaxPoolSize = Program.config.PHP_MaxPoolSize; // Adjust based on usage scenario

    public FastCGIClient(string host = "127.0.0.1", int port = 9000)
    {
        _host = host;
        _port = port;
    }

    public async Task Run(HttpContext context, string path)
    {
        string docRoot = Path.Combine(Program.BackendDir, path.Substring(Program.BackendDir.Length).TrimStart('/').Split("/")[0]);
        string reqpath = path.Substring(docRoot.Length);
        // ---- PARAMS
        var env = new Dictionary<string, string>
        {
            { "GATEWAY_INTERFACE", "FastCGI/1.0" },
            { "REQUEST_METHOD", context.Request.Method },
            { "REQUEST_URI", reqpath },
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
        foreach (var header in context.Request.Headers)
        {
            var headerValue = header.Value.ToString();
            if (string.IsNullOrEmpty(headerValue)) continue;
            var headerName = "HTTP_" + header.Key.ToUpper().Replace('-', '_');
            env[headerName] = headerValue;
        }

        foreach (var item in env)
        {
            Console.WriteLine("env " + item.Key + " = " + item.Value);
        }

        await ExecutePhpScriptAsyncStream(context, path, GetRequestId(), env);
    }

    public ushort GetRequestId()
    {
        requestId++;
        return requestId == 0 ? ++requestId : requestId;
    }

    public async Task ExecutePhpScriptAsyncStream(HttpContext context, string scriptFilename, ushort requestId, Dictionary<string, string> env = null)
    {
        // Try to get an existing connection from the pool
        if (!_connectionPool.TryDequeue(out TcpClient? client) || !client.Connected)
        {
            client?.Close();
            client = new TcpClient();
            Console.WriteLine("Connecting new TcpClient.");
            client.ReceiveTimeout = 300000;
            client.SendTimeout = 300000;
            await client.ConnectAsync(_host, _port);
        }
        Console.WriteLine("Connected.");

        var stream = client.GetStream();


        // --- Step 1: MemoryStream for BEGIN + PARAMS ---
        var fastCgiStream = new MemoryStream();

        // BEGIN_REQUEST
        fastCgiStream.Write(BuildHeader(FastCGIConstants.BEGIN_REQUEST, requestId, 8));
        fastCgiStream.Write(new byte[] { 0x00, FastCGIConstants.ROLE_RESPONDER, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });

        // PARAMS
        var paramData = new List<byte>();
        foreach (var kv in env)
            paramData.AddRange(EncodeNameValuePair(kv.Key, kv.Value));

        fastCgiStream.Write(BuildHeader(FastCGIConstants.PARAMS, requestId, (ushort)paramData.Count));
        fastCgiStream.Write(paramData.ToArray());

        // Empty PARAMS
        fastCgiStream.Write(BuildHeader(FastCGIConstants.PARAMS, requestId, 0));

        // --- Step 2: Send the setup ---
        fastCgiStream.Position = 0;
        await fastCgiStream.CopyToAsync(stream);
        await stream.FlushAsync();

        // --- Step 3: Stream the body ---
        if (context.Request.Method != HttpMethods.Get &&
            context.Request.Method != HttpMethods.Head &&
            context.Request.Method != HttpMethods.Options)
        {
            context.Request.EnableBuffering();
            context.Request.Body.Position = 0;

            var tempBuffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = await context.Request.Body.ReadAsync(tempBuffer, 0, tempBuffer.Length)) > 0)
            {
                // Write header for this body chunk
                var bodyHeader = BuildHeader(FastCGIConstants.STDIN, requestId, (ushort)bytesRead);
                await stream.WriteAsync(bodyHeader);

                // Write body chunk
                await stream.WriteAsync(tempBuffer.AsMemory(0, bytesRead));
            }
        }

        // --- Step 4: Final empty STDIN ---
        await stream.WriteAsync(BuildHeader(FastCGIConstants.STDIN, requestId, 0));

        // --- Step 5: Flush once ---
        await stream.FlushAsync();


        // ---- Read response
        try
        {
            bool headersSent = false;
            var stdoutBuffer = new MemoryStream();

            while (true)
            {
                byte[] header = await ReadExactAsync(stream, 8);
                Console.WriteLine("Received CGI header of size: " + header.Length.ToString());
                if (header.Length < 8) break;

                byte type = header[1];
                ushort contentLength = (ushort)((header[4] << 8) + header[5]);
                byte paddingLength = header[6];
                Console.WriteLine("Based of header[4] (" + header[4] + ") and header[5] (" + header[5] + "), contentLength = " + contentLength.ToString());
                byte[] content = contentLength > 0 ? await ReadExactAsync(stream, contentLength) : Array.Empty<byte>();
                if (paddingLength > 0)
                {
                    Console.WriteLine("Skip padding: " + paddingLength.ToString());
                    await ReadExactAsync(stream, paddingLength); // skip padding
                }
                Console.WriteLine("content:\n" + Encoding.UTF8.GetString(content));
                switch (type)
                {
                    case FastCGIConstants.STDOUT:
                        Console.WriteLine("FastCGI STDOUT length: " + content.Length.ToString());
                        Console.WriteLine("FastCGI STDOUT byte[] content = " + content);
                        if (content.Length == 0) continue;

                        if (!headersSent)
                        {
                            stdoutBuffer.Write(content, 0, content.Length);

                            var headerBytes = stdoutBuffer.ToArray();
                            var headerEnd = FindDoubleCRLF(headerBytes);
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
                                {
                                    await context.Response.Body.WriteAsync(headerBytes, bodyStart, headerBytes.Length - bodyStart);
                                }
                            }
                        }
                        else
                        {
                            await context.Response.Body.WriteAsync(content, 0, content.Length);
                        }

                        break;

                    case FastCGIConstants.STDERR:
                        var err = Encoding.UTF8.GetString(content);
                        Console.Error.WriteLine("[PHP STDERR] " + err);
                        break;

                    case FastCGIConstants.END_REQUEST:
                        Console.WriteLine("FastCGI received: END_REQUEST");
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
            if (_connectionPool.Count < Program.config.PHP_MaxPoolSize && client.Connected)
            {
                _connectionPool.Enqueue(client);
                Console.WriteLine("TcpClient was put back to queue..");
            }
            else
            {
                client.Close(); // Optionally, close the connection if the pool size limit is reached
                Console.WriteLine("TcpClient was closed..");
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
