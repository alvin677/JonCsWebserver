using System.Net;
using System.Net.Sockets;
using WebServer;
using static FastCGIClient;

public class TcpUnixClient : IDisposable
{
    private readonly Socket _socket;
    private readonly NetworkStream _stream;

    public NetworkStream Stream => _stream;
    public bool Connected => _socket.Connected;

    public int ReceiveTimeout
    {
        get => _socket.ReceiveTimeout;
        set => _socket.ReceiveTimeout = value;
    }
    public int SendTimeout
    {
        get => _socket.SendTimeout;
        set => _socket.SendTimeout = value;
    }

    public static async Task<TcpUnixClient> Create()
    {
        return await ConnectAsync(Startup.FastCGI.connect);
    }
    public TcpUnixClient(Socket socket)
    {
        _socket = socket ?? throw new ArgumentNullException(nameof(socket));
        _stream = new NetworkStream(_socket, ownsSocket: true);
    }

    public static async Task<TcpUnixClient> ConnectAsync(ConnectionInfo connectInfo)
    {
        Socket socket;

        switch (connectInfo.Type)
        {
            case EndpointType.IP:
#pragma warning disable CS8602 // Dereference of a possibly null reference.
                socket = new Socket(connectInfo.IpEndPoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                await socket.ConnectAsync(connectInfo.IpEndPoint);
#pragma warning restore CS8602 // Dereference of a possibly null reference.
                break;

            case EndpointType.Unix:
                socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
#pragma warning disable CS8604 // Possible null reference argument.
                await socket.ConnectAsync(connectInfo.UnixEndPoint);
#pragma warning restore CS8604 // Possible null reference argument.
                break;

            default:
                throw new InvalidOperationException("Unsupported endpoint type.");
        }

        return new TcpUnixClient(socket);
    }
    public void Close()
    {
        _socket?.Close();
        _stream?.Close();
    }

    public void Dispose()
    {
        _stream?.Dispose();
        _socket?.Dispose();
    }
}