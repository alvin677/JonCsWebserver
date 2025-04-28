namespace WebServer
{
    interface IStreamWriter
    {
        Task WriteAsync(Memory<byte> buffer);  // Change to accept Memory<byte>
        Task FlushAsync();
    }

    class DirectStreamWriter : IStreamWriter
    {
        private readonly Stream _stream;
        public DirectStreamWriter(Stream stream) => _stream = stream;
        public async Task WriteAsync(Memory<byte> buffer) => await _stream.WriteAsync(buffer);  // Direct write with Memory<byte>
        public Task FlushAsync()
        {
            _stream.FlushAsync();
            return Task.CompletedTask; // No need to flush manually
        }
    }

    class BufferedStreamWriter : IStreamWriter
    {
        private readonly MemoryStream _memoryStream = new MemoryStream();
        private readonly Stream _stream;
        public BufferedStreamWriter(Stream stream) => _stream = stream;
        public async Task WriteAsync(Memory<byte> buffer) => await _memoryStream.WriteAsync(buffer);  // Write async with Memory<byte>
        public async Task FlushAsync()
        {
            _memoryStream.Position = 0;
            await _memoryStream.CopyToAsync(_stream);
            await _stream.FlushAsync();
        }
        ~BufferedStreamWriter()
        {
            _memoryStream.Dispose();
        }
    }
}