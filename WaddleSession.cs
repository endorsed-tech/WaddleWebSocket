using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace WaddleWebSocket;

public sealed class WaddleSession
{
    public event Action<WaddleSession>? OnDisconnect;
    public event Action<WaddleSession>? OnHandshakeCompleted;
    public event EventHandler<ReadOnlyMemory<byte>>? OnRecievedMessage;
    public event EventHandler<ReadOnlyMemory<byte>>? OnRecievedBinaryMessage;
    public event EventHandler<string>? OnRecievedTextMessage;

    private WaddleWsServer _server;
    private TcpClient _client;
    private NetworkStream _stream;
    private Guid _guid;
    private bool _connected = false;

    public WaddleSession(TcpClient client, WaddleWsServer server)
    {
        _server = server;
        _client = client;
        _stream = client.GetStream();
        _guid = Guid.NewGuid();
    }

    public Guid GetGuid() => _guid;

    private const string endl = "\r\n";
    public void Start()
    {
        using MemoryStream messageBuffer = new();
        bool isConnecting = false;
        bool shouldClose = false;
        while (_client.Connected)
        {
            while (!_stream.DataAvailable) ;
            while (_client.Available < 3) ;

            byte[] bytes = new byte[_client.Available];
            _stream.Read(bytes.AsSpan());
            string inBytesStr = Encoding.UTF8.GetString(bytes);

            // Upgrade request solution derived from:
            // https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_server#put_together
            if (!_connected && !isConnecting && Regex.IsMatch(inBytesStr, "^GET", RegexOptions.IgnoreCase))
            {
                string swk = Regex.Match(inBytesStr, "Sec-WebSocket-Key: (.*)").Groups[1].Value.Trim();
                string swka = swk + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
                string swkaSha1Str = Convert.ToBase64String(SHA1.Create().ComputeHash(Encoding.UTF8.GetBytes(swka)));

                string protocols = Regex.Match(inBytesStr, "Sec-WebSocket-Protocol: (.*)").Groups[1].Value.Trim();
                string extensions = Regex.Match(inBytesStr, "Sec-WebSocket-Extensions: (.*)").Groups[1].Value.Trim();
                string version = Regex.Match(inBytesStr, "Sec-WebSocket-Version: (\\d*)").Groups[1].Value.Trim();

                string hsresponse = "HTTP/1.1 101 Switching Protocols" + endl +
                                    "Upgrade: websocket" + endl +
                                    "Connection: Upgrade" + endl +
                                    $"Sec-WebSocket-Accept: {swkaSha1Str}" + endl
                                    + endl;

                isConnecting = true;

                // TODO: Support Protocols
                // TODO: Support Extensions
                // TODO: Support Multiple Versions

                byte[] responseBytes = Encoding.UTF8.GetBytes(hsresponse);
                _stream.Write(responseBytes.AsSpan());

                _connected = true;
                isConnecting = false;
                OnHandshakeCompleted?.Invoke(this);
                continue;
            }
            else if (!_connected && !isConnecting)
            {
                throw new InvalidOperationException("Can not operate on a client that has not completed the handshake.");
            }

            bool fin = (bytes[0] & 0b10000000) != 0;
            bool mask = (bytes[1] & 0b10000000) != 0;

            // if (!mask)
            //     throw new InvalidDataException($"`{nameof(mask).ToUpper()}` from the client MUST be set.");

            int opcode = (bytes[0] & 0b00001111);

            switch (opcode)
            {
                case 0x00: // Continuation Frame
                    continue;

                case 0x01: // Text Frame
                case 0x02: // Binary Frame
                    break;

                case 0x08: //Connection Close
                    shouldClose = true;
                    break;

                case 0x09:
                    // TODO: Immediate ping
                    if (shouldClose) break;
                    continue;

                case 0x0A:
                    // TODO: Immediate pong
                    if (shouldClose) break;
                    continue;

                default: // Reserved
                    continue;
            }

            ulong payloadLen = (ulong)(bytes[1] & 0b01111111);
            int offset = 2;

            if (payloadLen == 126)
            {
                var lenSpan = bytes.AsSpan(3, 2);
                lenSpan.Reverse();
                payloadLen = BitConverter.ToUInt16(lenSpan);
                offset += 2;
            }
            else if (payloadLen == 127)
            {
                var lenSpan = bytes.AsSpan(3, 8);
                lenSpan.Reverse();
                payloadLen = BitConverter.ToUInt64(lenSpan);
                offset += 8;
            }

            if (payloadLen is 0) continue;

            byte[] decoded = new byte[payloadLen];
            byte[] masks = new byte[4] { bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3] };
            offset += 4;

            for (ulong i = 0; i < payloadLen; i++)
            {
                decoded[i] = (byte)(bytes[(ulong)offset + i] ^ masks[i % 4]);
            }

            messageBuffer.Write(decoded);

            if (!fin) continue;

            switch (opcode)
            {
                case 0x01:
                    OnRecievedMessage?.Invoke(this, messageBuffer.GetBuffer());
                    OnRecievedTextMessage?.Invoke(this, new String(Encoding.UTF8.GetString(messageBuffer.GetBuffer())));
                    break;

                case 0x02:
                    OnRecievedMessage?.Invoke(this, messageBuffer.GetBuffer());
                    OnRecievedBinaryMessage?.Invoke(this, messageBuffer.GetBuffer());
                    break;

                case 0x08:
                    Disconnect();
                    break;

                default:
                    throw new InvalidOperationException($"Invalid opcode `0x{opcode:X2}`");
            }
        }
    }

    public void Disconnect()
    {
        if (!_connected) return;
        _connected = false;

        SendMessage(0x08, Array.Empty<byte>());

        _client.Close();

        OnDisconnect?.Invoke(this);
    }

    public void SendMessage(string payload) => SendMessage(0x01, Encoding.UTF8.GetBytes(payload));
    public void SendMessage(int opcode, ReadOnlySpan<byte> payload) => SendMessage(this, opcode, payload, false, Array.Empty<byte>());
    private static void SendMessage(WaddleSession session, int opcode, ReadOnlySpan<byte> payload, bool masking, ReadOnlySpan<byte> mask)
    {
        if (!session._connected) return;
        if (masking && mask.Length is 0) throw new ArgumentNullException($"While {nameof(masking)} is set, {nameof(mask)} can NOT be empty.");
        var client = session._client;

        using MemoryStream byteBuffer = new();
        byte[] headerBytes = new byte[2];
        headerBytes[0] = 0b10000000; // fin
        headerBytes[0] |= (byte)opcode;

        if (masking)
        {
            headerBytes[1] |= 0b10000000; // mask
        }
        
        byte[]? payloadLen  = null;
        if (payload.Length < 126)
        {
            headerBytes[1] |= (byte)payload.Length;
        }
        else if (payload.Length <= ushort.MaxValue)
        {
            headerBytes[1] |= 0b01111110;

            payloadLen = new byte[2];
            var len = BitConverter.GetBytes(payload.Length);
            len.Reverse();
            payloadLen[0] = len[0];
            payloadLen[1] = len[1];
        }
        else
        {
            headerBytes[1] |= 0b01111111;

            payloadLen = new byte[8];
            var len = BitConverter.GetBytes(payload.Length);
            len.Reverse();
            Buffer.BlockCopy(len, 0, payloadLen, 0, 8);
        }

        byteBuffer.Write(headerBytes.AsSpan());
        if (payloadLen is not null)
        {
            byteBuffer.Write(payloadLen.AsSpan());
        }

        if (masking)
        {
            byteBuffer.Write(mask);
            payload = ApplyMask(payload, mask);
        }

        byteBuffer.Write(payload);
        
        client.GetStream().Write(byteBuffer.GetBuffer());
    }

    public static byte[] ApplyMask(byte[] data, byte[] mask) => ApplyMask(data.AsSpan(), mask.AsSpan());
    public static byte[] ApplyMask(ReadOnlySpan<byte> data, ReadOnlySpan<byte> mask)
    {
        byte[] encoded = new byte[data.Length];
        for (int i = 0; i < data.Length; i++)
        {
            encoded[i] = (byte)(data[i] ^ mask[i % 4]);
        }
        return encoded;
    }
}