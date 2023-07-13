using System.Collections.ObjectModel;
using System.Net;
using System.Net.Sockets;

namespace WaddleWebSocket;

public sealed class WaddleWsServer
{
    private TcpListener _server;
    private bool _listening = false;
    private readonly List<string> _protocols = new();
    private readonly Dictionary<Guid, WaddleSession> clients = new();

    public event EventHandler<WaddleSession>? ClientConnected;
    public event EventHandler<WaddleSession>? ClientDisconnected;
    
    public WaddleWsServer(ushort port) : this(IPAddress.Any, port) { }

    public WaddleWsServer(string ip, ushort port) : this(IPAddress.Parse(ip), port) { }

    public WaddleWsServer(IPAddress ip, ushort port)
    {
        _server = new(ip, port);
    }

    public void RegisterProtocol(string protocol)
    {
        _protocols.Add(protocol);
    }

    public void RegisterProtocols(params string[] protocols)
    {
        foreach (var protocol in protocols)
        {
            _protocols.Add(protocol);
        }
    }

    public void Listen()
    {
        if (_listening)
            throw new InvalidProgramException($"You can not attempt to listen to the same `{nameof(WaddleWsServer)}` multiple times.");
        
        _listening = true;
        AwaitClientConnection(null);
    }

    public void ListenAsync()
    {
        if (_listening)
            throw new InvalidProgramException($"You can not attempt to listen to the same `{nameof(WaddleWsServer)}` multiple times.");
        
        _listening = true;
        ThreadPool.QueueUserWorkItem(AwaitClientConnection);
    }

    private void AwaitClientConnection(object? state)
    {
        _server.Start();
        while (_listening)
        {
            WaddleSession session = new(_server.AcceptTcpClient(), this);
            ClientConnected?.Invoke(this, session);
            clients.Add(session.GetGuid(), session);
            session.Start();

            session.OnDisconnect += (_) => {
                clients.Remove(session.GetGuid());
                ClientDisconnected?.Invoke(this, session);
            };
        }

        foreach (var client in clients)
        {
            client.Value.Disconnect();
        }

        clients.Clear();

        _server.Stop();
    }

    public void Close()
    {
        _listening = false;
    }

    public ReadOnlyCollection<WaddleSession> GetClients() => clients.Values.ToList().AsReadOnly();
}
