using ModelContextProtocol.AspNetCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Hosting;

namespace dnSpy.Extension.MalwareMCP;

sealed class McpServerHost
{
    private IHost? _host;
    private readonly DnSpyBridge _bridge;
    private readonly int _port;

    public McpServerHost(DnSpyBridge bridge, int port = 0)
    {
        _bridge = bridge;
        _port = port > 0 ? port
            : int.TryParse(Environment.GetEnvironmentVariable("DNSPY_MCP_PORT"), out var p) ? p
            : 8765;
    }

    public async Task StartAsync()
    {
        try
        {
            var builder = Host.CreateApplicationBuilder();

            builder.Services.AddSingleton(_bridge);

            builder.WebHost.UseKestrelCore()
                .ConfigureKestrel(k => k.ListenAnyIP(_port));

            builder.Services
                .AddMcpServer()
                .WithStreamableHttpTransport()
                .WithToolsFromAssembly(typeof(McpServerHost).Assembly);

            _host = builder.Build();
            await _host.StartAsync();

            _bridge.Log($"[MalwareMCP] MCP server listening on 0.0.0.0:{_port}");
        }
        catch (Exception ex)
        {
            _bridge.Log($"[MalwareMCP] Failed to start MCP server: {ex.Message}");
        }
    }

    public async Task StopAsync()
    {
        if (_host != null)
            await _host.StopAsync();
    }
}
