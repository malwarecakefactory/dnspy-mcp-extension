using System.ComponentModel.Composition;
using dnSpy.Contracts.App;
using dnSpy.Contracts.Documents;
using dnSpy.Contracts.Documents.TreeView;
using dnSpy.Contracts.Decompiler;

namespace dnSpy.Extension.MalwareMCP;

[ExportAutoLoaded]
sealed class McpExtensionLoader : IAutoLoaded
{
    private readonly McpServerHost _host;

    [ImportingConstructor]
    McpExtensionLoader(
        IDocumentTreeView documentTreeView,
        IDsDocumentService documentService,
        IDecompilerService decompilerService,
        IAppWindow appWindow)
    {
        // Store references for tool implementations
        var bridge = new DnSpyBridge(documentTreeView, documentService, decompilerService, appWindow);

        // Start MCP server on background thread
        _host = new McpServerHost(bridge);
        _host.StartAsync().ConfigureAwait(false);
    }
}

[ExportExtension]
public sealed class MalwareMcpExtension : IExtension
{
    public void OnEvent(ExtensionEvent @event, object? obj) { }

    public ExtensionInfo ExtensionInfo => new()
    {
        ShortDescription = "MCP Server for AI-assisted .NET malware analysis",
    };

    public IEnumerable<string> MergedResourceDictionaries { get; } = [];
}
