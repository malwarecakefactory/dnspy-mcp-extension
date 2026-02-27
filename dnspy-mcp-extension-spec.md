# dnSpyEx MCP Extension — Build Specification

**Project**: `dnSpy.Extension.MalwareMCP`
**Purpose**: C# dnSpyEx extension embedding an MCP server for AI-assisted .NET malware reverse engineering.
**Trust model**: Written from scratch. Zero code from third-party extensions. Only official dnSpyEx contracts + official Microsoft MCP C# SDK.

---

## 1. Architecture

### 1.1 How It Works

The extension is a C# class library that dnSpyEx loads via MEF. On startup it spins up an HTTP-based MCP server on a configurable port inside the dnSpy process. Claude Code connects over the network.

```
┌───────────────────────────────────────────────────────────────────────────┐
│                         Windows Analysis VM                               │
│                                                                           │
│  ┌─────────────────────────────────────────────────────────────────────┐  │
│  │                         dnSpyEx Process                             │  │
│  │                                                                     │  │
│  │  ┌──────────────┐   MEF    ┌──────────────────────────────────┐    │  │
│  │  │  dnSpy Core   │◄───────►│  dnSpy.Extension.MalwareMCP.x   │    │  │
│  │  │              │  Import  │                                  │    │  │
│  │  │ IDecompiler  │         │  ┌──────────────┐                │    │  │
│  │  │ IDocService  │         │  │  MCP Server   │ :8765          │    │  │
│  │  │ IAnalyzer    │         │  │  (Kestrel)    │◄─── HTTP ──────┼──┐ │  │
│  │  │ dnlib        │         │  └──────────────┘                │  │ │  │
│  │  └──────────────┘         └──────────────────────────────────┘  │ │  │
│  │                                                                  │ │  │
│  └──────────────────────────────────────────────────────────────────┘ │  │
│                                                                       │  │
└───────────────────────────────────────────────────────────────────────┘  │
                                                                           │
┌──────────────────────────────────────────┐                               │
│           Ubuntu VM                       │           Streamable HTTP     │
│                                          │           MCP Protocol        │
│  ┌────────────┐                          │                               │
│  │ Claude Code │◄────────────────────────┼───────────────────────────────┘
│  └────────────┘                          │
│                                          │
└──────────────────────────────────────────┘
```

### 1.2 Why Inside dnSpyEx (Not Standalone)

Embedding inside dnSpy gives us access to things pure Python/static analysis cannot do:

- **ILSpy decompiler output** — dnSpy's built-in C# decompiler (ILSpy engine), same output you see in the GUI. Far superior to `ilspycmd` subprocess calls.
- **dnlib access** — dnSpy's underlying metadata library, giving us deep access to types, methods, IL bodies, custom attributes, everything.
- **Assembly editing** — rename types/methods/fields, edit IL, save modified assemblies. Enables AI-driven deobfuscation.
- **Tree view state** — know what the analyst is currently looking at.
- **Analyzer results** — who calls what, who is called by what (dnSpy's built-in analyzer).

### 1.3 Design Principles

- **Clean build from official sources only** — reference only `dnSpy.Contracts.DnSpy.dll` from the official dnSpyEx release, and `ModelContextProtocol` NuGet packages.
- **Read-first** — all read tools work immediately. Write/edit tools require explicit `confirm: true` parameter.
- **Malware-safe** — never execute target assembly code. All analysis is static.
- **Graceful degradation** — corrupted metadata, obfuscated names, stripped binaries — handle it all without crashing.
- **Minimal surface** — extension does one thing: expose dnSpy's capabilities over MCP.

---

## 2. Extension Skeleton

### 2.1 Project Setup

```
dnSpy.Extension.MalwareMCP/
├── dnSpy.Extension.MalwareMCP.csproj
├── ExtensionEntry.cs              # MEF entry point, starts MCP server
├── McpServerHost.cs               # Kestrel + MCP server lifecycle
├── Tools/
│   ├── AssemblyTools.cs           # Load, list, info
│   ├── TypeTools.cs               # Type/class exploration
│   ├── MethodTools.cs             # Decompile, disassemble
│   ├── StringTools.cs             # String extraction
│   ├── ResourceTools.cs           # Resource listing/extraction
│   ├── XrefTools.cs               # Cross-references (analyzer)
│   ├── PInvokeTools.cs            # P/Invoke declarations
│   ├── TriageTools.cs             # Automated malware triage
│   ├── EditTools.cs               # Rename, edit IL (write operations)
│   └── NavigationTools.cs         # Selected node, tree state
├── Services/
│   ├── DnSpyBridge.cs             # Thread-safe access to dnSpy services
│   └── DecompilerService.cs       # Decompilation wrapper
└── Utils/
    ├── TokenResolver.cs           # Metadata token → name
    ├── Entropy.cs                 # Shannon entropy
    └── Patterns.cs                # Suspicious API/string patterns
```

### 2.2 Project File

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net48</TargetFramework>
    <!-- Use net8.0-windows if targeting .NET build of dnSpyEx -->
    <AssemblyName>dnSpy.Extension.MalwareMCP.x</AssemblyName>
    <UseWpf>true</UseWpf>
    <LangVersion>latest</LangVersion>
    <Nullable>enable</Nullable>
  </PropertyGroup>

  <ItemGroup>
    <!-- Official dnSpyEx contracts — copy from your dnSpyEx installation -->
    <Reference Include="dnSpy.Contracts.DnSpy">
      <HintPath>..\lib\dnSpy.Contracts.DnSpy.dll</HintPath>
    </Reference>
    <Reference Include="dnSpy.Contracts.Logic">
      <HintPath>..\lib\dnSpy.Contracts.Logic.dll</HintPath>
    </Reference>
    <!-- dnlib is bundled with dnSpy, reference it for metadata access -->
    <Reference Include="dnlib">
      <HintPath>..\lib\dnlib.dll</HintPath>
    </Reference>
  </ItemGroup>

  <ItemGroup>
    <!-- Official Microsoft MCP C# SDK -->
    <PackageReference Include="ModelContextProtocol" Version="1.0.0-*" />
    <PackageReference Include="ModelContextProtocol.AspNetCore" Version="1.0.0-*" />
    <PackageReference Include="Microsoft.Extensions.Hosting" Version="8.*" />
    <PackageReference Include="System.ComponentModel.Composition" Version="8.0.0" />
  </ItemGroup>
</Project>
```

**Note on TFM**: dnSpyEx ships as both `net48` and `net8.0-windows`. Match whichever build you use. If using `net48`, the MCP SDK requires the ASP.NET Core runtime or a self-hosted HTTP listener. For `net8.0-windows`, Kestrel works natively.

### 2.3 Extension Entry Point

```csharp
// ExtensionEntry.cs
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
```

### 2.4 Extension Registration (Optional)

```csharp
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
```

---

## 3. MCP Server Host

### 3.1 Server Lifecycle

```csharp
// McpServerHost.cs
using ModelContextProtocol.AspNetCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection;

namespace dnSpy.Extension.MalwareMCP;

sealed class McpServerHost
{
    private IHost? _host;
    private readonly DnSpyBridge _bridge;
    private readonly int _port;

    public McpServerHost(DnSpyBridge bridge, int port = 8765)
    {
        _bridge = bridge;
        _port = port;
    }

    public async Task StartAsync()
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

        // Log to dnSpy output window
        _bridge.Log($"[MalwareMCP] MCP server listening on 0.0.0.0:{_port}");
    }

    public async Task StopAsync()
    {
        if (_host != null)
            await _host.StopAsync();
    }
}
```

### 3.2 Claude Code Configuration (Remote)

```bash
# On Ubuntu VM
claude mcp add dnspy --transport http --url http://<WINDOWS_VM_IP>:8765/mcp
```

Or `~/.config/claude/config.json`:
```json
{
  "mcpServers": {
    "dnspy": {
      "type": "url",
      "url": "http://192.168.1.50:8765/mcp"
    }
  }
}
```

### 3.3 Port Configuration

Read from environment variable or default:
```csharp
int port = int.TryParse(Environment.GetEnvironmentVariable("DNSPY_MCP_PORT"), out var p) ? p : 8765;
```

---

## 4. DnSpy Bridge (Thread Safety)

dnSpy is a WPF application. All UI-thread services must be invoked via the dispatcher.

```csharp
// Services/DnSpyBridge.cs
using System.Windows.Threading;
using dnSpy.Contracts.Documents;
using dnSpy.Contracts.Documents.TreeView;
using dnSpy.Contracts.Decompiler;
using dnSpy.Contracts.App;
using dnlib.DotNet;

namespace dnSpy.Extension.MalwareMCP;

sealed class DnSpyBridge
{
    public IDocumentTreeView TreeView { get; }
    public IDsDocumentService DocumentService { get; }
    public IDecompilerService DecompilerService { get; }
    public IAppWindow AppWindow { get; }

    private readonly Dispatcher _dispatcher;

    public DnSpyBridge(
        IDocumentTreeView treeView,
        IDsDocumentService documentService,
        IDecompilerService decompilerService,
        IAppWindow appWindow)
    {
        TreeView = treeView;
        DocumentService = documentService;
        DecompilerService = decompilerService;
        AppWindow = appWindow;
        _dispatcher = System.Windows.Application.Current.Dispatcher;
    }

    /// Run action on UI thread and return result (for dnSpy service calls)
    public T RunOnUiThread<T>(Func<T> func)
    {
        if (_dispatcher.CheckAccess())
            return func();
        return _dispatcher.Invoke(func);
    }

    /// Run action on UI thread (fire-and-forget safe)
    public void RunOnUiThread(Action action)
    {
        if (_dispatcher.CheckAccess())
            action();
        else
            _dispatcher.Invoke(action);
    }

    /// Get all loaded assemblies (ModuleDef from dnlib)
    public IReadOnlyList<ModuleDef> GetLoadedModules()
    {
        return RunOnUiThread(() =>
            DocumentService.GetDocuments()
                .Select(d => d.ModuleDef)
                .Where(m => m != null)
                .ToList()!
        );
    }

    /// Find a specific module by name
    public ModuleDef? FindModule(string name)
    {
        return GetLoadedModules()
            .FirstOrDefault(m =>
                m.Name.Equals(name, StringComparison.OrdinalIgnoreCase) ||
                m.Location.EndsWith(name, StringComparison.OrdinalIgnoreCase));
    }

    /// Decompile a type to C# using dnSpy's built-in ILSpy engine
    public string DecompileType(TypeDef typeDef)
    {
        return RunOnUiThread(() =>
        {
            var decompiler = DecompilerService.Decompiler; // current language
            var output = new StringBuilderDecompilerOutput();
            decompiler.Decompile(typeDef, output, new DecompilationContext());
            return output.ToString();
        });
    }

    /// Decompile a method to C#
    public string DecompileMethod(MethodDef methodDef)
    {
        return RunOnUiThread(() =>
        {
            var decompiler = DecompilerService.Decompiler;
            var output = new StringBuilderDecompilerOutput();
            decompiler.Decompile(methodDef, output, new DecompilationContext());
            return output.ToString();
        });
    }

    public void Log(string message)
    {
        // Write to dnSpy output or Debug output
        System.Diagnostics.Debug.WriteLine(message);
    }
}
```

---

## 5. MCP Tool Definitions

All tools use the `[McpServerTool]` attribute from the official SDK. Tools are organized by category.

### 5.1 Assembly Tools

```csharp
// Tools/AssemblyTools.cs
using ModelContextProtocol.Server;
using System.ComponentModel;

namespace dnSpy.Extension.MalwareMCP.Tools;

[McpServerToolType]
public static class AssemblyTools
{
    /// List all assemblies currently loaded in dnSpy
    [McpServerTool, Description("List all .NET assemblies loaded in dnSpy")]
    public static object GetLoadedAssemblies(DnSpyBridge bridge)
    {
        var modules = bridge.GetLoadedModules();
        return modules.Select(m => new
        {
            name = m.Name?.String,
            full_path = m.Location,
            runtime_version = m.RuntimeVersion,
            is_dotnet = true,
            num_types = m.Types?.Count ?? 0,
            has_entry_point = m.EntryPoint != null,
            mvid = m.Mvid?.ToString(),
        }).ToList();
    }

    /// Get detailed metadata for a specific assembly
    [McpServerTool, Description("Get detailed assembly metadata: CLR header, streams, PE sections, assembly references")]
    public static object GetAssemblyInfo(
        DnSpyBridge bridge,
        [Description("Assembly filename (e.g., 'stealer.exe')")] string assembly_name)
    {
        var module = bridge.FindModule(assembly_name)
            ?? throw new ArgumentException($"Assembly not found: {assembly_name}");

        return new
        {
            name = module.Name?.String,
            location = module.Location,
            runtime_version = module.RuntimeVersion,
            entry_point = module.EntryPoint?.FullName,
            mvid = module.Mvid?.ToString(),
            cor20_header_flags = module.Cor20HeaderFlags.ToString(),
            // Assembly references
            assembly_refs = module.GetAssemblyRefs().Select(r => new
            {
                name = r.Name?.String,
                version = r.Version?.ToString(),
                public_key_token = r.PublicKeyOrToken?.ToString(),
            }).ToList(),
            // Module refs (unmanaged DLLs)
            module_refs = module.GetModuleRefs().Select(r => r.Name?.String).ToList(),
            // Type counts
            num_typedefs = module.Types?.Count ?? 0,
            num_typerefs = module.GetTypeRefs().Count(),
            num_memberrefs = module.GetMemberRefs().Count(),
        };
    }
}
```

### 5.2 Type Exploration Tools

```csharp
[McpServerToolType]
public static class TypeTools
{
    /// List types (classes, structs, interfaces, enums) with filtering
    [McpServerTool, Description("List types in assembly with optional filtering by namespace, name, or kind")]
    public static object ListTypes(
        DnSpyBridge bridge,
        [Description("Assembly filename")] string assembly_name,
        [Description("Namespace substring filter")] string? filter_namespace = null,
        [Description("Type name substring filter")] string? filter_name = null,
        [Description("Kind filter: class, interface, struct, enum, delegate, all")] string filter_kind = "all",
        [Description("Include compiler-generated types")] bool include_generated = false,
        [Description("Max results (default 100)")] int limit = 100,
        [Description("Pagination offset")] int offset = 0)
    {
        var module = bridge.FindModule(assembly_name)
            ?? throw new ArgumentException($"Assembly not found: {assembly_name}");

        var types = module.GetTypes().AsEnumerable();

        if (!include_generated)
            types = types.Where(t => !t.Name.String.Contains("<") && !t.Name.String.Contains(">"));

        if (!string.IsNullOrEmpty(filter_namespace))
            types = types.Where(t => (t.Namespace?.String ?? "").Contains(filter_namespace, StringComparison.OrdinalIgnoreCase));

        if (!string.IsNullOrEmpty(filter_name))
            types = types.Where(t => t.Name.String.Contains(filter_name, StringComparison.OrdinalIgnoreCase));

        if (filter_kind != "all")
            types = filter_kind switch
            {
                "interface" => types.Where(t => t.IsInterface),
                "enum" => types.Where(t => t.IsEnum),
                "struct" => types.Where(t => t.IsValueType && !t.IsEnum),
                "delegate" => types.Where(t => t.BaseType?.FullName == "System.MulticastDelegate"),
                "class" => types.Where(t => t.IsClass && !t.IsDelegate),
                _ => types,
            };

        var list = types.ToList();
        var paged = list.Skip(offset).Take(limit);

        return new
        {
            total = list.Count,
            offset,
            limit,
            types = paged.Select(t => new
            {
                token = $"0x{t.MDToken.Raw:X8}",
                name = t.Name?.String,
                @namespace = t.Namespace?.String,
                full_name = t.FullName,
                kind = t.IsInterface ? "interface" : t.IsEnum ? "enum" :
                       t.IsValueType ? "struct" : t.IsDelegate ? "delegate" : "class",
                visibility = t.Visibility.ToString(),
                base_type = t.BaseType?.FullName,
                interface_count = t.Interfaces?.Count ?? 0,
                method_count = t.Methods?.Count ?? 0,
                field_count = t.Fields?.Count ?? 0,
                has_cctor = t.FindStaticConstructor() != null,
            }).ToList(),
        };
    }

    /// Get full details of a specific type
    [McpServerTool, Description("Get detailed type info: all fields, methods, properties, events")]
    public static object GetTypeDetails(
        DnSpyBridge bridge,
        [Description("Assembly filename")] string assembly_name,
        [Description("Full type name (e.g., 'Stealer.Config')")] string type_full_name)
    {
        var module = bridge.FindModule(assembly_name)
            ?? throw new ArgumentException($"Assembly not found: {assembly_name}");

        var type = module.GetTypes()
            .FirstOrDefault(t => t.FullName == type_full_name)
            ?? throw new ArgumentException($"Type not found: {type_full_name}");

        return new
        {
            token = $"0x{type.MDToken.Raw:X8}",
            full_name = type.FullName,
            kind = type.IsInterface ? "interface" : type.IsEnum ? "enum" :
                   type.IsValueType ? "struct" : "class",
            base_type = type.BaseType?.FullName,
            interfaces = type.Interfaces?.Select(i => i.Interface?.FullName).ToList(),
            custom_attributes = type.CustomAttributes?.Select(a => a.TypeFullName).ToList(),

            fields = type.Fields?.Select(f => new
            {
                token = $"0x{f.MDToken.Raw:X8}",
                name = f.Name?.String,
                type_name = f.FieldType?.FullName,
                is_static = f.IsStatic,
                is_literal = f.IsLiteral,
                is_init_only = f.IsInitOnly,
                visibility = f.Access.ToString(),
                constant = f.Constant?.Value?.ToString(),
            }).ToList(),

            methods = type.Methods?.Select(m => new
            {
                token = $"0x{m.MDToken.Raw:X8}",
                name = m.Name?.String,
                full_name = m.FullName,
                return_type = m.ReturnType?.FullName,
                parameters = m.Parameters?
                    .Where(p => !p.IsHiddenThisParameter)
                    .Select(p => new { name = p.Name, type_name = p.Type?.FullName })
                    .ToList(),
                is_static = m.IsStatic,
                is_virtual = m.IsVirtual,
                is_constructor = m.IsConstructor,
                visibility = m.Access.ToString(),
                il_code_size = m.Body?.Instructions?.Count ?? 0,
                has_body = m.HasBody,
            }).ToList(),

            properties = type.Properties?.Select(p => new
            {
                name = p.Name?.String,
                type_name = p.PropertySig?.RetType?.FullName,
                has_getter = p.GetMethod != null,
                has_setter = p.SetMethod != null,
            }).ToList(),

            events = type.Events?.Select(e => new
            {
                name = e.Name?.String,
                type_name = e.EventType?.FullName,
            }).ToList(),
        };
    }
}
```

### 5.3 Method Analysis Tools

```csharp
[McpServerToolType]
public static class MethodTools
{
    /// Decompile a type to C# using dnSpy's ILSpy engine
    [McpServerTool, Description("Decompile a type to C# source code using dnSpy's built-in decompiler")]
    public static object DecompileType(
        DnSpyBridge bridge,
        [Description("Assembly filename")] string assembly_name,
        [Description("Full type name")] string type_full_name)
    {
        var module = bridge.FindModule(assembly_name)
            ?? throw new ArgumentException($"Assembly not found: {assembly_name}");

        var type = module.GetTypes()
            .FirstOrDefault(t => t.FullName == type_full_name)
            ?? throw new ArgumentException($"Type not found: {type_full_name}");

        var source = bridge.DecompileType(type);
        return new { type_full_name, language = "C#", source_code = source };
    }

    /// Decompile a specific method to C#
    [McpServerTool, Description("Decompile a method to C# source code")]
    public static object DecompileMethod(
        DnSpyBridge bridge,
        [Description("Assembly filename")] string assembly_name,
        [Description("Full method name (e.g., 'Stealer.Config::Decrypt')")] string method_full_name)
    {
        var (type, method) = ResolveMethod(bridge, assembly_name, method_full_name);
        var source = bridge.DecompileMethod(method);
        return new { method_full_name = method.FullName, language = "C#", source_code = source };
    }

    /// Get CIL/IL disassembly of a method
    [McpServerTool, Description("Get raw CIL/IL instructions for a method")]
    public static object DisassembleMethod(
        DnSpyBridge bridge,
        [Description("Assembly filename")] string assembly_name,
        [Description("Full method name")] string method_full_name)
    {
        var (type, method) = ResolveMethod(bridge, assembly_name, method_full_name);

        if (!method.HasBody)
            return new { error = "Method has no body (abstract/extern/pinvoke)" };

        var body = method.Body;
        var instructions = body.Instructions.Select(i => new
        {
            offset = $"IL_{i.Offset:X4}",
            opcode = i.OpCode.Name,
            operand = FormatOperand(i),
        }).ToList();

        var locals = body.Variables?.Select(v => new
        {
            index = v.Index,
            type_name = v.Type?.FullName,
        }).ToList();

        var exception_handlers = body.ExceptionHandlers?.Select(eh => new
        {
            handler_type = eh.HandlerType.ToString(),
            try_start = $"IL_{eh.TryStart?.Offset:X4}",
            try_end = $"IL_{eh.TryEnd?.Offset:X4}",
            catch_type = eh.CatchType?.FullName,
        }).ToList();

        return new
        {
            method_full_name = method.FullName,
            code_size = body.Instructions.Count,
            max_stack = body.MaxStack,
            init_locals = body.InitLocals,
            locals,
            instructions,
            exception_handlers,
        };
    }

    // Helper: resolve "TypeName::MethodName" to (TypeDef, MethodDef)
    private static (TypeDef, MethodDef) ResolveMethod(DnSpyBridge bridge, string asmName, string fullName)
    {
        var module = bridge.FindModule(asmName)
            ?? throw new ArgumentException($"Assembly not found: {asmName}");

        // Try "Type::Method" format
        var parts = fullName.Split("::", 2);
        if (parts.Length == 2)
        {
            var type = module.GetTypes().FirstOrDefault(t => t.FullName == parts[0])
                ?? throw new ArgumentException($"Type not found: {parts[0]}");
            var method = type.Methods.FirstOrDefault(m => m.Name == parts[1])
                ?? throw new ArgumentException($"Method not found: {parts[1]} in {parts[0]}");
            return (type, method);
        }

        // Try finding by full method name across all types
        foreach (var t in module.GetTypes())
            foreach (var m in t.Methods)
                if (m.FullName == fullName || m.Name == fullName)
                    return (t, m);

        throw new ArgumentException($"Method not found: {fullName}");
    }

    private static string FormatOperand(dnlib.DotNet.Emit.Instruction instr)
    {
        if (instr.Operand == null) return "";
        return instr.Operand switch
        {
            dnlib.DotNet.IMethod m => m.FullName,
            dnlib.DotNet.IField f => f.FullName,
            dnlib.DotNet.ITypeDefOrRef t => t.FullName,
            string s => $"\"{s}\"",
            dnlib.DotNet.Emit.Instruction target => $"IL_{target.Offset:X4}",
            _ => instr.Operand.ToString() ?? "",
        };
    }
}
```

### 5.4 String Extraction

```csharp
[McpServerToolType]
public static class StringTools
{
    /// Extract strings from the #US (user strings) heap
    [McpServerTool, Description("Extract user strings from .NET #US heap with optional filtering")]
    public static object GetStrings(
        DnSpyBridge bridge,
        [Description("Assembly filename")] string assembly_name,
        [Description("Substring filter (case-insensitive)")] string? filter = null,
        [Description("Minimum string length")] int min_length = 4,
        [Description("Max results")] int limit = 500)
    {
        var module = bridge.FindModule(assembly_name)
            ?? throw new ArgumentException($"Assembly not found: {assembly_name}");

        var strings = new List<object>();
        var us = module.USStream;
        if (us != null)
        {
            uint offset = 1; // skip first null entry
            while (offset < us.StreamLength)
            {
                try
                {
                    var s = us.ReadNoRid(offset);
                    if (s != null && s.Length >= min_length)
                    {
                        if (filter == null || s.Contains(filter, StringComparison.OrdinalIgnoreCase))
                        {
                            strings.Add(new
                            {
                                source = "user_strings",
                                offset = $"0x{offset:X}",
                                value = s,
                                length = s.Length,
                            });
                        }
                    }
                    // Advance offset (rough — actual US encoding is blob-encoded)
                    offset += (uint)(s?.Length * 2 ?? 2) + 3;
                }
                catch { offset++; }

                if (strings.Count >= limit) break;
            }
        }

        // Also scan literal string fields
        foreach (var type in module.GetTypes())
        {
            foreach (var field in type.Fields)
            {
                if (field.IsLiteral && field.Constant?.Value is string val && val.Length >= min_length)
                {
                    if (filter == null || val.Contains(filter, StringComparison.OrdinalIgnoreCase))
                    {
                        strings.Add(new
                        {
                            source = "literal_field",
                            declaring_type = type.FullName,
                            field_name = field.Name?.String,
                            value = val,
                            length = val.Length,
                        });
                    }
                }
                if (strings.Count >= limit) break;
            }
        }

        return new { total = strings.Count, strings };
    }
}
```

### 5.5 P/Invoke Tools

```csharp
[McpServerToolType]
public static class PInvokeTools
{
    /// List all P/Invoke (DllImport) declarations
    [McpServerTool, Description("List all P/Invoke declarations (DllImport) — native API calls")]
    public static object GetPInvokes(
        DnSpyBridge bridge,
        [Description("Assembly filename")] string assembly_name)
    {
        var module = bridge.FindModule(assembly_name)
            ?? throw new ArgumentException($"Assembly not found: {assembly_name}");

        var pinvokes = new List<object>();
        foreach (var type in module.GetTypes())
        {
            foreach (var method in type.Methods)
            {
                if (method.ImplMap == null) continue;
                var impl = method.ImplMap;
                pinvokes.Add(new
                {
                    method_name = method.Name?.String,
                    declaring_type = type.FullName,
                    dll_name = impl.Module?.Name?.String,
                    entry_point = impl.Name?.String,
                    calling_convention = impl.Attributes.ToString(),
                });
            }
        }

        return new { count = pinvokes.Count, pinvokes };
    }
}
```

### 5.6 Malware Triage

```csharp
[McpServerToolType]
public static class TriageTools
{
    /// Automated triage: suspicious APIs, IoCs, obfuscation signals
    [McpServerTool, Description("Run automated malware triage: suspicious APIs, string IoCs, P/Invoke, obfuscation detection, high-entropy resources")]
    public static object Triage(
        DnSpyBridge bridge,
        [Description("Assembly filename")] string assembly_name)
    {
        var module = bridge.FindModule(assembly_name)
            ?? throw new ArgumentException($"Assembly not found: {assembly_name}");

        var indicators = new List<object>();

        // 1. Scan TypeRefs + MemberRefs for suspicious APIs
        foreach (var mr in module.GetMemberRefs())
        {
            var fullName = mr.FullName ?? "";
            foreach (var (category, patterns) in Patterns.SuspiciousApis)
            {
                if (patterns.Any(p => fullName.Contains(p, StringComparison.OrdinalIgnoreCase)))
                {
                    indicators.Add(new { category, detail = fullName, severity = "medium" });
                }
            }
        }

        // 2. P/Invoke analysis
        var pinvokes = new List<string>();
        foreach (var type in module.GetTypes())
            foreach (var method in type.Methods)
                if (method.ImplMap != null)
                    pinvokes.Add($"{method.ImplMap.Module?.Name}!{method.ImplMap.Name}");

        if (pinvokes.Any())
            indicators.Add(new { category = "pinvoke", detail = string.Join(", ", pinvokes), severity = "medium" });

        // 3. String IoCs (regex patterns)
        var iocs = Patterns.ExtractIoCs(module);

        // 4. Obfuscation signals
        var obfSignals = new List<string>();
        foreach (var type in module.GetTypes())
        {
            if (Patterns.IsObfuscatedName(type.Name?.String))
                obfSignals.Add($"Obfuscated type: {type.FullName}");
        }
        if (obfSignals.Any())
            indicators.Add(new { category = "obfuscation", detail = $"{obfSignals.Count} obfuscated names detected", severity = "high" });

        // 5. Resource entropy
        var resources = module.Resources?.Select(r => new
        {
            name = r.Name?.String,
            type = r.ResourceType.ToString(),
            size = (r as EmbeddedResource)?.Length ?? 0,
            entropy = (r is EmbeddedResource er) ? Entropy.Calculate(er.CreateReader().ToArray()) : 0.0,
        }).Where(r => r.entropy > 7.0).ToList();

        if (resources?.Any() == true)
            indicators.Add(new { category = "high_entropy_resource", detail = string.Join(", ", resources.Select(r => $"{r.name} ({r.entropy:F1})")), severity = "high" });

        return new
        {
            assembly = module.Name?.String,
            indicator_count = indicators.Count,
            indicators,
            string_iocs = iocs,
            pinvoke_imports = pinvokes,
            assembly_refs = module.GetAssemblyRefs().Select(r => r.Name?.String).ToList(),
        };
    }
}
```

### 5.7 Cross-Reference Tools

```csharp
[McpServerToolType]
public static class XrefTools
{
    /// Find callers/callees of a method using IL scanning
    [McpServerTool, Description("Get cross-references: who calls this method, and what does it call")]
    public static object GetMethodCalls(
        DnSpyBridge bridge,
        [Description("Assembly filename")] string assembly_name,
        [Description("Full method name (Type::Method)")] string method_full_name,
        [Description("Direction: calls, callers, both")] string direction = "both")
    {
        var module = bridge.FindModule(assembly_name)
            ?? throw new ArgumentException($"Assembly not found: {assembly_name}");

        var (targetType, targetMethod) = ResolveMethod(bridge, assembly_name, method_full_name);

        var calls = new List<object>();    // what target calls
        var callers = new List<object>();  // who calls target

        // Outgoing calls from target method
        if (direction is "calls" or "both" && targetMethod.HasBody)
        {
            foreach (var instr in targetMethod.Body.Instructions)
            {
                if (instr.Operand is IMethod calledMethod &&
                    (instr.OpCode == dnlib.DotNet.Emit.OpCodes.Call ||
                     instr.OpCode == dnlib.DotNet.Emit.OpCodes.Callvirt ||
                     instr.OpCode == dnlib.DotNet.Emit.OpCodes.Newobj))
                {
                    calls.Add(new
                    {
                        offset = $"IL_{instr.Offset:X4}",
                        opcode = instr.OpCode.Name,
                        target = calledMethod.FullName,
                    });
                }
            }
        }

        // Incoming callers — scan all methods in module
        if (direction is "callers" or "both")
        {
            foreach (var type in module.GetTypes())
            {
                foreach (var method in type.Methods)
                {
                    if (!method.HasBody) continue;
                    foreach (var instr in method.Body.Instructions)
                    {
                        if (instr.Operand is IMethod called &&
                            called.MDToken == targetMethod.MDToken)
                        {
                            callers.Add(new
                            {
                                caller = method.FullName,
                                offset = $"IL_{instr.Offset:X4}",
                                opcode = instr.OpCode.Name,
                            });
                        }
                    }
                }
            }
        }

        return new
        {
            method = targetMethod.FullName,
            outgoing_calls = direction is "calls" or "both" ? calls : null,
            incoming_callers = direction is "callers" or "both" ? callers : null,
        };
    }
}
```

### 5.8 Edit Tools (Write Operations)

These mutate the assembly state in dnSpy. All require `confirm: true`.

```csharp
[McpServerToolType]
public static class EditTools
{
    /// Rename a type (class/struct/etc)
    [McpServerTool, Description("Rename a type. Requires confirm=true. Changes are visible in dnSpy immediately.")]
    public static object RenameType(
        DnSpyBridge bridge,
        [Description("Assembly filename")] string assembly_name,
        [Description("Current full type name")] string old_name,
        [Description("New type name (just the name, not namespace)")] string new_name,
        [Description("Must be true to execute")] bool confirm = false)
    {
        if (!confirm)
            return new { status = "dry_run", message = $"Would rename '{old_name}' to '{new_name}'. Set confirm=true to execute." };

        var module = bridge.FindModule(assembly_name)
            ?? throw new ArgumentException($"Assembly not found: {assembly_name}");

        var type = module.GetTypes().FirstOrDefault(t => t.FullName == old_name)
            ?? throw new ArgumentException($"Type not found: {old_name}");

        bridge.RunOnUiThread(() => { type.Name = new dnlib.DotNet.UTF8String(new_name); });

        return new { status = "renamed", old_name, new_name = type.FullName };
    }

    /// Rename a method
    [McpServerTool, Description("Rename a method. Requires confirm=true.")]
    public static object RenameMethod(
        DnSpyBridge bridge,
        [Description("Assembly filename")] string assembly_name,
        [Description("Full method name (Type::Method)")] string old_name,
        [Description("New method name")] string new_name,
        [Description("Must be true to execute")] bool confirm = false)
    {
        if (!confirm)
            return new { status = "dry_run", message = $"Would rename method '{old_name}' to '{new_name}'. Set confirm=true to execute." };

        var (type, method) = MethodTools.ResolveMethod(bridge, assembly_name, old_name);

        bridge.RunOnUiThread(() => { method.Name = new dnlib.DotNet.UTF8String(new_name); });

        return new { status = "renamed", old_name, new_full_name = method.FullName };
    }

    /// Batch rename multiple methods at once (for deobfuscation)
    [McpServerTool, Description("Batch rename methods for deobfuscation. Requires confirm=true.")]
    public static object BatchRename(
        DnSpyBridge bridge,
        [Description("Assembly filename")] string assembly_name,
        [Description("JSON array of {old_name, new_name} pairs")] string renames_json,
        [Description("Must be true to execute")] bool confirm = false)
    {
        var renames = System.Text.Json.JsonSerializer.Deserialize<List<RenameEntry>>(renames_json)
            ?? throw new ArgumentException("Invalid JSON");

        if (!confirm)
            return new { status = "dry_run", count = renames.Count, message = "Set confirm=true to execute." };

        var results = new List<object>();
        bridge.RunOnUiThread(() =>
        {
            var module = bridge.FindModule(assembly_name)!;
            foreach (var r in renames)
            {
                try
                {
                    // Try as method first (Type::Method format)
                    if (r.old_name.Contains("::"))
                    {
                        var parts = r.old_name.Split("::", 2);
                        var type = module.GetTypes().FirstOrDefault(t => t.FullName == parts[0]);
                        var method = type?.Methods.FirstOrDefault(m => m.Name == parts[1]);
                        if (method != null)
                        {
                            method.Name = new dnlib.DotNet.UTF8String(r.new_name);
                            results.Add(new { old = r.old_name, @new = r.new_name, status = "ok" });
                            continue;
                        }
                    }
                    // Try as type
                    var t2 = module.GetTypes().FirstOrDefault(t => t.FullName == r.old_name);
                    if (t2 != null)
                    {
                        t2.Name = new dnlib.DotNet.UTF8String(r.new_name);
                        results.Add(new { old = r.old_name, @new = r.new_name, status = "ok" });
                    }
                    else
                    {
                        results.Add(new { old = r.old_name, @new = r.new_name, status = "not_found" });
                    }
                }
                catch (Exception ex)
                {
                    results.Add(new { old = r.old_name, @new = r.new_name, status = $"error: {ex.Message}" });
                }
            }
        });

        return new { renamed = results.Count(r => ((dynamic)r).status == "ok"), total = renames.Count, results };
    }

    record RenameEntry(string old_name, string new_name);
}
```

### 5.9 Navigation Tools

```csharp
[McpServerToolType]
public static class NavigationTools
{
    /// Get the currently selected node in dnSpy's tree view
    [McpServerTool, Description("Get what the analyst currently has selected in dnSpy's tree view")]
    public static object GetSelectedNode(DnSpyBridge bridge)
    {
        return bridge.RunOnUiThread(() =>
        {
            var nodes = bridge.TreeView.TreeView.SelectedItems;
            return new
            {
                selected_count = nodes.Count(),
                nodes = nodes.Select(n => new
                {
                    text = n.ToString(),
                    node_type = n.GetType().Name,
                }).ToList(),
            };
        });
    }
}
```

---

## 6. Utility Classes

### 6.1 Suspicious API Patterns

```csharp
// Utils/Patterns.cs
static class Patterns
{
    public static readonly Dictionary<string, string[]> SuspiciousApis = new()
    {
        ["network"] = new[] { "System.Net.WebClient", "HttpWebRequest", "TcpClient",
                              "System.Net.Http.HttpClient", "WebRequest", "Socket" },
        ["crypto"] = new[] { "Cryptography.Aes", "Cryptography.RSA", "RijndaelManaged",
                             "Cryptography.DES", "FromBase64String", "ToBase64String" },
        ["reflection"] = new[] { "Assembly.Load", "Assembly.LoadFrom", "Activator.CreateInstance",
                                 "Reflection.Emit", "DynamicMethod", "MethodInfo.Invoke" },
        ["process"] = new[] { "Process.Start", "Process.GetProcesses", "Process.Kill" },
        ["anti_analysis"] = new[] { "Debugger.IsAttached", "IsDebuggerPresent",
                                     "Environment.UserName", "Environment.MachineName",
                                     "ManagementObjectSearcher", "CheckRemoteDebuggerPresent" },
        ["persistence"] = new[] { "Microsoft.Win32.Registry", "RegistryKey", "RunOnStartup" },
        ["injection"] = new[] { "VirtualAlloc", "VirtualProtect", "WriteProcessMemory",
                                "CreateRemoteThread", "Marshal.Copy", "GetDelegateForFunctionPointer" },
        ["evasion"] = new[] { "Thread.Sleep", "Environment.TickCount", "DateTime.Now",
                              "Stopwatch", "AmsiScanBuffer" },
    };

    public static bool IsObfuscatedName(string? name)
    {
        if (string.IsNullOrEmpty(name)) return false;
        if (name.Length <= 2 && !name.All(char.IsAsciiLetterOrDigit)) return true;
        if (name.Any(c => c > 0x7F && !char.IsLetter(c))) return true;  // unicode tricks
        if (name.All(c => c < 0x20)) return true;  // non-printable
        return false;
    }

    // IoC extraction via regex on #US heap strings
    public static object ExtractIoCs(ModuleDef module) { /* regex for URLs, IPs, paths, registry, base64 */ }
}
```

### 6.2 Shannon Entropy

```csharp
// Utils/Entropy.cs
static class Entropy
{
    public static double Calculate(byte[] data)
    {
        if (data.Length == 0) return 0.0;
        var counts = new int[256];
        foreach (var b in data) counts[b]++;
        double entropy = 0;
        foreach (var c in counts)
        {
            if (c == 0) continue;
            double freq = (double)c / data.Length;
            entropy -= freq * Math.Log2(freq);
        }
        return entropy;
    }
}
```

---

## 7. Complete Tool Summary

| # | Tool | Category | Read/Write | Description |
|---|------|----------|-----------|-------------|
| 1 | `GetLoadedAssemblies` | Assembly | Read | List all assemblies open in dnSpy |
| 2 | `GetAssemblyInfo` | Assembly | Read | CLR metadata, assembly refs, module refs |
| 3 | `ListTypes` | Types | Read | Paginated type listing with filters |
| 4 | `GetTypeDetails` | Types | Read | Full type: fields, methods, properties, events |
| 5 | `DecompileType` | Methods | Read | C# decompilation via dnSpy's ILSpy engine |
| 6 | `DecompileMethod` | Methods | Read | C# decompilation of single method |
| 7 | `DisassembleMethod` | Methods | Read | Raw CIL/IL instructions |
| 8 | `GetStrings` | Strings | Read | #US heap + literal field extraction |
| 9 | `GetPInvokes` | P/Invoke | Read | All DllImport declarations |
| 10 | `Triage` | Malware | Read | Auto-triage: APIs, IoCs, obfuscation, entropy |
| 11 | `GetMethodCalls` | Xrefs | Read | Call graph: callers + callees |
| 12 | `RenameType` | Edit | Write | Rename type (requires confirm) |
| 13 | `RenameMethod` | Edit | Write | Rename method (requires confirm) |
| 14 | `BatchRename` | Edit | Write | Bulk rename for deobfuscation |
| 15 | `GetSelectedNode` | Nav | Read | What's selected in the tree view |

---

## 8. Build & Deploy

### 8.1 Build

```powershell
# Prerequisites: dnSpyEx source or release, .NET SDK
cd dnSpy.Extension.MalwareMCP
dotnet build -c Release
```

Output: `bin/Release/net48/dnSpy.Extension.MalwareMCP.x.dll` (plus dependencies)

### 8.2 Deploy

**Option A: Extension directory flag**
```powershell
dnSpy.exe --extension-directory "C:\path\to\bin\Release\net48"
```

**Option B: Copy to Extensions folder**
```
dnSpy-net-win64/
└── bin/
    └── Extensions/
        └── MalwareMCP/
            ├── dnSpy.Extension.MalwareMCP.x.dll
            ├── ModelContextProtocol.dll
            ├── ModelContextProtocol.Core.dll
            ├── ModelContextProtocol.AspNetCore.dll
            └── (other dependency DLLs)
```

### 8.3 Firewall

```powershell
netsh advfirewall firewall add rule name="dnSpy MCP" dir=in action=allow protocol=TCP localport=8765
```

### 8.4 Verify

```bash
# From Ubuntu VM
curl http://192.168.1.50:8765/mcp
# Should return MCP server info
```

---

## 9. Example Agent Workflow

```
User: "Analyze the .NET sample stealer.exe loaded in dnSpy"

Claude Code:
1. GetLoadedAssemblies()
   → sees stealer.exe loaded

2. Triage(assembly_name="stealer.exe")
   → flags: WebClient (network), AES (crypto), Assembly.Load (reflection),
     VirtualAlloc (injection), 2 high-entropy resources, 15 obfuscated names

3. ListTypes(assembly_name="stealer.exe", include_generated=false)
   → a, b, c, d, e, Config, Program (obfuscated names + 2 readable)

4. GetStrings(assembly_name="stealer.exe", filter="http")
   → "http://evil.com/gate.php", "http://evil.com/upload"

5. DecompileType(assembly_name="stealer.exe", type_full_name="Config")
   → C# source with C2 URLs, mutex name, install path, encryption key

6. DecompileMethod(assembly_name="stealer.exe", method_full_name="a::b")
   → C# showing AES decryption routine

7. GetPInvokes(assembly_name="stealer.exe")
   → kernel32!VirtualAlloc, kernel32!CreateThread, ntdll!RtlMoveMemory

8. GetMethodCalls(assembly_name="stealer.exe", method_full_name="Program::Main")
   → call graph from entry point

9. BatchRename(assembly_name="stealer.exe", confirm=true, renames_json=
   '[{"old_name":"a","new_name":"CryptoHelper"},
     {"old_name":"b","new_name":"NetworkComm"},
     {"old_name":"a::b","new_name":"DecryptPayload"}]')
   → deobfuscated names visible in dnSpy UI immediately
```

---

## 10. Comparison: This Extension vs. Pure Python Spec (v2)

| Capability | This Extension (C# in dnSpy) | Python Standalone (v2 spec) |
|-----------|------------------------------|---------------------------|
| C# decompilation | dnSpy's ILSpy engine (best quality) | ilspycmd subprocess (optional) |
| IL disassembly | dnlib (full fidelity) | dncil (good, occasional gaps) |
| Assembly editing | Direct dnlib mutation, visible in GUI | Not supported |
| Renaming | Immediate UI update | Not supported |
| Tree view state | Know what analyst is looking at | Not available |
| Cross-platform | Windows only (WPF app) | Cross-platform (Python) |
| Dependencies | Must build C# project against dnSpy | `pip install` only |
| Runtime requirement | .NET Framework 4.8 or .NET 8+ | Python 3.10+ |

**Recommendation**: Use this extension as primary for interactive analysis with Claude Code. Keep the Python spec (v2) as a backup for headless/batch scenarios or Linux environments.

---

## 11. Security Notes

- The MCP server has **no authentication** by default (matches IDA MCP pattern). Acceptable for isolated analysis VMs.
- Future: add `--api-key` environment variable for basic bearer token auth.
- Extension **never executes target assembly code**. All analysis is static through dnlib metadata.
- Write operations (rename, edit) require explicit `confirm: true` parameter.
- The extension runs inside the dnSpy process with full trust. Ensure your dnSpyEx binary is from the official [dnSpyEx releases](https://github.com/dnSpyEx/dnSpy/releases).
