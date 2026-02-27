# dnSpy.Extension.MalwareMCP

A dnSpyEx extension that embeds an MCP (Model Context Protocol) server for AI-assisted .NET malware reverse engineering. Claude Code connects over HTTP to access dnSpy's decompiler, metadata engine, and assembly editing capabilities — 33 tools covering the full RE workflow from triage to deobfuscation.

```
┌─────────────────────────────────────────────────────────────────┐
│  Windows Analysis VM                                            │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  dnSpyEx Process                                          │  │
│  │                                                           │  │
│  │  dnSpy Core ◄── MEF ──► MalwareMCP Extension              │  │
│  │  (ILSpy, dnlib)          MCP Server (Kestrel) :8765  ◄────┼──┐
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
                                                                   │
┌──────────────────────────────┐                                   │
│  Ubuntu VM                   │       Streamable HTTP MCP         │
│  Claude Code ◄───────────────┼───────────────────────────────────┘
└──────────────────────────────┘
```

## Why Inside dnSpyEx

Embedding inside dnSpy gives access to capabilities that standalone tools cannot match:

- **ILSpy decompiler** — same C# output you see in the GUI, far superior to `ilspycmd`
- **dnlib metadata** — deep access to types, methods, IL bodies, custom attributes
- **Assembly editing** — rename types/methods/fields, visible in dnSpy immediately
- **Tree view state** — know what the analyst is currently looking at
- **Cross-references** — who calls what, call graph analysis via IL scanning

---

## Quick Start

### 1. Prerequisites

**On your Windows analysis VM:**

- [dnSpyEx](https://github.com/dnSpyEx/dnSpy/releases) — download the latest release (either `net48` or `net8.0-windows` build)
- [.NET SDK](https://dotnet.microsoft.com/download) — version 8.0 or later
- NuGet package restore requires internet access (one-time during build)

**On your Ubuntu VM (or wherever Claude Code runs):**

- [Claude Code](https://claude.ai/claude-code) installed and configured

### 2. Set Up the Build Environment

```powershell
# Clone or copy this project to your Windows VM
# Then create a lib/ directory next to the project and copy DLLs from your dnSpyEx installation

mkdir lib

# Copy these 3 DLLs from your dnSpyEx installation directory:
copy "C:\Tools\dnSpyEx\dnSpy.Contracts.DnSpy.dll"   lib\
copy "C:\Tools\dnSpyEx\dnSpy.Contracts.Logic.dll"    lib\
copy "C:\Tools\dnSpyEx\dnlib.dll"                     lib\
```

Your directory should look like:
```
project-root/
├── lib/
│   ├── dnSpy.Contracts.DnSpy.dll    ← from dnSpyEx installation
│   ├── dnSpy.Contracts.Logic.dll    ← from dnSpyEx installation
│   └── dnlib.dll                     ← from dnSpyEx installation
└── dnSpy.Extension.MalwareMCP/
    ├── dnSpy.Extension.MalwareMCP.csproj
    ├── ExtensionEntry.cs
    ├── McpServerHost.cs
    └── ...
```

> **Which dnSpyEx build are you using?**
> - If `net48` (Framework): the csproj is already set to `<TargetFramework>net48</TargetFramework>` — no changes needed.
> - If `net8.0-windows` (.NET 8): edit the csproj and change `<TargetFramework>net48</TargetFramework>` to `<TargetFramework>net8.0-windows</TargetFramework>`.

### 3. Build

```powershell
cd dnSpy.Extension.MalwareMCP
dotnet restore
dotnet build -c Release
```

This produces the extension DLL and all dependencies in `bin\Release\net48\` (or `bin\Release\net8.0-windows\`).

### 4. Deploy to dnSpyEx

**Option A — Extension directory flag (recommended for development):**
```powershell
# Launch dnSpy pointing at your build output
dnSpy.exe --extension-directory "C:\path\to\dnSpy.Extension.MalwareMCP\bin\Release\net48"
```

**Option B — Copy to dnSpy's Extensions folder (permanent installation):**
```powershell
# Create an extension subfolder inside dnSpy
mkdir "C:\Tools\dnSpyEx\bin\Extensions\MalwareMCP"

# Copy all DLLs from build output (extension + MCP SDK + dependencies)
copy bin\Release\net48\*.dll "C:\Tools\dnSpyEx\bin\Extensions\MalwareMCP\"
```

Then launch dnSpy normally — it auto-loads extensions from the `Extensions/` folder.

The resulting layout:
```
dnSpy-net-win64/
└── bin/
    ├── dnSpy.exe
    └── Extensions/
        └── MalwareMCP/
            ├── dnSpy.Extension.MalwareMCP.x.dll   ← the extension
            ├── ModelContextProtocol.dll
            ├── ModelContextProtocol.Core.dll
            ├── ModelContextProtocol.AspNetCore.dll
            ├── Microsoft.Extensions.Hosting.dll
            └── (other dependency DLLs)
```

### 5. Verify the MCP Server Is Running

When dnSpy starts, the extension auto-starts an HTTP MCP server. You should see a debug message:
```
[MalwareMCP] MCP server listening on 0.0.0.0:8765
```

Test from another machine (or locally):
```bash
curl http://<WINDOWS_VM_IP>:8765/mcp
# Should return an MCP server response (not a connection refused)
```

If the connection is refused from another machine, open the firewall:
```powershell
netsh advfirewall firewall add rule name="dnSpy MCP" dir=in action=allow protocol=TCP localport=8765
```

### 6. Connect Claude Code

**From your Ubuntu VM (or wherever Claude Code runs):**

```bash
# Add the MCP server
claude mcp add dnspy --transport http --url http://<WINDOWS_VM_IP>:8765/mcp

# Verify it's connected
claude mcp list
```

Or manually edit `~/.config/claude/config.json`:
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

### 7. Load a Sample and Analyze

1. In dnSpy on Windows, open a .NET malware sample: **File > Open** or drag-and-drop
2. In Claude Code on Ubuntu, start a conversation:

```
You: Analyze the malware sample loaded in dnSpy

Claude: [calls GetLoadedAssemblies → sees stealer.exe]
        [calls Triage → flags suspicious APIs, IoCs]
        [calls DetectObfuscator → identifies ConfuserEx]
        ...provides full analysis report...
```

---

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `DNSPY_MCP_PORT` | `8765` | HTTP port for the MCP server. Set as environment variable before launching dnSpy. |

To use a custom port:
```powershell
$env:DNSPY_MCP_PORT = "9000"
dnSpy.exe
```

Then connect Claude Code to port 9000 instead:
```bash
claude mcp add dnspy --transport http --url http://<IP>:9000/mcp
```

---

## MCP Tools (33 total)

### Assembly & Navigation

| Tool | Description |
|------|-------------|
| `GetLoadedAssemblies` | List all assemblies open in dnSpy |
| `GetAssemblyInfo` | CLR metadata, assembly refs, module refs |
| `GetSelectedNode` | What the analyst currently has selected in the tree view |

### Type & Method Exploration

| Tool | Description |
|------|-------------|
| `ListTypes` | Paginated type listing with namespace/name/kind filters |
| `GetTypeDetails` | Full type info: fields, methods, properties, events |
| `GetTypeHierarchy` | Inheritance chain, derived types, interface implementations, virtual overrides |
| `DecompileType` | C# decompilation via dnSpy's ILSpy engine |
| `DecompileMethod` | C# decompilation of a single method |
| `DisassembleMethod` | Raw CIL/IL instructions with operands |

### Search

| Tool | Description |
|------|-------------|
| `SearchCode` | Regex search across type/method/field/property names |
| `FindStringReferences` | Find all methods that reference a specific string via `ldstr` |
| `SearchILPattern` | Find methods containing specific opcode sequences or operand patterns |

### Strings & Resources

| Tool | Description |
|------|-------------|
| `GetStrings` | #US heap + literal field string extraction with filtering |
| `ListResources` | Embedded resources with size and entropy |
| `ExtractResource` | Extract resource content as base64 |

### Cross-References & Flow

| Tool | Description |
|------|-------------|
| `GetMethodCalls` | One-level cross-references: callers and callees |
| `GetCallGraph` | Recursive call graph from a method (depth-limited tree) |
| `GetFieldXrefs` | Find all methods that read or write a specific field |

### Malware Triage & Metadata

| Tool | Description |
|------|-------------|
| `Triage` | Auto-triage: suspicious APIs, IoCs, obfuscation, high-entropy resources |
| `GetPInvokes` | All DllImport/P/Invoke native API declarations |
| `GetCustomAttributes` | Custom attributes with constructor and named arguments |
| `AnalyzeStaticConstructors` | All `.cctor` analysis: calls, strings, field init, suspicious ops |

### Crypto & Payload Detection

| Tool | Description |
|------|-------------|
| `DetectStringEncryption` | Heuristic detection of string decryptor methods |
| `FindByteArrays` | Find byte[] initializations (encryption keys, IVs, encrypted payloads) |
| `FindEmbeddedPEs` | Detect PE files (MZ header) in resources and byte arrays |

### Obfuscation Analysis

| Tool | Description |
|------|-------------|
| `DetectObfuscator` | Identify obfuscator by watermarks/signatures (ConfuserEx, .NET Reactor, SmartAssembly, Dotfuscator, Babel, Eazfuscator, Crypto Obfuscator, Agile.NET, ILProtector, Obfuscar) |
| `AnalyzeControlFlow` | Detect control flow obfuscation: switch dispatchers, opaque predicates, flattened CF |
| `FindProxyMethods` | Detect proxy/delegate-based call obfuscation |

### Dynamic Code & Reflection

| Tool | Description |
|------|-------------|
| `FindReflectionUsage` | Assembly.Load, Type.GetType, MethodInfo.Invoke, Activator.CreateInstance |
| `FindDelegateCreation` | Delegate construction (ldftn/newobj) and invocation patterns |
| `FindDynamicCode` | DynamicMethod, ILGenerator, Reflection.Emit, CodeDom, Marshal patterns |

### Write Tools (require `confirm=true`)

| Tool | Description |
|------|-------------|
| `RenameType` | Rename a type (visible in dnSpy immediately) |
| `RenameMethod` | Rename a method |
| `RenameField` | Rename a field |
| `BatchRename` | Bulk rename types/methods/fields for deobfuscation |
| `SaveAssembly` | Save modified assembly to disk after deobfuscation |

---

## Usage Examples

### Basic Analysis

```
You: What assemblies are loaded in dnSpy?
Claude: [calls GetLoadedAssemblies]
→ stealer.exe (47 types, has entry point, .NET 4.8)
  mscorlib.dll, System.dll, ...

You: Run triage on stealer.exe
Claude: [calls Triage(assembly_name="stealer.exe")]
→ 12 indicators found:
  - network: System.Net.WebClient::DownloadString
  - crypto: System.Security.Cryptography.Aes::Create
  - injection: kernel32!VirtualAlloc, kernel32!CreateRemoteThread
  - 3 high-entropy resources (7.9 bits/byte)
  - 15 obfuscated type names
  IoCs: http://evil.com/gate.php, 185.123.45.67
```

### Investigating Obfuscation

```
You: What obfuscator was used?
Claude: [calls DetectObfuscator(assembly_name="stealer.exe")]
→ Detected: ConfuserEx (high confidence)
  Evidence: ConfuserEx attribute watermark
  Generic signals: 38/47 types have obfuscated names, module initializer present

You: Find the string decryption method
Claude: [calls DetectStringEncryption(assembly_name="stealer.exe")]
→ High confidence candidate: \u0002::\u0003(System.Int32)
  Score: 8 — returns string, is static, has XOR, array access, byte conversion
  Called from 127 sites

You: Decompile that decryptor
Claude: [calls DecompileMethod(assembly_name="stealer.exe", method_full_name="\u0002::\u0003")]
→ public static string \u0003(int index) {
      byte[] array = \u0002.\u0005;  // encrypted string table
      int num = array[index] ^ 0x4F;
      ...
  }
```

### Tracing Data Flow

```
You: Where is the C2 URL used?
Claude: [calls FindStringReferences(assembly_name="stealer.exe", search_string="gate.php")]
→ Found in 2 methods:
  - NetworkComm::SendData at IL_001A
  - Config::.cctor at IL_0042

You: Show me the call graph from Main
Claude: [calls GetCallGraph(assembly_name="stealer.exe", method_full_name="Program::Main", max_depth=3)]
→ Program::Main
   ├─ Config::Initialize
   │  ├─ Config::DecryptStrings
   │  └─ Config::LoadC2Urls
   ├─ Stealer::CollectCredentials
   │  ├─ ChromeStealer::Grab
   │  └─ FirefoxStealer::Grab
   └─ NetworkComm::Exfiltrate
      └─ NetworkComm::SendData

You: Who reads the encryption key field?
Claude: [calls GetFieldXrefs(assembly_name="stealer.exe", type_full_name="Config", field_name="encKey")]
→ 3 reads: CryptoHelper::Decrypt, CryptoHelper::Encrypt, Config::Verify
  1 write: Config::.cctor (static constructor)
```

### Finding Packed Payloads

```
You: Are there any embedded executables?
Claude: [calls FindEmbeddedPEs(assembly_name="stealer.exe")]
→ 1 embedded PE found:
  - resource:payload (62,480 bytes, entropy 7.94)
  - PE info: x86, .NET assembly, 3 sections

You: Find the byte arrays — any encryption keys?
Claude: [calls FindByteArrays(assembly_name="stealer.exe", min_size=16)]
→ 4 arrays found:
  - CryptoHelper::.cctor: 32 bytes, entropy 4.2 → AES-256 key
    Preview: 2B 7E 15 16 28 AE D2 A6 AB F7 15 88 09 CF 4F 3C ...
  - CryptoHelper::.cctor: 16 bytes, entropy 3.8 → IV
  - Loader::Unpack: 62,480 bytes, entropy 7.9 → encrypted payload
```

### Deobfuscation

```
You: Rename the obfuscated types based on your analysis
Claude: [calls BatchRename(assembly_name="stealer.exe", confirm=true, renames_json=
  '[{"old_name":"\u0002",       "new_name":"StringDecryptor"},
    {"old_name":"\u0003",       "new_name":"CryptoHelper"},
    {"old_name":"\u0005",       "new_name":"NetworkComm"},
    {"old_name":"\u0002::\u0003","new_name":"DecryptString"},
    {"old_name":"\u0003::\u0002","new_name":"AesDecrypt"}]')]
→ 5/5 renamed successfully. Names visible in dnSpy GUI immediately.

You: Save the deobfuscated assembly
Claude: [calls SaveAssembly(assembly_name="stealer.exe", confirm=true)]
→ Saved to C:\Samples\stealer_modified.exe (124,832 bytes)
```

### Searching IL Patterns

```
You: Find all methods that use XOR operations
Claude: [calls SearchILPattern(assembly_name="stealer.exe", opcodes="xor")]
→ 8 methods contain XOR:
  - StringDecryptor::DecryptString (3 occurrences)
  - CryptoHelper::AesDecrypt (1)
  - Loader::Unpack (2)
  ...

You: Find methods that call VirtualAlloc
Claude: [calls SearchILPattern(assembly_name="stealer.exe", opcodes="call", operand_pattern="VirtualAlloc")]
→ 2 methods:
  - Injector::AllocateMemory at IL_0012
  - Injector::InjectShellcode at IL_003A
```

---

## Full Analysis Workflow

A typical malware analysis session follows this pattern:

```
Phase 1: TRIAGE
  GetLoadedAssemblies → Triage → DetectObfuscator → GetPInvokes

Phase 2: DISCOVERY
  ListTypes → SearchCode → GetStrings → FindStringReferences
  AnalyzeStaticConstructors → GetCustomAttributes

Phase 3: DEEP ANALYSIS
  DecompileType → DecompileMethod → DisassembleMethod
  GetCallGraph → GetMethodCalls → GetFieldXrefs → GetTypeHierarchy

Phase 4: CRYPTO & PAYLOADS
  DetectStringEncryption → FindByteArrays → FindEmbeddedPEs
  ExtractResource → FindReflectionUsage → FindDynamicCode

Phase 5: OBFUSCATION
  AnalyzeControlFlow → FindProxyMethods → FindDelegateCreation

Phase 6: DEOBFUSCATION & EXPORT
  RenameType → RenameMethod → RenameField → BatchRename
  SaveAssembly
```

---

## Project Structure

```
dnSpy.Extension.MalwareMCP/
├── dnSpy.Extension.MalwareMCP.csproj
├── ExtensionEntry.cs                  # MEF entry point, starts MCP server
├── McpServerHost.cs                   # Kestrel + MCP server lifecycle
├── Tools/
│   ├── AssemblyTools.cs               # GetLoadedAssemblies, GetAssemblyInfo
│   ├── TypeTools.cs                   # ListTypes, GetTypeDetails
│   ├── MethodTools.cs                 # DecompileType, DecompileMethod, DisassembleMethod
│   ├── SearchTools.cs                 # SearchCode, FindStringReferences, SearchILPattern
│   ├── StringTools.cs                 # GetStrings
│   ├── ResourceTools.cs              # ListResources, ExtractResource
│   ├── FlowTools.cs                   # GetCallGraph, GetFieldXrefs, GetTypeHierarchy
│   ├── XrefTools.cs                   # GetMethodCalls
│   ├── TriageTools.cs                 # Triage
│   ├── PInvokeTools.cs                # GetPInvokes
│   ├── CryptoTools.cs                 # DetectStringEncryption, FindByteArrays, FindEmbeddedPEs
│   ├── ObfuscationTools.cs            # DetectObfuscator, AnalyzeControlFlow, FindProxyMethods
│   ├── DynamicTools.cs                # FindReflectionUsage, FindDelegateCreation, FindDynamicCode
│   ├── AttributeTools.cs             # GetCustomAttributes, AnalyzeStaticConstructors
│   ├── EditTools.cs                   # RenameType, RenameMethod, RenameField, BatchRename
│   ├── SaveTools.cs                   # SaveAssembly
│   └── NavigationTools.cs             # GetSelectedNode
├── Services/
│   ├── DnSpyBridge.cs                 # Thread-safe WPF dispatcher bridge to dnSpy services
│   └── DecompilerService.cs           # Decompilation helper wrapper
└── Utils/
    ├── Patterns.cs                    # Suspicious API dictionaries, IoC regex extraction
    ├── Entropy.cs                     # Shannon entropy calculator
    └── TokenResolver.cs               # Metadata token → name resolver
```

---

## Troubleshooting

**Extension doesn't load**
- Ensure the DLL is named `dnSpy.Extension.MalwareMCP.x.dll` (the `.x` suffix is required by dnSpy's extension discovery)
- Ensure all dependency DLLs are in the same folder as the extension DLL
- Check dnSpy's Output window (View > Output) for error messages
- Verify the `lib/` DLLs match your dnSpyEx version

**MCP server doesn't start**
- Check for port conflicts: `netstat -an | findstr 8765`
- Set a different port: `$env:DNSPY_MCP_PORT = "9000"` before launching dnSpy
- Check dnSpy's debug output for `[MalwareMCP]` messages

**Claude Code can't connect**
- Verify the URL is correct: `curl http://<IP>:8765/mcp`
- Check Windows Firewall allows inbound TCP 8765
- If using VMs, ensure they're on the same network / the port is forwarded
- Try `claude mcp list` to see if the server is registered

**Build errors**
- "Reference not found": ensure `lib/` directory contains all 3 DLLs from dnSpyEx
- NuGet restore fails: run `dotnet restore` explicitly, check internet access
- TFM mismatch: ensure `<TargetFramework>` in csproj matches your dnSpyEx build (net48 vs net8.0-windows)

**"Assembly not found" errors from tools**
- The `assembly_name` parameter matches against the module name and file path
- Use the exact filename: `stealer.exe`, not `C:\Samples\stealer.exe`
- Call `GetLoadedAssemblies` first to see the exact names

---

## Security

- **No authentication** by default — intended for isolated analysis VMs only. Do not expose to untrusted networks.
- **Never executes target assembly code** — all analysis is static via dnlib metadata.
- **Write operations** (`RenameType`, `RenameMethod`, `RenameField`, `BatchRename`, `SaveAssembly`) require explicit `confirm: true` parameter. Without it, they return a dry-run preview.
- Ensure your dnSpyEx binary is from the [official releases](https://github.com/dnSpyEx/dnSpy/releases).
