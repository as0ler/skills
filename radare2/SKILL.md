---
name: radare2
description: "Expertise in reverse engineering binaries using radare2 (r2). Use this to analyze executables (ELF, PE, Mach-O), decompile code, disassemble code, find functions, extract exports/imports, extract strings, patch binaries, and debug programs."
---

# Radare2

Radare2 (r2) is a complete framework for reverse engineering and binary analysis.

When reviewing code, follow this workflow:
1. **Analyze**: Analyze the binary using `aa` to identify all the function prologues and `aae` to analyze the binary using emulation.
2. **Get binary information**: Use `i` to get binary information.
3. **Get all the imports**: Get all binary imports using `ii`.
4. **Get all the exports**: Get all binary exports using `iE`.
5. **Get the function list**: Get function list using `afl`.
6. **Get all binary strings**: Get all binary strings using `iz`.

## Quick Start

- DO NOT run `list_sessions` to get a valid session. INSTEAD use use `run_command` to run command `i` to get binary information to verify there is a valid r2 session opened using r2mcp.
- You MUST always use r2mcp to get a valid session. DO NOT open new r2 instances.


## Dissassembly procedure

To get the dissassembly of a function:
1. **Seek**: Seek to the beginning of the target function. 
2. **Analyze**: Analyze the function using `af`. 
3. **Get the disssassembly**: Use `pdf` to get the function disassembly.

## Decompilation procedure

Always use r2ghidra to decompile a function.

To get the decompilation of a function:
1. **Seek**: Seek to the beginning of the target function. 
2. **Analyze**: Analyze the function using `af`. 
3. **Get the decompiled code**: Use `pdg` to get the decompiled code using r2Ghidra. capture the output as the RAW block. Do not alter spacing, names, or formatting.

## Essential Concepts

* **Seek**: `s` moves the cursor (address) and most commands operate at the current seek.
* **Analysis**: `aa` creates functions, basic blocks, xrefs, types, etc.
* **Flags**: r2 names addresses (`f`, `fs`, `f~`...) — strings, functions, symbols show up as flags.
* **Grep/filter**: append `~` pattern to filter output quickly. Use `~+` to do it case-insensitive.
* **JSON output**: append `j` at the end of any command for JSON output (great for scripts): `ij`, `aflj`, `izj`.

## Essential Commands

### Navigation & Analysis
| Command | Description |
|---------|-------------|
| `aaa` | Analyze all (functions, refs, calls) |
| `afl` | List all functions |
| `s addr` | Seek to address |
| `s main` | Seek to main function |
| `pdf` | Print disassembly of current function |
| `pd 20` | Print 20 instructions |

### Information Gathering
| Command | Description |
|---------|-------------|
| `i` | File information |
| `ie` | Entrypoints |
| `iS` | Sections |
| `ii` | Imports |
| `iE` | Exports |
| `iz` | Strings in data sections |
| `izz` | All strings in binary |

### Cross-References
| Command | Description |
|---------|-------------|
| `axt addr` | Find xrefs to address |
| `axf addr` | Find xrefs from address |
| `afx` | Xrefs in current function |

### Visual Modes
| Command | Description |
|---------|-------------|
| `V` | Visual mode |
| `VV` | Graph mode |
| `v` | Visual panels |

### Debugging
| Command | Description |
|---------|-------------|
| `db addr` | Set breakpoint |
| `dc` | Continue execution |
| `ds` | Step instruction |
| `dso` | Step over |
| `dr` | Show registers |
| `dm` | Memory maps |

### Searching
| Command | Description |
|---------|-------------|
| `/x 9090` | Search hex bytes |
| `/ string` | Search string |
| `/R pattern` | Search ROP gadgets |
| `/c opcode` | Search assembly pattern |

### Writing & Patching
| Command | Description |
|---------|-------------|
| `wa nop` | Write assembly at current position |
| `wx 90` | Write hex bytes |
| `wao nop` | Write opcode (replaces instruction) |

## Common Workflows

### Analyze Unknown Binary
```bash
r2 -A binary
> i           # Basic info
> iS          # Check sections
> afl         # List functions
> s main      # Go to main
> pdf         # Disassemble
```

### Find Interesting Strings
```bash
r2 binary
> izz~password    # Search for "password" in strings
> izz~flag        # Search for "flag"
> axt @@ str.*    # Find xrefs to all strings
```

### Trace Function Calls
```bash
r2 -A binary
> afl~sym.        # List imported functions
> axt sym.strcmp  # Find where strcmp is called
> s [address]
> pdf
```

### Patch Binary
```bash
r2 -w binary
> s 0x401000      # Seek to instruction
> pd 1            # View current instruction
> wa jmp 0x401050 # Patch with jump
> wao nop         # Or NOP it out
```

### Debug Session
```bash
r2 -d binary
> aaa
> db main         # Break at main
> dc              # Run
> dr              # View registers
> ds              # Step
> px 32 @ rsp     # View stack
```

## Persistent Sessions (Large Binaries)

For large binaries, avoid re-analyzing on every command. Use one of these approaches:

### Option 1: r2 HTTP Server
Start r2 with HTTP server, then send commands via curl:
```bash
# Terminal 1: Start server (keeps session alive)
r2 -q -c 'aaa; =h 9090' binary

# Terminal 2+: Send commands without re-analyzing
curl -s "http://localhost:9090/cmd/afl"
curl -s "http://localhost:9090/cmd/pdf%20@%20main"
curl -s "http://localhost:9090/cmd/axt%200x401000"
```

### Option 2: r2pipe with Persistent Process
```python
import r2pipe
r2 = r2pipe.open("binary")
r2.cmd("aaa")  # Analyze once
# Now run many commands on same session
print(r2.cmd("afl"))
print(r2.cmd("pdf @ main"))
print(r2.cmd("izz~flag"))
# Session stays open until:
r2.quit()
```

### Option 3: Projects (Save/Restore Analysis)
```bash
r2 binary
> aaa              # Analyze (slow)
> Ps myproject     # Save project
> q

# Later, restore instantly:
r2 -p myproject binary
> afl              # No re-analysis needed
```

### Option 4: Named Pipe
```bash
# Create pipe and start r2
mkfifo /tmp/r2pipe
r2 -q -i /tmp/r2pipe binary &

# Send commands
echo "aaa" > /tmp/r2pipe
echo "afl" > /tmp/r2pipe
```

### Large Binary Tips
- Use `aa` instead of `aaa` for faster initial analysis
- Limit analysis depth: `e anal.depth=5`
- Analyze only specific functions: `af @ 0x401000`
- Skip analysis entirely: `r2 -n binary` then analyze on-demand
- Use `rabin2` for quick info without loading into r2

## Non-Interactive Analysis

For one-off commands, use r2 with `-q` (quiet) and `-c`:

```bash
# List all functions
r2 -q -c 'aaa; afl' binary

# Disassemble main
r2 -q -c 'aaa; s main; pdf' binary

# Get strings containing "flag"
r2 -q -c 'izz~flag' binary

# Get imports
r2 -q -c 'ii' binary

# Analyze and output JSON
r2 -q -c 'aaa; aflj' binary | jq .
```

## Companion Tools

### rabin2 - Binary Info
```bash
rabin2 -I binary    # File info
rabin2 -z binary    # Strings
rabin2 -i binary    # Imports
rabin2 -e binary    # Entrypoints
rabin2 -S binary    # Sections
```

### rasm2 - Assembler/Disassembler
```bash
rasm2 -a x86 -b 64 'nop'           # Assemble
rasm2 -a x86 -b 64 -d '90'         # Disassemble
rasm2 -a arm -b 32 'mov r0, 1'     # ARM assembly
```

### rahash2 - Hashing
```bash
rahash2 -a md5 binary
rahash2 -a sha256 binary
rahash2 -a all binary
```

### rafind2 - Pattern Search
```bash
rafind2 -x 4141 binary    # Find hex pattern
rafind2 -s "flag" binary  # Find string
```

## Architecture-Specific Notes

### x86/x64
- Use `e asm.syntax=att` for AT&T syntax
- Common calling conventions: cdecl, fastcall, System V AMD64

### ARM
- `e asm.arch=arm` and `e asm.bits=32` or `64`
- Check for Thumb mode with `e asm.bits=16`

### MIPS
- `e asm.arch=mips`
- Big/little endian: `e cfg.bigendian=true/false`

## Tips

1. Use `?` after any command for help: `pd?`, `a?`, `s?`
2. Append `j` for JSON output: `aflj`, `ij`, `izj`
3. Append `q` for quiet output: `aflq`
4. Use `@@` for iteration: `pdf @@ fcn.*`
5. Use `~` for grep: `afl~main`
6. Use `~:` for column selection: `afl~:0`
7. Save project with `Ps name` and load with `Po name`

See [references/REFERENCE.md](references/REFERENCE.md) for advanced usage.
