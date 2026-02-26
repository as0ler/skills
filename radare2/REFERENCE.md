# Radare2 Advanced Reference

## Configuration

### Essential Config Options
```bash
e asm.syntax=intel     # Intel syntax (default)
e asm.syntax=att       # AT&T syntax
e asm.bytes=true       # Show instruction bytes
e asm.describe=true    # Describe opcodes
e scr.color=2          # Enable 256-color mode
e io.cache=true        # Cache writes (for patching without saving)
```

### Save Configuration
```bash
# Save current config
e > ~/.radare2rc

# Or create project
Ps myproject
```

## Advanced Analysis

### Control Flow Analysis
```bash
af @ sym.func        # Analyze function at address
afr                   # Recover function recursively
afc                   # Define calling convention
aft                   # Analyze function types
```

### Type Analysis
```bash
td "struct point { int x; int y; }"   # Define type
ts                                      # List types
tl point @ 0x401000                    # Link type to address
tp point @ 0x401000                    # Cast pointer to type
```

### ESIL (Evaluable Strings Intermediate Language)
```bash
ae esi,eax,+         # Evaluate ESIL expression
aei                  # Initialize ESIL VM
aeim                 # Initialize ESIL memory
aeip                 # Initialize ESIL IP
aes                  # Step ESIL
```

## Binary Formats

### ELF Analysis
```bash
iS                    # Sections
iS~.plt               # PLT section
iS~.got               # GOT section
ir                    # Relocations
is                    # Symbols
```

### PE Analysis
```bash
iS                    # Sections
iI                    # Info (includes PE header)
ii                    # Import table
iE                    # Export table
iV                    # Version info
```

### Mach-O Analysis
```bash
iS                    # Segments/sections
il                    # Libraries
ii                    # Imports
iE                    # Exports
```

### Raw/Firmware
```bash
r2 -b 32 -a arm firmware.bin     # Specify arch
e asm.arch=arm
e asm.bits=32
e cfg.bigendian=false
o+ 0x08000000                     # Map to load address
```

## ROP Gadget Finding

```bash
/R pop rdi             # Find gadgets containing "pop rdi"
/R/j pop               # JSON output of gadgets
/Rq                    # Quiet mode (addresses only)
/R/ pop rdi; ret       # Regex search
e search.roplen=4      # Max gadget length
```

## Scripting

### r2pipe (Python)
```python
import r2pipe

r2 = r2pipe.open("binary")
r2.cmd("aaa")
functions = r2.cmdj("aflj")  # JSON output
for f in functions:
    print(f["name"], hex(f["offset"]))
r2.quit()
```

### Shell Scripting
```bash
#!/bin/bash
# Analyze multiple binaries
for bin in *.elf; do
    echo "=== $bin ==="
    r2 -q -c 'aaa; afl' "$bin"
done
```

### r2 Script File
```bash
# analysis.r2
aaa
s main
pdf
afl
q
```
Run with: `r2 -i analysis.r2 binary`

## Debugging Remote Targets

### GDB Server
```bash
r2 -d gdb://host:port binary
```

### Debug Forked Process
```bash
e dbg.follow.child=true
dc
```

### Attach to Process
```bash
r2 -d pid
# Or
r2 -d attach://pid
```

## Memory Analysis

### Heap Analysis (Linux)
```bash
dmh                   # Heap info
dmhc                  # Heap chunks
dmhf                  # Heap fastbins
dmhb                  # Heap bins
```

### Memory Dump
```bash
wtf file 0x1000 @ addr   # Write to file
pr 0x100 @ addr          # Print raw bytes
pcp 0x100 @ addr         # Print C array
```

## Comparison & Diffing

```bash
r2 -m 0x400000 binary1   # Open first
o+ binary2 0x500000      # Open second at offset
c 100 @ 0x400000         # Compare 100 bytes
cc addr1 addr2           # Compare at two offsets
```

## Emulation with ESIL

```bash
aei                      # Init ESIL
aeim                     # Init memory
aeip                     # Set IP
aer rax=5                # Set register
aes                      # Step
aer                      # Show registers
```

## Signatures & Flirt

```bash
zg                       # Generate signatures
z                        # Show signatures
z* > sigs.r2             # Export signatures
. sigs.r2                # Import signatures
```

## Output Formats

| Suffix | Format |
|--------|--------|
| `j` | JSON |
| `*` | r2 commands |
| `q` | Quiet |
| `~pattern` | Grep |
| `~:n` | Column n |
| `~[n]` | Row n |

## Performance Tips

1. Use `-A` or `aaa` only when needed; faster: `aa`
2. For large binaries: `e anal.depth=10`
3. Disable analysis: `r2 -n binary`
4. Use projects for resuming: `Ps`/`Po`

## Large Binary Strategies

### Analysis Levels
```bash
r2 -n binary     # No analysis (instant load)
r2 binary        # Minimal analysis
> aa             # Basic analysis
> aaa            # Full analysis (slow)
> aaaa           # Experimental deep analysis (very slow)
```

### Selective Analysis
```bash
# Skip full analysis, analyze only what you need
r2 -n binary
> af @ 0x401000           # Analyze single function
> afr @ 0x401000          # Analyze recursively from function
> aac                     # Analyze calls only
> aan                     # Autoname functions
```

### Analysis Tuning
```bash
e anal.depth=5            # Limit recursion depth
e anal.calls=false        # Skip call analysis
e anal.jmp.ref=false      # Skip jump references
e anal.datarefs=false     # Skip data references
e anal.strings=false      # Skip string references
```

### HTTP Server for Persistent Sessions
```bash
# Start server with analysis
r2 -q -c 'aaa; =h 9090' binary

# Query via HTTP (no reconnect overhead)
curl "http://localhost:9090/cmd/afl"
curl "http://localhost:9090/cmd/pdf%20@%20main"
curl "http://localhost:9090/cmd/pxq%2064%20@%20rsp"
```

### r2pipe Persistent Connection
```python
import r2pipe

# Open once, analyze once
r2 = r2pipe.open("binary")
r2.cmd("aaa")

# Run unlimited commands on same session
while True:
    cmd = input("r2> ")
    if cmd == "q":
        break
    print(r2.cmd(cmd))

r2.quit()
```

### Project Workflow
```bash
# First session: analyze and save
r2 binary
> aaa
> afn rename_me fcn.00401234
> CC this is important @ 0x401000
> Ps myproject
> q

# Later sessions: instant restore
r2 -p myproject binary
# All analysis, renames, comments preserved
```

### Incremental Analysis
```bash
# Start with minimal analysis
r2 binary
> aac              # Just analyze calls

# As you explore, analyze specific areas
> s 0x401000
> af               # Analyze this function
> pdf              # Now you can disassemble it
```
