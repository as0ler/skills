---
name: vmprotect
description: "VMProtect deobfuscation and unpacking for native binaries (ELF, PE, Mach-O). Use this when encountering VMProtect-packed binaries, virtualized code, mutated functions, obfuscated strings, or anti-tamper protections. Triggers: any mention of 'VMProtect', 'VMP', '.vmp0/.vmp1 sections', virtualized code with handler dispatch loops, excessive push/pop/jmp chains, or binaries with characteristic VMP section names. Covers detection heuristics, string deobfuscation, IAT reconstruction, devirtualization strategies, and anti-debug bypass."
---

# VMProtect Deobfuscation & Unpacking

Comprehensive reference for identifying, analyzing, and deobfuscating VMProtect-protected binaries. VMProtect (VMP) is a commercial software protection tool that uses code virtualization, mutation, packing, and anti-debug to hinder reverse engineering.

> **Versions covered:** VMProtect 2.x and 3.x (including 3.5+). Techniques differ between versions — always identify the version first.
> **Parent skill:** [../SKILL.md](../SKILL.md) — generic deobfuscation framework and reusable techniques (mprotect monitoring, API-level string capture, section dumping, deduplication).

---

## 1. Detection Heuristics

Before attempting deobfuscation, confirm the target is VMProtect-protected. These heuristics range from trivial to behavioral.

### 1.1 Section Names

VMProtect adds characteristic sections to the binary. This is the fastest indicator.

```
.vmp0    — packed/virtualized code (primary VMP section)
.vmp1    — additional VMP section (second layer or data)
.vmp2    — rare, seen in heavily protected binaries
.VMP     — older VMProtect 2.x naming
UPX0/UPX1 — VMProtect sometimes mimics UPX section names as a decoy
```

**Detection with radare2:**
```bash
iS~vmp          # list sections matching "vmp"
iS~.vmp         # stricter match
iS~VMP
```

**Detection with rabin2:**
```bash
rabin2 -S binary | grep -i vmp
```

### 1.2 Entry Point Analysis

VMProtect-packed binaries have a distinctive entry point pattern:

- **VMP 3.x:** Entry point jumps into a `.vmp0` section, not `.text`
- **VMP 2.x:** Entry point contains a `push` of all registers followed by a jump to the VM dispatcher
- The original entry point (OEP) is virtualized or redirected

```bash
# Check if EP lands in a VMP section
ie              # show entry point
iS              # compare EP address against section ranges
s entry0; pd 20 # disassemble first 20 instructions at EP
```

**Red flags at entry point:**
- `pushfd` / `pushad` or `push` of many registers as very first instructions
- Immediate jump to a high/unusual address outside `.text`
- `call` to a location that computes the next address dynamically

### 1.3 VM Handler Dispatch Pattern

The core of VMProtect is a **bytecode interpreter** (virtual machine). Look for this dispatch loop pattern:

```
; Typical VMP3 dispatch loop (x86-64)
mov     reg1, [rsi]         ; fetch VM opcode from bytecode stream
add     rsi, 4              ; advance VM instruction pointer
lea     reg2, [rip + table] ; handler table base
mov     reg3, [reg2 + reg1*8] ; lookup handler address
jmp     reg3                ; dispatch to handler

; Alternative pattern (computed jump)
movzx   eax, byte [rbx]
inc     rbx
jmp     qword [rdi + rax*8]
```

**Heuristic signals:**
- A single function with hundreds or thousands of basic blocks
- Very high cyclomatic complexity (>100) in a single function
- Repeated `jmp reg` or `jmp [reg + reg*8]` patterns (indirect jumps)
- A large jump table (>50 entries) used as a handler dispatch

```bash
# Find functions with abnormally many basic blocks
aflj | jq '.[] | select(.nbbs > 200) | {name, addr: .offset, blocks: .nbbs}'

# Search for indirect jump patterns (handler dispatch)
/c jmp rax
/c jmp qword [rdi
/c jmp qword [rbx
```

### 1.4 Import Table Anomalies

VMProtect wraps or virtualizes imports:

- **No imports or very few imports** visible in the IAT — VMProtect resolves them at runtime via `GetProcAddress`/`dlsym`
- Import thunks jump through VMP stubs instead of directly to the API
- `GetProcAddress`, `LoadLibraryA/W` are among the few visible imports (used by VMP's own resolver)

```bash
ii           # list imports — suspiciously few?
ii~GetProc   # VMP always needs these
ii~LoadLib
```

### 1.5 dlsym Mass-Resolution Pattern (Android/Linux)

On Android, VMP-protected `.so` files resolve **all** their imports dynamically via `dlsym` at startup. This produces a distinctive burst of 100-300+ `dlsym` calls immediately after the library loads — covering everything from `malloc` and `memcpy` to OpenGL functions and JNI helpers.

This pattern is a strong behavioral indicator: normal libraries use the ELF dynamic linker for most imports and only `dlsym` a handful of optional symbols.

Hook `dlsym` and count calls originating from the target module — if you see 100+ distinct symbol resolutions at load time, VMP is almost certainly present:

```javascript
var dlsymCount = 0;
Interceptor.attach(Module.getGlobalExportByName('dlsym'), {
    onEnter(args) {
        if (!isFromTarget(this.returnAddress)) return;
        var name = args[1].readCString();
        if (name) {
            dlsymCount++;
            console.log('[dlsym #' + dlsymCount + '] ' + name);
        }
    }
});
```

### 1.6 String Obfuscation Indicators

VMProtect encrypts strings referenced by virtualized code:

- `iz` (data section strings) returns very few meaningful strings
- `izz` (all strings) may reveal encrypted blobs or base64-like data
- API name strings are absent (resolved dynamically)
- String references (`axt`) point into VMP sections, not `.text`

```bash
iz                     # meaningful strings are missing
izz~flag               # try to find something
izz | wc -l            # compare count — VMP binaries have far fewer readable strings
```

### 1.7 Code Mutation Indicators

Mutated (but not virtualized) functions show:

- **Junk instructions:** meaningless arithmetic that cancels out (e.g., `add rax, 5; sub rax, 5`)
- **Opaque predicates:** conditional jumps where the condition is always true/false
- **Register shuffling:** excessive `mov reg, reg` chains
- **Constant unfolding:** simple constants split into multi-step computations
- **Dead stores:** writes to registers/memory immediately overwritten

```bash
# Look for mutation patterns — high instruction count, low semantic density
pdf @ fcn.addr | grep -c "nop\|xchg\|stc\|clc\|cmc"
```

### 1.8 Anti-Debug and Anti-Tamper Signatures

VMProtect includes runtime checks:

- Calls to `IsDebuggerPresent`, `NtQueryInformationProcess`, `CheckRemoteDebuggerPresent`
- `RDTSC` timing checks (measure time between two points)
- `INT 2D` / `INT 3` exceptions used as anti-debug
- CRC/hash checks over code sections (anti-tamper)
- TLS callbacks that run before `main()`
- On Android/Linux: reads `/proc/self/status` and checks `TracerPid` field

```bash
ii~Debugger
ii~NtQuery
/c rdtsc
/c int 0x2d
/c int 3
iS~.tls          # TLS section present?
```

### 1.9 mprotect Storm at Startup (Android/Linux)

VMP-protected `.so` files call `mprotect` repeatedly during initialization to:
1. Make packed sections writable (`r-x` → `rwx`)
2. Unpack/decrypt code into those sections
3. Re-protect them (`rwx` → `r-x`)

Hook `mprotect` and filter for calls targeting the library's address range. Seeing 5-20+ `mprotect` calls on a single library at load time is a strong VMP indicator (normal libraries make 0-1 calls). See the [parent skill](../SKILL.md#33-mprotect-monitoring) for the hook template.

### 1.10 uncompress / zlib Usage During Unpacking

VMProtect uses zlib's `uncompress` function to decompress packed code sections at runtime. If you see `uncompress` calls with output landing inside the target library's memory range right after load, this confirms VMP packing.

```javascript
Interceptor.attach(Module.getGlobalExportByName('uncompress'), {
    onEnter(args) {
        this.dest   = args[0];
        this.srcLen = args[3].toUInt32();
    },
    onLeave(retval) {
        if (retval.toInt32() !== 0) return;
        if (this.dest.compare(targetBase) >= 0 && this.dest.compare(targetEnd) < 0) {
            console.log('[!] uncompress wrote into target module @ ' + this.dest);
        }
    }
});
```

### 1.11 Composite Detection Script (radare2)

Run this sequence to get a confidence score:

```bash
# 1. Section check
iS~vmp

# 2. Entry point check
s entry0; pd 5

# 3. Import poverty check
ii | wc -l      # < 10 imports on a complex binary = suspicious

# 4. String poverty check
iz | wc -l      # very few strings for a large binary

# 5. Indirect jump frequency
/c jmp rax; /c jmp rbx; /c jmp rcx   # many hits = VM dispatch

# 6. Anti-debug imports
ii~Debugger; ii~NtQuery; ii~CheckRemote

# 7. Large functions
aflj | jq '[.[] | select(.nbbs > 100)] | length'
```

**Scoring:**
- `.vmp` sections found → **confirmed VMProtect**
- 3+ other heuristics match → **highly likely VMProtect**
- 1–2 heuristics match → **possibly VMProtect or other virtualizer** (check for Themida/Code Virtualizer patterns)

**Behavioral confirmation (requires running the binary):**
- dlsym mass-resolution (100+ calls at startup) → **confirmed VMP import obfuscation**
- mprotect storm (5+ calls on the library at load) → **confirmed VMP packing**
- uncompress writing into the library → **confirmed VMP compression**
- `/proc/self/status` TracerPid check → **confirmed VMP anti-debug**

---

## 2. VMProtect Architecture

Understanding the VM is essential for deobfuscation.

### 2.1 VM Components

```
+------------------+     +----------------+     +------------------+
| Bytecode Stream  | --> | VM Dispatcher  | --> | Handler Table    |
| (encrypted ops)  |     | (fetch-decode) |     | (native stubs)  |
+------------------+     +----------------+     +------------------+
                                |
                          +-----+-----+
                          |           |
                    +---------+ +---------+
                    | VM Stack| | VM Regs  |
                    | (RSP-   | | (mapped  |
                    |  based) | |  to mem) |
                    +---------+ +---------+
```

- **Bytecode stream:** Encrypted VM opcodes stored in `.vmp0`/`.vmp1`
- **Dispatcher:** Fetch-decode-execute loop; fetches next opcode, decrypts, jumps to handler
- **Handler table:** Array of native code snippets, each implementing one VM opcode
- **VM stack:** Separate stack area, often pointed to by a repurposed general register
- **VM context/registers:** Virtual registers stored in memory, not mapped 1:1 to CPU registers

### 2.2 VMP Opcode Classes

VMProtect VMs implement these broad opcode categories:

| Category | Examples | Purpose |
|----------|----------|---------|
| Stack ops | vPush, vPop | Move data on/off VM stack |
| Arithmetic | vAdd, vSub, vMul, vDiv, vNor | ALU operations (NOR is used to build AND/OR/XOR/NOT) |
| Memory | vLoad, vStore | Read/write native memory |
| Control flow | vJmp, vCall, vRet | Branch, call native, return |
| Flags | vPushFlags, vPopFlags | Manage EFLAGS/RFLAGS |
| Context | vReadReg, vWriteReg | Access native CPU registers |
| Crypto | vDecrypt, vRotate | Decrypt next bytecode chunk |

### 2.3 Version Differences

| Feature | VMP 2.x | VMP 3.x |
|---------|---------|---------|
| Section names | `.VMP0`, `.VMP1` | `.vmp0`, `.vmp1` |
| Handler encoding | Direct handler addresses | Delta-encoded / encrypted handler offsets |
| Bytecode encryption | Simple XOR/ADD rolling key | Multi-layer, key-dependent decryption per opcode |
| VM entry | `pushad; pushfd; call vm_entry` | More varied, often via `call [rip+disp]` |
| Handler count | ~30-50 | ~40-80 (more granular) |
| Mutation | Light | Heavy mutation + MBA (mixed boolean arithmetic) |
| Anti-debug | Basic (`IsDebuggerPresent`) | Layered (timing, exception, TLS, CRC, TracerPid) |

---

## 3. String Deobfuscation

VMProtect encrypts strings referenced by protected functions. The most effective approach is to **hook the consumers** of decrypted strings rather than reversing the decryption algorithm.

### 3.1 Strategy: Hook API Consumers (Proven Approach)

Decrypted strings must eventually flow through standard APIs — JNI calls, libc string functions, `dlsym`, logging. By hooking these APIs and filtering for calls originating from the target module, you capture all decrypted strings without needing to understand the decryption algorithm.

This approach was proven effective on VMProtect-protected Android `.so` files, recovering 2000+ unique strings including class names, method signatures, dynamically resolved API names, and file paths.

### 3.2 JNI Vtable Hooking (Android)

The most valuable source of strings on Android. Hook JNI functions by their vtable index to capture all strings crossing the Java-native boundary:

```javascript
Java.perform(function () {
    var env = Java.vm.getEnv();
    var vtable = env.handle.readPointer();

    // NewStringUTF — native code creating Java strings
    Interceptor.attach(vtable.add(167 * Process.pointerSize).readPointer(), {
        onEnter: function (args) {
            var s = args[1].readUtf8String();
            if (s) logString('JNI:NewStringUTF', s);
        }
    });

    // GetStringUTFChars — native code reading Java strings
    Interceptor.attach(vtable.add(169 * Process.pointerSize).readPointer(), {
        onEnter: function (args) { this.jstr = args[1]; },
        onLeave: function (retval) {
            var s = retval.readUtf8String();
            if (s) logString('JNI:GetStringUTFChars', s);
        }
    });

    // FindClass — class names being loaded
    Interceptor.attach(vtable.add(6 * Process.pointerSize).readPointer(), {
        onEnter: function (args) {
            var s = args[1].readCString();
            if (s) logString('JNI:FindClass', s);
        }
    });

    // GetMethodID — method lookups (name + signature)
    Interceptor.attach(vtable.add(33 * Process.pointerSize).readPointer(), {
        onEnter: function (args) {
            var name = args[2].readCString();
            var sig = args[3].readCString();
            if (name) logString('JNI:GetMethodID', name, sig);
        }
    });

    // GetFieldID — field lookups
    Interceptor.attach(vtable.add(36 * Process.pointerSize).readPointer(), {
        onEnter: function (args) {
            var name = args[2].readCString();
            var sig = args[3].readCString();
            if (name) logString('JNI:GetFieldID', name, sig);
        }
    });

    // GetStaticMethodID
    Interceptor.attach(vtable.add(113 * Process.pointerSize).readPointer(), {
        onEnter: function (args) {
            var name = args[2].readCString();
            var sig = args[3].readCString();
            if (name) logString('JNI:GetStaticMethodID', name, sig);
        }
    });

    // GetStaticFieldID
    Interceptor.attach(vtable.add(114 * Process.pointerSize).readPointer(), {
        onEnter: function (args) {
            var name = args[2].readCString();
            var sig = args[3].readCString();
            if (name) logString('JNI:GetStaticFieldID', name, sig);
        }
    });

    // RegisterNatives — JNI method registration (name + sig + native function pointer)
    Interceptor.attach(vtable.add(215 * Process.pointerSize).readPointer(), {
        onEnter: function (args) {
            var count = args[3].toInt32();
            for (var i = 0; i < count; i++) {
                var entry = args[2].add(i * 3 * Process.pointerSize);
                var name = entry.readPointer().readCString();
                var sig = entry.add(Process.pointerSize).readPointer().readCString();
                var fn = entry.add(Process.pointerSize * 2).readPointer();
                if (name) logString('JNI:RegisterNatives', name, sig + ' -> ' + fn);
            }
        }
    });
});
```

**JNI vtable index reference:**

| Index | Function | Captures |
|-------|----------|----------|
| 6 | FindClass | Class names (e.g., `com/example/GameManager`) |
| 33 | GetMethodID | Instance method names + signatures |
| 36 | GetFieldID | Instance field names + signatures |
| 113 | GetStaticMethodID | Static method names + signatures |
| 114 | GetStaticFieldID | Static field names + signatures |
| 167 | NewStringUTF | Strings created by native code for Java |
| 169 | GetStringUTFChars | Java strings read by native code |
| 215 | RegisterNatives | JNI method bindings (name, sig, native addr) |

### 3.3 libc String Function Hooking

Hook libc string functions, filtering to calls originating from the target module:

```javascript
var hooks = [
    { name: 'strcmp',  read: [0, 1] },
    { name: 'strncmp', read: [0, 1] },
    { name: 'strstr', read: [0, 1] },
    { name: 'strlen', read: [0] }
];

hooks.forEach(function (h) {
    var addr = Module.findGlobalExportByName(h.name);
    if (!addr) return;

    Interceptor.attach(addr, {
        onEnter: function (args) {
            if (!isFromTarget(this.returnAddress)) return;
            this.log = true;
            this.strs = [];
            for (var i = 0; i < h.read.length; i++) {
                var s = args[h.read[i]].readCString();
                if (s) this.strs.push(s);
            }
        },
        onLeave: function () {
            if (!this.log) return;
            this.strs.forEach(function(s) { logString('libc:' + h.name, s); });
        }
    });
});

// snprintf / sprintf — read the output buffer after formatting
['snprintf', 'sprintf'].forEach(function(name) {
    var addr = Module.findGlobalExportByName(name);
    if (!addr) return;
    Interceptor.attach(addr, {
        onEnter: function (args) {
            if (!isFromTarget(this.returnAddress)) return;
            this.buf = args[0];
            this.log = true;
        },
        onLeave: function () {
            if (!this.log) return;
            var s = this.buf.readCString();
            if (s) logString('libc:' + name, s);
        }
    });
});
```

### 3.4 dlsym Hooking — Import Recovery

VMProtect resolves all imports via `dlsym` at runtime. Hooking `dlsym` captures every API name the protected code uses:

```javascript
Interceptor.attach(Module.getGlobalExportByName('dlsym'), {
    onEnter: function (args) {
        var name = args[1].readCString();
        if (name && isFromTarget(this.returnAddress)) {
            logString('dlsym', name);
        }
    }
});
```

Typical output from a VMP-protected library shows 200+ symbols resolved at startup: libc functions (`malloc`, `free`, `memcpy`, `strcmp`), POSIX (`pthread_*`, `socket`, `connect`), Android (`ANativeWindow_*`), OpenGL (`gl*`), and zlib (`inflate*`, `deflate*`).

### 3.5 Android Log Hooking

Capture log messages from the target:

```javascript
var logPrint = Module.findGlobalExportByName('__android_log_print');
if (logPrint) {
    Interceptor.attach(logPrint, {
        onEnter: function (args) {
            if (!isFromTarget(this.returnAddress)) return;
            var tag = args[1].readCString();
            var fmt = args[2].readCString();
            logString('log:print', (tag || '?') + ': ' + (fmt || '?'));
        }
    });
}
```

### 3.6 Anti-Debug String Detection

VMP's own anti-debug checks reveal themselves through string APIs. Watch for:

- `strstr` calls checking `/proc/self/status` content for `TracerPid`
- `strcmp` calls comparing library names (part of module enumeration for detection)
- `strlen` calls on system library paths (mapping enumeration)

These strings in the capture output confirm VMP anti-debug is active:

```
[libc:strstr] TracerPid
[libc:strstr] TracerPid:	0
[libc:strlen] /system/lib64/libc.so
[libc:strcmp] libc.so
```

### 3.7 Static Approach: Find the Decryption Routine

When dynamic hooking isn't possible, locate the decryption function statically:

```bash
# Look for functions that reference VMP data sections and use XOR in a loop
axt @ section..vmp0
/c xor byte
/c xor dword
```

**Common decryption stub pattern:**
```asm
lea  rdi, [encrypted_blob + offset]  ; source
lea  rsi, [rsp + local_buf]          ; destination
mov  ecx, string_length
.loop:
  mov  al, [rdi]
  xor  al, key_byte                  ; or: add/sub/rol
  mov  [rsi], al
  inc  rdi
  inc  rsi
  dec  ecx
  jnz  .loop
```

### 3.8 Batch String Extraction via Emulation

For offline decryption when you've identified the encrypted blob and key schedule:

```python
def vmp_decrypt_string(blob, offset, length, initial_key):
    key = initial_key
    result = bytearray()
    for i in range(length):
        dec = (blob[offset + i] ^ key) & 0xFF
        result.append(dec)
        key = (key + 0x37) & 0xFF  # adapt key mutation per binary
    return result.decode('utf-8', errors='replace')
```

---

## 4. Unpacking / Dumping

VMProtect packs the original code and unpacks it at runtime. To recover the original binary:

### 4.1 Android .so: Dump at JNI_OnLoad Entry

For VMP-protected Android libraries, the unpacking/decryption is complete by the time `JNI_OnLoad` is called. This is the optimal dump point.

**Module identification by JNI_OnLoad offset fingerprinting:**

```javascript
var JNI_ONLOAD_OFFSET = 0x0005a710;  // from static analysis of the protected .so

function findTargetModule() {
    for (var i = 0, mods = Process.enumerateModules(); i < mods.length; i++) {
        var jni = mods[i].findExportByName('JNI_OnLoad');
        if (jni && jni.equals(mods[i].base.add(JNI_ONLOAD_OFFSET))) return mods[i];
    }
    return null;
}
```

**Hook dlopen to detect library load, then hook JNI_OnLoad to dump:**

```javascript
var targetModule = null;
var dumped = false;

// Wait for the library to load via dlopen
var dlopen = Module.getGlobalExportByName('android_dlopen_ext')
    ?? Module.getGlobalExportByName('dlopen');

Interceptor.attach(dlopen, {
    onLeave() {
        if (targetModule) return;
        targetModule = findTargetModule();
        if (!targetModule) return;

        console.log('[+] Target loaded: ' + targetModule.name + ' @ ' + targetModule.base);

        // Hook JNI_OnLoad — decryption is done by this point
        Interceptor.attach(targetModule.base.add(JNI_ONLOAD_OFFSET), {
            onEnter() {
                if (dumped) return;
                dumped = true;
                dumpSection(targetModule, SECTION_OFFSET, SECTION_SIZE, 'JNI_OnLoad_entry');
            }
        });
    }
});
```

### 4.2 mprotect-Based Dump Timing

Track mprotect calls to understand the unpacking sequence and dump at the right moment. VMP's typical pattern:

```
mprotect(section, size, PROT_READ|PROT_WRITE|PROT_EXEC)  — make writable
<... unpacking/decryption happens ...>
mprotect(section, size, PROT_READ|PROT_EXEC)              — re-protect
```

Dump after the section transitions from `rwx` back to `r-x`:

```javascript
var mprotectLog = [];
Interceptor.attach(Module.getGlobalExportByName('mprotect'), {
    onEnter(args) {
        this.addr = args[0];
        this.len  = args[1].toUInt32();
        this.prot = args[2].toInt32();
    },
    onLeave(retval) {
        if (retval.toInt32() !== 0) return;
        if (!targetModule) return;

        var start = this.addr;
        var end   = start.add(this.len);
        var modStart = targetModule.base;
        var modEnd   = modStart.add(targetModule.size);
        if (start.compare(modEnd) >= 0 || end.compare(modStart) <= 0) return;

        var prot = '';
        if (this.prot & 1) prot += 'r';
        if (this.prot & 2) prot += 'w';
        if (this.prot & 4) prot += 'x';

        mprotectLog.push({ addr: start.toString(), len: this.len, prot: prot });
        console.log('[mprotect] ' + start + ' 0x' + this.len.toString(16) + ' ' + prot);

        // Dump when section goes from rwx -> r-x (unpack complete)
        if (prot === 'rx' && !dumped) {
            dumpSection(targetModule, 0, targetModule.size, 'mprotect_reprotect');
        }
    }
});
```

### 4.3 Section Dump with Metadata

Send the dump to the Python host with full context for offline analysis:

```javascript
function dumpSection(mod, offset, size, reason) {
    var addr = mod.base.add(offset);
    var bytes = addr.readByteArray(size);

    send({
        type: 'dump',
        module: mod.name,
        base: mod.base.toString(),
        section_addr: addr.toString(),
        size: size,
        reason: reason,
        mprotect_log: mprotectLog
    }, bytes);

    console.log('[+] Dump sent: ' + size + ' bytes @ ' + addr + ' (' + reason + ')');
}
```

### 4.4 Dump at OEP (PE binaries)

For PE binaries, find where VMP jumps to the original code:

```javascript
const text = Process.getModuleByName('target.exe')
  .enumerateSections()
  .find(s => s.name === '.text');

Stalker.follow(Process.getCurrentThreadId(), {
  events: { block: true },
  onReceive(events) {
    for (const [, addr] of Stalker.parse(events)) {
      if (addr >= text.base && addr < text.base.add(text.size)) {
        console.log('[OEP CANDIDATE]', addr);
        Stalker.unfollow();
        break;
      }
    }
  }
});
```

### 4.5 IAT Reconstruction

After dumping, rebuild the Import Address Table:

```javascript
// Scan IAT region and resolve function names
var iatBase = mod.base.add(0x1000);  // adjust per binary
var iatSize = 0x500;
for (var off = 0; off < iatSize; off += Process.pointerSize) {
  var target = iatBase.add(off).readPointer();
  if (!target.isNull()) {
    var sym = DebugSymbol.fromAddress(target);
    console.log('IAT+' + off.toString(16) + ': ' + target + ' -> ' + sym);
  }
}
```

Tools: **Scylla** (Windows), **pe-sieve / hollows_hunter** (Windows), manual resolution via Frida.

---

## 5. Devirtualization Strategies

Recovering the original x86/x64 code from VMP bytecode.

### 5.1 Trace-Based Approach

1. **Trace execution** of the VM with Stalker or a debugger
2. **Record** all native instructions executed by handlers
3. **Filter out** VM dispatcher overhead (fetch, decode, key update)
4. **Reconstruct** the semantic operations from handler behavior

```javascript
// Stalker trace of VM execution — capture handler instructions
const vmSection = { base: mod.base.add(0x1000), size: 0x50000 };

Interceptor.attach(virtualizedFunction, {
  onEnter() {
    Stalker.follow(this.threadId, {
      transform(iterator) {
        let instr = iterator.next();
        const block = [];
        while (instr !== null) {
          const addr = instr.address;
          if (addr.compare(vmSection.base) >= 0 &&
              addr.compare(vmSection.base.add(vmSection.size)) < 0) {
            block.push(instr.toString());
          }
          iterator.keep();
          instr = iterator.next();
        }
        if (block.length > 0) {
          iterator.putCallout(() => {
            send({ type: 'trace', block: block.join('\n') });
          });
        }
      }
    });
  },
  onLeave() {
    Stalker.unfollow(this.threadId);
    Stalker.flush();
    Stalker.garbageCollect();
  }
});
```

### 5.2 Symbolic Execution / Pattern Matching

For known handler patterns, map VMP opcodes back to x86:

| VM Handler Pattern | Original x86 Equivalent |
|---|---|
| `push [rsp]; push [rsp+8]; add; pop` | `add reg, reg` |
| `push imm; push [rsp+8]; xor; pop` | `xor reg, imm` |
| `push [mem]; pop to vreg` | `mov vreg, [mem]` |
| `push vreg; pop [mem]` | `mov [mem], vreg` |
| `nor(a,b)` sequence | `and`/`or`/`xor`/`not` (via De Morgan) |

### 5.3 Tools for Devirtualization

| Tool | Description |
|------|-------------|
| **NoVmp** | Open-source VMP3 devirtualizer (VTIL-based) |
| **VMPAttack** | Deobfuscation framework for VMP |
| **Triton** | Symbolic execution engine — useful for simplifying VMP handlers |
| **Miasm** | IR-based analysis — can lift and simplify virtualized code |
| **VTIL** | Virtual-machine Translation Intermediate Language |

---

## 6. Anti-Debug / Anti-Tamper Bypass

### 6.1 Windows Anti-Debug Bypass

```javascript
// IsDebuggerPresent
var isDbg = Module.findGlobalExportByName('IsDebuggerPresent');
if (isDbg) {
  Interceptor.replace(isDbg, new NativeCallback(function() { return 0; }, 'int', []));
}

// NtQueryInformationProcess
var ntQuery = Module.findGlobalExportByName('NtQueryInformationProcess');
if (ntQuery) {
  Interceptor.attach(ntQuery, {
    onEnter(args) {
      this.cls = args[1].toInt32();
      this.buf = args[2];
    },
    onLeave(retval) {
      if (this.cls === 7)    this.buf.writePointer(ptr(0));           // ProcessDebugPort
      if (this.cls === 0x1e) retval.replace(ptr(0xC0000353));         // ProcessDebugObjectHandle
      if (this.cls === 0x1f) this.buf.writeU32(1);                    // ProcessDebugFlags
    }
  });
}
```

### 6.2 Linux/Android Anti-Debug Bypass

VMP on Android checks `/proc/self/status` for `TracerPid`. The `strstr` hook from string deobfuscation doubles as anti-anti-debug detection — when you see `TracerPid` in the captured strings, you know this check is active.

To bypass without patching (which triggers CRC checks):

```javascript
// Hook fopen + fgets to fake TracerPid:0
Interceptor.attach(Module.getGlobalExportByName('fopen'), {
    onEnter(args) {
        var path = args[0].readCString();
        this.isStatus = path && path.indexOf('/proc/self/status') >= 0;
    },
    onLeave(retval) {
        if (this.isStatus) this.statusFp = retval;
    }
});

Interceptor.attach(Module.getGlobalExportByName('fgets'), {
    onLeave(retval) {
        if (retval.isNull()) return;
        var line = retval.readCString();
        if (line && line.indexOf('TracerPid:') >= 0) {
            retval.writeUtf8String('TracerPid:\t0\n');
        }
    }
});
```

### 6.3 Timing Check Bypass

```javascript
// Patch RDTSC (0F 31) to NOPs
Memory.patchCode(rdtscAddr, 2, function(code) {
  var w = new X86Writer(code, { pc: rdtscAddr });
  w.putNop();
  w.putNop();
  w.flush();
});
```

### 6.4 CRC / Integrity Check Bypass

VMProtect checksums its own code sections. Bypass CRC before patching anything:

```javascript
// Find CRC check by searching for the CRC32 polynomial constant
// /x 2083B8ED  — CRC32 polynomial 0xEDB88320 in little-endian

Interceptor.attach(crcCheckAddr, {
  onLeave(retval) {
    retval.replace(ptr(0));  // force "integrity OK"
  }
});
```

### 6.5 TLS Callback Neutralization (PE)

```bash
iS~.tls
ie~tls
```

```javascript
Memory.patchCode(tlsCallbackAddr, 4, function(code) {
  var w = new X86Writer(code, { pc: tlsCallbackAddr });
  w.putRet();
  w.flush();
});
```

---

## 7. Workflow: Full VMProtect Analysis

### Phase 1: Detection & Triage
1. Run section heuristics (`iS~vmp`)
2. Check entry point behavior
3. Count imports and strings — compare to expected
4. Identify VMP version (2.x vs 3.x)

### Phase 2: Dynamic Confirmation (optional)
1. Hook `dlsym` — if 100+ resolutions at startup, VMP confirmed
2. Hook `mprotect` — if 5+ calls on the library, packing confirmed
3. Hook `uncompress` — if it writes into the library, compression confirmed

### Phase 3: Anti-Debug Bypass
1. Bypass `IsDebuggerPresent` / `NtQueryInformationProcess` (Windows)
2. Fake `TracerPid:0` in `/proc/self/status` (Android/Linux)
3. Neutralize timing checks (RDTSC)
4. Disable CRC integrity checks (must be done before any patching)
5. Patch or skip TLS callbacks (PE)

### Phase 4: Unpacking / Section Dump
1. Identify target module by JNI_OnLoad offset fingerprint (Android) or by section layout
2. Hook JNI_OnLoad (Android) or find OEP via Stalker (PE)
3. Dump decrypted sections via `send()` with binary payload
4. Track mprotect log for understanding the unpack sequence

### Phase 5: String Recovery
1. Deploy JNI vtable hooks (Android) for class/method/field names
2. Deploy libc string hooks with return-address filtering
3. Deploy dlsym hook for import name recovery
4. Run the app and collect output via Python host script
5. Categorize results by source

### Phase 6: Function Analysis
1. Identify which functions are virtualized vs mutated vs unprotected
2. For mutated functions: use decompiler (r2ghidra) — mutation adds noise but semantics survive
3. For virtualized functions: trace with Stalker, attempt devirtualization or analyze handler behavior

---

## 8. Tips & Pitfalls

- **Hook consumers, not decryptors.** The JNI vtable + libc + dlsym approach recovers strings without understanding VMP's encryption. This is the proven first-pass technique.
- **Don't fight the VM head-on.** If a function is virtualized, consider hooking its inputs/outputs rather than fully devirtualizing it.
- **Mutation is easier than virtualization.** Mutated code can often be understood with a good decompiler — the junk cancels out during optimization/decompilation.
- **Dump at JNI_OnLoad, not before.** On Android, VMP completes unpacking before JNI_OnLoad runs. Dumping earlier gets encrypted garbage.
- **Fingerprint by offset, not by name.** Library names change between builds. Match `JNI_OnLoad` (or another export) at its known offset instead.
- **Filter by return address.** Without filtering, libc hooks produce thousands of irrelevant hits from system libraries. Always check `this.returnAddress` against the target module range.
- **Deduplicate aggressively.** VMP-protected code may call `strcmp` or `strlen` on the same string thousands of times. Use a seen-set keyed on `source|string`.
- **VMP version matters.** VMP 2.x is significantly easier to analyze than 3.x. Check the section names and handler complexity.
- **CRC checks will crash you.** If you patch code in `.vmp` sections, the integrity check will detect it. Bypass CRC first, then patch.
- **Memory breakpoints over INT3.** VMProtect detects software breakpoints (0xCC). Use hardware breakpoints instead.
- **Anti-anti-debug first.** Always neutralize anti-debug before attempting interactive debugging.
- **Watch for multi-layered protection.** VMP can virtualize the virtualizer — the first VM layer may unpack a second VM layer.

---

## 9. Reference: VMP Section Layout (PE)

```
Section     Characteristics              Purpose
.text       CODE, EXECUTE, READ          Original code (partially hollowed)
.rdata      INITIALIZED_DATA, READ       Original read-only data
.data       INITIALIZED_DATA, READ/WRITE Original mutable data
.vmp0       CODE, EXECUTE, READ/WRITE    VM bytecode + handlers + encrypted data
.vmp1       CODE, EXECUTE, READ/WRITE    Additional VM code (overflow or 2nd layer)
.rsrc       INITIALIZED_DATA, READ       Resources (may be VMP-packed)
.reloc      INITIALIZED_DATA, READ       Relocations (may be stripped by VMP)
```

Note: `.vmp0` having `WRITE` permission is itself a heuristic — legitimate code sections rarely need write access (VMP needs it for runtime self-modification).

---

## 10. Reference: VMP Section Layout (ELF / Android .so)

```
Section       Flags              Purpose
.text         AX (alloc+exec)    Original code (may be hollowed or minimal)
.rodata       A  (alloc)         Read-only data
.data         WA (write+alloc)   Mutable data
.vmp0         WAX (write+alloc+exec)  VM bytecode + handlers
.vmp1         WAX (write+alloc+exec)  Additional VM code
.init_array   WA                 Constructors (VMP may add entries here)
```

For Android `.so` files, VMProtect may also:
- Add custom `PT_LOAD` segments with RWX permissions
- Use `JNI_OnLoad` as the unpacking entry point
- Encrypt the `.init_array` entries
- Resolve all imports via `dlsym` (no ELF dynamic linking)

```bash
# ELF-specific detection
readelf -S target.so | grep -i vmp
readelf -l target.so | grep RWE    # RWX segments are suspicious
```
