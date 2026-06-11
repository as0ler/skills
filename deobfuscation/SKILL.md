---
name: deobfuscation
description: "Binary deobfuscation, unpacking, and string recovery for protected native binaries (ELF, PE, Mach-O). Use this when encountering obfuscated, packed, or virtualized code — including VMProtect, Themida, Code Virtualizer, Arxan/Irdeto, custom protectors, or unknown obfuscation. Triggers: any mention of 'deobfuscation', 'obfuscated', 'packed binary', 'string encryption', 'code virtualization', 'anti-tamper', 'VMProtect', 'VMP', 'Themida', 'obfuscator', 'unpacking', encrypted sections, import obfuscation, or dynamic API resolution."
---

# Binary Deobfuscation & Unpacking

Framework for identifying, analyzing, and defeating software protection schemes on native binaries. This skill provides the generic methodology; protector-specific techniques are in sub-skills.

## Sub-Skills

| Protector | Reference |
|-----------|-----------|
| **VMProtect** | [vmprotect/SKILL.md](./vmprotect/SKILL.md) — VMP 2.x/3.x detection, section dumping, string deobfuscation, devirtualization, anti-debug bypass |

---

## 1. General Workflow

```
1. Detect    → identify the protector and features used
2. Bypass    → neutralize anti-debug / anti-tamper
3. Unpack    → dump decrypted code sections at runtime
4. Recover   → extract strings, reconstruct imports
5. Analyze   → decompile / devirtualize recovered code
```

---

## 2. Protector Identification

### 2.1 Quick Triage (radare2)

```bash
iS                    # unusual section names (.vmp0, .themida, .enigma, etc.)
iS~rwx                # RWX sections — strong packing indicator
ii | wc -l            # import count — very few = likely packed
iz | wc -l            # string count — very few = string encryption
ie                    # entry point — does it land in a non-.text section?
s entry0; pd 20       # entry point instructions — push/call/jmp patterns
```

### 2.2 Protector Signatures

| Protector | Section Names | Entry Pattern | Key Imports | Other Indicators |
|-----------|--------------|---------------|-------------|------------------|
| **VMProtect** | `.vmp0`, `.vmp1`, `.VMP` | Jump into VMP section | `dlsym`/`GetProcAddress` only | VM dispatch loops, handler tables |
| **Themida/WL** | `.themida`, `.winlice` | `pushad; call $+5` | Kernel-level anti-debug | Driver-based protection |
| **Code Virtualizer** | `.cv0`, `.cv1` | Similar to VMP | Few imports | Oreans family (same vendor as Themida) |
| **Arxan/Irdeto** | Normal names | Guard pages, integrity checks | Normal imports | Checksum functions, code guards |
| **UPX** | `UPX0`, `UPX1` | Decompression stub | Normal (after unpack) | `upx -d` works for unmodified UPX |
| **Custom** | Varies | Varies | Often `dlsym`/`mmap`/`mprotect` | Manual analysis required |

### 2.3 Android .so Specific Detection

On Android, native libraries protected with VMP or similar tools show:

```bash
readelf -S target.so | grep -iE 'vmp|themida|cv[0-9]'   # named sections
readelf -l target.so | grep RWE                           # RWX segments
readelf -d target.so | grep NEEDED                        # minimal dependencies
```

- **RWX segments** (`PF_R | PF_W | PF_X`) — legitimate .so files almost never need this
- **JNI_OnLoad doing heavy work** — protectors use JNI_OnLoad as the unpacking entry point
- **mprotect storms at startup** — the library calls mprotect repeatedly to make sections writable, unpack, then re-protect

---

## 3. Generic Dynamic Techniques

These techniques work regardless of the protector. They hook at the **API boundary** rather than trying to reverse the obfuscation internals.

### 3.1 Module Fingerprinting (Android)

Identify the target `.so` by matching a known export at an expected offset:

```javascript
function findTargetModule(exportName, expectedOffset) {
    for (const mod of Process.enumerateModules()) {
        const exp = mod.findExportByName(exportName);
        if (exp && exp.equals(mod.base.add(expectedOffset))) {
            return mod;
        }
    }
    return null;
}
```

This avoids name-based matching (which breaks when the library is renamed) and works even when the library hasn't been loaded yet when combined with a dlopen hook.

### 3.2 Library Load Detection

Wait for a target library to load at runtime:

```javascript
function waitForLibrary(identifyFn, callback) {
    var found = identifyFn();
    if (found) { callback(found); return; }

    var dlopen = Module.getGlobalExportByName('android_dlopen_ext')
        ?? Module.getGlobalExportByName('dlopen');

    Interceptor.attach(dlopen, {
        onLeave() {
            if (found) return;
            found = identifyFn();
            if (found) callback(found);
        }
    });
}
```

### 3.3 mprotect Monitoring

Track memory permission changes to understand the unpacking sequence:

```javascript
function hookMprotect(targetModule) {
    var log = [];
    Interceptor.attach(Module.getGlobalExportByName('mprotect'), {
        onEnter(args) {
            this.addr = args[0];
            this.len  = args[1].toUInt32();
            this.prot = args[2].toInt32();
        },
        onLeave(retval) {
            if (retval.toInt32() !== 0) return;

            var start = this.addr;
            var end   = start.add(this.len);
            var modStart = targetModule.base;
            var modEnd   = modStart.add(targetModule.size);
            if (start.compare(modEnd) >= 0 || end.compare(modStart) <= 0) return;

            var prot = '';
            if (this.prot & 1) prot += 'r';
            if (this.prot & 2) prot += 'w';
            if (this.prot & 4) prot += 'x';
            log.push({ addr: start.toString(), len: this.len, prot: prot || 'none' });
            console.log('[mprotect] ' + start + ' len=0x' + this.len.toString(16) + ' ' + prot);
        }
    });
    return log;
}
```

Typical protector sequence: `r-x` → `rwx` (unpack) → `r-x` (re-protect). A section that becomes `rwx` and then goes back to `r-x` has just been unpacked — dump it at the transition.

### 3.4 Section Dumping via Frida

Dump a decrypted section after the protector finishes unpacking:

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
        reason: reason
    }, bytes);
    console.log('[+] Dumped 0x' + size.toString(16) + ' bytes @ ' + addr + ' (' + reason + ')');
}
```

### 3.5 API-Level String Capture

Instead of reversing the string decryption algorithm, hook the functions that **consume** decrypted strings. This works for any protector because decrypted strings must eventually pass through standard APIs.

**Target functions by category:**

| Category | Functions | What they reveal |
|----------|-----------|------------------|
| **libc string** | `strcmp`, `strncmp`, `strstr`, `strlen`, `snprintf`, `sprintf` | General strings used by the protected code |
| **Dynamic linking** | `dlsym`, `dlopen` | Dynamically resolved API names and libraries |
| **JNI (Android)** | `NewStringUTF`, `GetStringUTFChars`, `FindClass`, `GetMethodID`, `GetFieldID`, `RegisterNatives` | Java-native boundary: class names, method names, field names |
| **Logging** | `__android_log_print`, `__android_log_write`, `NSLog` | Debug/status messages |
| **File I/O** | `fopen`, `open`, `access` | File paths accessed by the protected code |

**Return-address filtering** — only log calls originating from the target module to reduce noise:

```javascript
function isFromTarget(returnAddr) {
    return returnAddr.compare(targetBase) >= 0 &&
           returnAddr.compare(targetEnd) < 0;
}

Interceptor.attach(Module.getGlobalExportByName('strcmp'), {
    onEnter(args) {
        if (!isFromTarget(this.returnAddress)) return;
        this.log = true;
        this.s1 = args[0].readCString();
        this.s2 = args[1].readCString();
    },
    onLeave() {
        if (!this.log) return;
        if (this.s1) console.log('[strcmp] ' + this.s1);
        if (this.s2) console.log('[strcmp] ' + this.s2);
    }
});
```

### 3.6 Deduplication

When hooking high-frequency functions, deduplicate to avoid log noise:

```javascript
var seen = {};
var seenCount = 0;
var MAX_SEEN = 50000;

function isDuplicate(source, str) {
    var key = source + '|' + str;
    if (seen[key]) return true;
    if (seenCount < MAX_SEEN) {
        seen[key] = 1;
        seenCount++;
    }
    return false;
}

function logString(source, str, extra) {
    if (!str || str.length === 0 || str.length > 4096) return;
    if (isDuplicate(source, str)) return;
    send({ type: 'string', source: source, value: str, extra: extra || '' });
}
```

### 3.7 Python Host Script Pattern

Capture agent output and write categorized results:

```python
import frida, sys, signal, time

strings_by_source = {}

def on_message(message, data):
    if message["type"] == "send":
        payload = message["payload"]
        if isinstance(payload, dict) and payload.get("type") == "string":
            source = payload.get("source", "unknown")
            value = payload.get("value", "")
            strings_by_source.setdefault(source, []).append(value)
            print(f"[{source}] {value}")
        elif isinstance(payload, dict) and payload.get("type") == "dump":
            with open(f"dump_{payload['reason']}.bin", "wb") as f:
                f.write(data)
            print(f"[dump] {payload['size']} bytes saved")

device = frida.get_device_manager().add_remote_device("127.0.0.1:27042")
pid = device.spawn(["com.example.app"])
session = device.attach(pid)
script = session.create_script(open("agent.js").read())
script.on("message", on_message)
script.load()
device.resume(pid)

signal.signal(signal.SIGINT, lambda *_: sys.exit(0))
while True: time.sleep(1)
```

### 3.8 uncompress / zlib Monitoring

Many protectors (including VMProtect) use zlib to decompress packed code at runtime:

```javascript
var uncompress = Module.getGlobalExportByName('uncompress');
if (uncompress) {
    Interceptor.attach(uncompress, {
        onEnter(args) {
            this.dest    = args[0];
            this.destLen = args[1];
            this.srcLen  = args[3].toUInt32();
        },
        onLeave(retval) {
            if (retval.toInt32() !== 0) return;
            var outLen = this.destLen.readU32();
            console.log('[uncompress] ' + this.srcLen + ' -> ' + outLen + ' bytes @ ' + this.dest);
        }
    });
}
```

---

## 4. Tips

- **Hook consumers, not decryptors.** Reversing the decryption algorithm is hard and protector-specific. Hooking the APIs that receive decrypted data (strcmp, JNI, dlsym) is protector-agnostic and much faster.
- **Filter by return address.** Without filtering, libc hooks produce thousands of irrelevant hits from system libraries. Check `this.returnAddress` against the target module range.
- **Dump after JNI_OnLoad (Android).** For protected Android .so files, the unpacking is typically complete by the time `JNI_OnLoad` is called. Hook it and dump sections from `onEnter`.
- **Track mprotect to understand unpacking.** The sequence of mprotect calls reveals which sections are being unpacked and when. This tells you the right moment to dump.
- **Use fingerprinting, not names.** Identify target modules by matching exports at known offsets, not by library name (which can change between builds).
