---
name: frida
description: "Use this skill whenever writing, debugging, or reviewing Frida instrumentation scripts targeting iOS ARM64 or Android. Triggers include: any mention of 'Frida', 'dynamic instrumentation', 'hooking', 'Interceptor', 'Stalker', 'ObjC bridge', 'Java bridge', 'frida-server', 'frida-gadget', 'NativeFunction', or requests to hook/trace/patch native or managed functions at runtime. Also use when bypassing SSL pinning, root detection, anti-cheat systems, or Frida self-detection. Apply for both JavaScript and TypeScript agents targeting frida-tools 14+ and Frida 17.x. Do NOT use for static binary analysis (use radare2/Ghidra skills instead), build-time patching, or non-Frida instrumentation frameworks."
---

# Frida 17 JavaScript API Reference

> **Version:** Frida 17.x (latest: 17.6.2, Feb 2026) · frida-tools 14+
> **Runtimes:** QuickJS (default), V8 (opt-in) · TypeScript supported via `frida-compile`
> **Script templates:** See [EXAMPLES.md](./EXAMPLES.md) for ready-to-use iOS ARM64 & Android scripts.

---

## Table of Contents

1. [Setup & Tooling](#1-setup--tooling)
2. [Migration Notes from Frida 16.x](#2-migration-notes-from-frida-16x)
3. [Global / Script Scope](#3-global--script-scope)
4. [Process](#4-process)
5. [Module](#5-module)
6. [Memory](#6-memory)
7. [NativePointer](#7-nativepointer)
8. [NativeFunction & NativeCallback](#8-nativefunction--nativecallback)
9. [Interceptor](#9-interceptor)
10. [Stalker](#10-stalker)
11. [Thread](#11-thread)
12. [DebugSymbol](#12-debugsymbol)
13. [CModule](#13-cmodule)
14. [ObjC Bridge (iOS/macOS)](#14-objc-bridge-iosmacos)
15. [Java Bridge (Android)](#15-java-bridge-android)
16. [Socket](#16-socket)
17. [File & I/O](#17-file--io)
18. [Hexdump & Utilities](#18-hexdump--utilities)
19. [Script IPC (send / recv)](#19-script-ipc-send--recv)
20. [Frida.Compiler](#20-fridacompiler)
21. [Arm64Writer / X86Writer / ThumbWriter](#21-arm64writer--x86writer--thumbwriter)
22. [Platform Tips: iOS ARM64](#22-platform-tips-ios-arm64)
23. [Platform Tips: Android](#23-platform-tips-android)
24. [Quick Reference Table](#24-quick-reference-table)

---

## 1. Setup & Tooling

Install Frida and launch an agent against a target process over USB, TCP, or locally.

```bash
# Minimal working setup
pip install frida frida-tools
frida -U -f com.example.App -l script.js   # spawn via USB
frida -U -F -l script.js                   # attach to frontmost iOS app
```

```bash
# Full tooling reference
pip install frida frida-tools

# Spawn and inject
frida -U -f com.example.App -l script.js          # USB, spawn
frida -U -F -l script.js                           # USB, frontmost app (iOS)
frida -H 192.168.1.10:27042 -f com.example.App -l script.js  # remote TCP

# Interactive REPL (ObjC/Java bridges auto-loaded in frida-tools 14+)
frida -U -F

# Compile TypeScript agent
frida-compile agent.ts -o agent.js
frida-compile agent.ts -o agent.js -w   # watch mode

# Auto-trace functions by name or glob pattern
frida-trace -U -F -i "open" -I "NSURLSession*"

# Push frida-server to Android device
adb push frida-server /data/local/tmp/
adb shell "chmod +x /data/local/tmp/frida-server && /data/local/tmp/frida-server &"

# iOS (jailbroken): install via Cydia/Sileo — package: re.frida.server
```

---

## 2. Migration Notes from Frida 16.x

Frida 17 removed three categories of long-deprecated APIs — update existing scripts before running them against a 17.x agent.

```javascript
// Quick migration checklist — if your script uses any of these patterns, update it:
// ❌ enumerateModulesSync() or callback-style enumerate  → ✅ returns array directly
// ❌ Memory.readU32(ptr)                                 → ✅ ptr.readU32()
// ❌ Module.getExportByName('lib', 'fn')                 → ✅ Process.getModuleByName('lib').getExportByName('fn')
// ❌ ObjC/Java globals without import in TS agents       → ✅ import "frida-objc-bridge"
```

```javascript
// ── Enumeration APIs ──────────────────────────────────────────────────────
// ❌ OLD
Process.enumerateModules({ onMatch(m) { ... }, onComplete() { } });
Process.enumerateModulesSync();
// ✅ NEW — returns array directly
for (const mod of Process.enumerateModules()) { console.log(mod.name); }

// ── Memory read/write ─────────────────────────────────────────────────────
// ❌ OLD
Memory.readU32(ptr('0x1234'));
Memory.writeU32(ptr('0x1234'), 100);
// ✅ NEW — methods on NativePointer, chainable
ptr('0x1234').readU32();
ptr('0x1234').writeU32(100);
ptr('0x1234').add(4).writeU32(10).add(4).writeU16(20);

// ── Static Module helpers ─────────────────────────────────────────────────
// ❌ OLD
Module.getBaseAddress('libc.so');
Module.getExportByName('libc.so', 'open');
Module.findExportByName('libc.so', 'open');
Module.ensureInitialized('libc.so');
// ✅ NEW
Process.getModuleByName('libc.so').base;
Process.getModuleByName('libc.so').getExportByName('open');
Process.getModuleByName('libc.so').findExportByName('open');
Module.getGlobalExportByName('open');   // replaces getExportByName(null, 'open')

// ── Runtime bridges ───────────────────────────────────────────────────────
// ObjC / Java / Swift no longer bundled in Frida core.
// frida-tools 14+ REPL auto-loads them. TypeScript agents must import explicitly:
import "frida-objc-bridge";   // provides ObjC global
import "frida-java-bridge";   // provides Java global
```

---

## 3. Global / Script Scope

Top-level globals and built-ins available in every Frida agent without any import.

```javascript
// Typical agent preamble
const base     = Process.mainModule.base;
const libc     = Process.getModuleByName('libc.so');
const openAddr = libc.getExportByName('open');
send({ type: 'ready', base: base.toString() });
```

```javascript
// Full global reference
ptr(val)           // Create NativePointer from hex string or number
NULL               // NativePointer(0x0)
Process            // Current process introspection
Memory             // Memory utilities (alloc, scan, patch, protect)
Interceptor        // Function hook engine
Stalker            // Code tracing engine
Thread             // Thread enumeration + backtrace
DebugSymbol        // Address ↔ symbol resolution
CModule            // Inline C compilation
Module             // Static module helpers (getGlobalExportByName, load)
ObjC               // Objective-C runtime bridge (iOS/macOS)
Java               // Android ART/JVM bridge
console            // console.log / console.warn / console.error
hexdump(buf)       // Pretty hex dump to string
send(msg, data?)   // Send message + optional binary to Python host
recv(type, cb)     // Register handler for message from Python host
rpc.exports        // Expose JS functions as RPC callable from host

// Script lifecycle
Script.pin();      // Prevent GC of this script object
Script.unpin();

// Top-level await is supported
const result = await SomeAsyncOperation();
```

---

## 4. Process

Provides identity, module lookup, memory range enumeration, thread listing, and exception handling for the instrumented process.

```javascript
// Log process info and look up a module
console.log(Process.id, Process.arch, Process.platform);
const libc = Process.getModuleByName('libc.so');
console.log('libc base:', libc.base, 'size:', libc.size);
```

```javascript
// ── Identity ──────────────────────────────────────────────────────────────
Process.id                  // PID (number)
Process.arch                // 'arm64' | 'x64' | 'arm' | 'ia32'
Process.platform            // 'darwin' | 'linux' | 'windows' | 'freebsd'
Process.pageSize            // page size in bytes
Process.pointerSize         // 4 or 8
Process.codeSigningPolicy   // 'optional' | 'required'
Process.mainModule          // Module object for the main executable
Process.currentDir          // working directory string

// ── Module lookup ─────────────────────────────────────────────────────────
Process.enumerateModules()                   // → Module[]
Process.getModuleByName('libc.so')           // throws if not found
Process.findModuleByName('libc.so')          // → Module | null
Process.getModuleByAddress(ptr('0x1234'))
Process.findModuleByAddress(ptr('0x1234'))

// ── Memory ranges ─────────────────────────────────────────────────────────
Process.enumerateRanges('r-x')                             // → RangeDetails[]
Process.enumerateRanges({ protection: 'r-x', coalesce: true })
Process.enumerateMallocRanges()                            // heap chunks

// RangeDetails: { base: NativePointer, size: number, protection: string,
//                 file?: { path, offset, size } }

// ── Threads ───────────────────────────────────────────────────────────────
Process.enumerateThreads()          // → ThreadDetails[] (Frida threads hidden)
Process.getCurrentThreadId()        // → number

// ── Exception handler ─────────────────────────────────────────────────────
Process.setExceptionHandler((details) => {
  console.log('Exception:', details.type, details.address);
  return false; // false = propagate to OS
});
```

---

## 5. Module

Represents a loaded binary (`.so`, `.dylib`, or executable) and exposes its exports, symbols, imports, and sections.

```javascript
// Look up a module and find two exports without redundant lookups
const libc   = Process.getModuleByName('libc.so');
const openFn = libc.getExportByName('open');
const readFn = libc.getExportByName('read');
console.log('open @', openFn, 'read @', readFn);
```

```javascript
// ── Module object properties ──────────────────────────────────────────────
mod.name    // 'libgame.so'
mod.path    // full filesystem path
mod.base    // NativePointer — load address
mod.size    // size in bytes

// ── Instance methods (Frida 17+) ──────────────────────────────────────────
mod.enumerateImports()        // → ImportDetails[]
mod.enumerateExports()        // → ExportDetails[]
mod.enumerateSymbols()        // → SymbolDetails[]
mod.enumerateSections()       // → SectionDetails[]
mod.enumerateDependencies()   // → string[]

mod.findExportByName('fn')    // → NativePointer | null
mod.getExportByName('fn')     // → NativePointer (throws if missing)
mod.findSymbolByName('_ZN…')  // → NativePointer | null
mod.getSymbolByName('_ZN…')   // → NativePointer

// ExportDetails: { type: 'function'|'variable', name: string, address: NativePointer }

// ── Static global helpers ─────────────────────────────────────────────────
Module.getGlobalExportByName('open')    // search all loaded modules; throws if missing
Module.findGlobalExportByName('open')   // → NativePointer | null
Module.load('/path/to/lib.so')          // dlopen and return Module
```

---

## 6. Memory

Allocates, copies, protects, patches, and scans process memory.

```javascript
// Allocate a C string and scan for its bytes
const buf = Memory.allocUtf8String('FIND_ME');
Memory.scan(buf, 8, '46 49 4e 44', {
  onMatch(addr) { console.log('found at', addr); },
  onError() {},
  onComplete() {}
});
```

```javascript
// ── Allocation ────────────────────────────────────────────────────────────
Memory.alloc(256)                            // zeroed buffer → NativePointer
Memory.allocUtf8String('hello')              // null-terminated UTF-8
Memory.allocUtf16String('hello')             // null-terminated UTF-16
Memory.allocByteArray(new Uint8Array([0x90, 0x90]))

// ── Copy / duplicate ──────────────────────────────────────────────────────
Memory.copy(dst, src, n)       // copy n bytes src → dst
Memory.dup(src, n)             // allocate + copy → new NativePointer

// ── Protection ────────────────────────────────────────────────────────────
Memory.protect(addr, size, 'rwx')          // change page protection
Memory.queryProtection(addr)               // → 'r-x' | 'rwx' | etc.

// ── Code patching (W^X safe) ──────────────────────────────────────────────
Memory.patchCode(addr, size, (code) => {
  const w = new Arm64Writer(code, { pc: addr });
  w.putNop();
  w.flush();
});

// ── Scanning (async, callback-based — remains async in Frida 17) ──────────
// Pattern format: 'AA BB ?? DD'  — ?? is a wildcard byte
Memory.scan(base, size, 'DE AD BE EF', {
  onMatch(address, size)  { console.log('found @', address); },
  onError(reason)         { /* skip unreadable pages */ },
  onComplete()            { }
});

// NOTE: Memory.readXxx() / Memory.writeXxx() static methods REMOVED in 17.
// Use NativePointer instance methods instead — see §7.
```

---

## 7. NativePointer

The universal address type in Frida — every memory address is a `NativePointer` with built-in arithmetic, read, and write methods.

```javascript
// Read a simple struct: vtable pointer + two 32-bit fields
const obj  = ptr('0x200000');
const vtbl = obj.readPointer();
const hp   = obj.add(8).readU32();
const mp   = obj.add(12).readU32();
console.log('vtable:', vtbl, 'hp:', hp, 'mp:', mp);
```

```javascript
const p = ptr('0x100400000');

// ── Arithmetic (returns new NativePointer) ────────────────────────────────
p.add(0x10)   p.sub(4)
p.and(0xFFF)  p.or(1)   p.xor(0xFF)
p.shl(2)      p.shr(1)  p.not()

// ── Comparison ────────────────────────────────────────────────────────────
p.equals(q)          // boolean
p.compare(q)         // -1 | 0 | 1
p.isNull()

// ── Conversion ────────────────────────────────────────────────────────────
p.toInt32()   p.toUInt32()
p.toString()  p.toString(16)
p.toMatchPattern()   // → 'AA BB CC DD' byte string for use in Memory.scan

// ── Read ──────────────────────────────────────────────────────────────────
p.readPointer()      // → NativePointer
p.readS8()   p.readU8()
p.readS16()  p.readU16()
p.readS32()  p.readU32()
p.readS64()  p.readU64()
p.readFloat()   p.readDouble()
p.readByteArray(n)    // → ArrayBuffer
p.readCString()       // null-terminated ASCII/UTF-8
p.readUtf8String(len?)
p.readUtf16String(len?)
p.readAnsiString(len?)  // Windows only

// ── Write (returns same NativePointer for chaining) ───────────────────────
p.writePointer(q)
p.writeS8(v)   p.writeU8(v)
p.writeS16(v)  p.writeU16(v)
p.writeS32(v)  p.writeU32(v)
p.writeS64(v)  p.writeU64(v)
p.writeFloat(v)   p.writeDouble(v)
p.writeByteArray(arrayBuffer)
p.writeUtf8String('hello')
p.writeUtf16String('hello')

// ── Chaining ──────────────────────────────────────────────────────────────
ptr('0x5000')
  .add(8).writeU32(100)
  .add(4).writeU16(42)
  .add(2).writeU8(1);
```

---

## 8. NativeFunction & NativeCallback

Wraps a native C function so it can be called directly from JavaScript, and creates a native-callable stub backed by a JavaScript function.

```javascript
// Call strlen directly from JS
const strlen = new NativeFunction(
  Module.getGlobalExportByName('strlen'), 'int', ['pointer']
);
console.log('length:', strlen(Memory.allocUtf8String('hello'))); // → 5
```

```javascript
// ── NativeFunction: call any native function from JS ─────────────────────
const open = new NativeFunction(
  Process.getModuleByName('libc.so').getExportByName('open'),
  'int',               // return type
  ['pointer', 'int'],  // argument types
  { abi: 'default' }   // optional: 'win64' | 'sysv' | 'stdcall' | 'fastcall'
);
const fd = open(Memory.allocUtf8String('/etc/hosts'), 0 /* O_RDONLY */);

// Supported type strings:
// 'void' 'bool' 'char' 'uchar' 'short' 'ushort' 'int' 'uint'
// 'long' 'ulong' 'longlong' 'ulonglong' 'float' 'double'
// 'pointer' 'size_t' 'ssize_t' 'int8_t' … 'uint64_t'

// ── NativeCallback: expose a JS function as a native C function ───────────
const myHook = new NativeCallback(
  (a, b) => {
    console.log('called with:', a, b);
    return a + b;
  },
  'int',          // return type
  ['int', 'int']  // argument types
);
// myHook is a NativePointer — pass it to Interceptor.replace() or any C API
```

---

## 9. Interceptor

The primary hooking engine — attaches `onEnter`/`onLeave` callbacks to observe any native function, or replaces it entirely with a new implementation.

```javascript
// Log every call to open() and override the return value
Interceptor.attach(Module.getGlobalExportByName('open'), {
  onEnter(args) {
    console.log('[open]', args[0].readCString(), 'flags:', args[1].toInt32());
  },
  onLeave(retval) {
    console.log('[open] fd =', retval.toInt32());
  }
});
```

```javascript
// ── attach: observe without replacing ─────────────────────────────────────
const hook = Interceptor.attach(targetPtr, {
  onEnter(args) {
    // args[n]       → NativePointer (n-th argument)
    // this.context  → CpuContext: pc, sp, fp, x0–x28 (ARM64) / rax… (x64)
    // this.threadId, this.returnAddress, this.depth, this.errno
    this.savedArg = args[0].readUtf8String();  // stash state for onLeave
  },
  onLeave(retval) {
    retval.replace(ptr(1));   // override return value
  }
});
hook.detach();   // remove this specific hook

// ── replace: swap implementation entirely ────────────────────────────────
Interceptor.replace(targetPtr,
  new NativeCallback((arg0) => {
    console.log('replaced, arg0 =', arg0);
    // To call original: new NativeFunction(targetPtr, 'void', ['pointer'])(arg0)
  }, 'void', ['pointer'])
);

// ── replaceFast: lower overhead, no InvocationContext, returns trampoline ─
const origPtr = Interceptor.replaceFast(targetPtr,
  new NativeCallback((arg0) => {
    return new NativeFunction(origPtr, 'int', ['pointer'])(arg0);
  }, 'int', ['pointer'])
);

// ── Housekeeping ──────────────────────────────────────────────────────────
Interceptor.revert(targetPtr);   // undo a replace / replaceFast
Interceptor.flush();              // apply all pending patches immediately
```

---

## 10. Stalker

A dynamic code tracing engine that follows thread execution at the basic-block or instruction level, enabling coverage collection, call tracing, and inline code transformation.

```javascript
// Collect basic-block addresses while a function executes
Interceptor.attach(targetFn, {
  onEnter() {
    Stalker.follow(this.threadId, {
      events: { block: true },
      onReceive(events) {
        for (const [, start] of Stalker.parse(events))
          console.log('block @', start);
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

```javascript
// ── Follow a thread ───────────────────────────────────────────────────────
Stalker.follow(threadId, {
  events: {
    call:    true,   // CALL instructions
    ret:     false,  // RET instructions
    exec:    false,  // every instruction (very high overhead)
    block:   true,   // basic block start addresses
    compile: false   // each time a block is JIT-compiled
  },
  // transform: inline instrumentation mode (alternative to onReceive)
  transform(iterator) {
    let instr = iterator.next();
    while (instr !== null) {
      iterator.putCallout((ctx) => { /* called at this instruction */ });
      iterator.keep();
      instr = iterator.next();
    }
  },
  onReceive(events) {
    // events: raw binary buffer
    const parsed = Stalker.parse(events, { annotate: true, stringify: false });
    // → [[type, from, to], …] or [[type, start, end], …] for blocks
  },
  onCallSummary(summary) {
    // summary: { [addressHex]: hitCount }
  }
});

Stalker.unfollow(threadId)
Stalker.flush()                               // drain buffered events
Stalker.garbageCollect()                      // free compiled code for unfollowed threads
Stalker.isFollowing(threadId)                 // → boolean
Stalker.exclude({ base: mod.base, size: mod.size })  // skip a memory range

Stalker.queueCapacity = 16384                 // event ring buffer size (entries)
Stalker.queueDrainInterval = 250              // drain interval in ms
```

---

## 11. Thread

Enumerates process threads, generates symbolicated backtraces, and provides sleep control for the current thread.

```javascript
// Print a symbolicated backtrace from inside a hook
Interceptor.attach(targetFn, {
  onEnter(args) {
    Thread.backtrace(this.context, Backtracer.ACCURATE)
      .map(DebugSymbol.fromAddress)
      .forEach(s => console.log(' ', s.toString()));
  }
});
```

```javascript
// ── Enumeration ───────────────────────────────────────────────────────────
// Frida's own threads are automatically hidden from results
Process.enumerateThreads()
// → [{ id: number, name?: string, state: string, context: CpuContext }, …]
// state: 'running' | 'stopped' | 'waiting' | 'uninterruptible' | 'halted'

Process.getCurrentThreadId()   // → number

// ── Timing ────────────────────────────────────────────────────────────────
Thread.sleep(0.5)   // sleep current thread for 0.5 seconds (float)

// ── Backtrace ─────────────────────────────────────────────────────────────
Thread.backtrace(context, Backtracer.ACCURATE)  // → NativePointer[]
Thread.backtrace(context, Backtracer.FUZZY)     // faster but less precise
// ACCURATE uses libunwind; FUZZY uses a heuristic frame scan
```

---

## 12. DebugSymbol

Resolves memory addresses to human-readable symbol names and source locations, and looks up addresses by symbol name.

```javascript
// Annotate a backtrace with symbol names
Thread.backtrace(this.context, Backtracer.FUZZY)
  .forEach(addr => console.log(DebugSymbol.fromAddress(addr).toString()));
// Example output: "0x100403f10 libgame!GameManager::isCheatEnabled()"
```

```javascript
// ── Address → symbol ──────────────────────────────────────────────────────
const sym = DebugSymbol.fromAddress(ptr('0x100403f10'));
sym.address      // NativePointer
sym.name         // mangled name string, or null if stripped
sym.moduleName   // 'libgame.so'
sym.fileName     // source file path (only if DWARF info is present)
sym.lineNumber   // number
sym.toString()   // one-line human-readable string

// ── Name → address ────────────────────────────────────────────────────────
const sym2 = DebugSymbol.fromName('_ZN7UObjectL13ProcessEventEPS_P9UFunctionPv');
// Use sym2.address to get the NativePointer

// ── Load external debug info ──────────────────────────────────────────────
DebugSymbol.load(Process.getModuleByName('libgame.so').path);
// Forces DWARF parsing for modules not yet fully analysed
```

---

## 13. CModule

Compiles and links a snippet of C source code into the process at runtime, producing native callbacks with zero JavaScript overhead — ideal for hot hooks and performance-critical instrumentation.

```javascript
// Count hook hits with no JS round-trip overhead
const cm = new CModule(`
  #include <stdint.h>
  static uint32_t hits = 0;
  void on_enter(void) { hits++; }
  uint32_t get_hits(void) { return hits; }
`);
Interceptor.attach(targetFn, { onEnter: cm.on_enter });
// Read the counter from JS:
const getHits = new NativeFunction(cm.get_hits, 'uint32', []);
console.log('hits:', getHits());
```

```javascript
// ── Construction ──────────────────────────────────────────────────────────
const cm = new CModule(`
  #include <gum/guminterceptor.h>   // GumInvocationContext etc.
  #include <stdint.h>
  // Available: GumStalker, GumInterceptor, gum_* APIs, standard C headers

  extern void imported_fn(void);    // symbol imported from JS

  static uint32_t call_count = 0;
  void on_enter(GumInvocationContext * ic) { call_count++; }
  uint32_t get_count(void) { return call_count; }
`,
  // Map C extern names to JS NativePointers
  { imported_fn: someNativeFuncPtr }
);

// ── Access exported C symbols (each is a NativePointer) ──────────────────
cm.on_enter    // → NativePointer
cm.get_count   // → NativePointer

// Use as a native Interceptor callback (no JS round-trip)
Interceptor.attach(target, { onEnter: cm.on_enter });

// Call the C function from JS
const getCount = new NativeFunction(cm.get_count, 'uint32', []);
console.log('calls:', getCount());

cm.dispose();  // unmap the module when no longer needed

// NOTE: CModule is unavailable on unsupported architectures — wrap in try/catch
```

---

## 14. ObjC Bridge (iOS/macOS)

Exposes the Objective-C runtime, letting you look up classes and protocols, hook instance and class methods, intercept and replace blocks, and schedule work on the main queue.

```javascript
// Hook NSURLSession and log every request URL
Interceptor.attach(
  ObjC.classes.NSURLSession['- dataTaskWithRequest:completionHandler:'].implementation,
  {
    onEnter(args) {
      const req = new ObjC.Object(args[2]);
      console.log('[NSURLSession] URL:', req.URL().absoluteString().toString());
    }
  }
);
```

```javascript
// ── Availability ──────────────────────────────────────────────────────────
ObjC.available   // boolean — false on Android / non-ObjC processes

// frida-tools 14+ REPL auto-loads ObjC.
// TypeScript agent: import "frida-objc-bridge";

// ── Class access ──────────────────────────────────────────────────────────
const NSString = ObjC.classes.NSString;
NSString['+ stringWithUTF8String:']    // class method wrapper
NSString['- length']                   // instance method wrapper

// ── ObjC.Object ───────────────────────────────────────────────────────────
const obj = new ObjC.Object(ptr);
obj.$className      // class name string
obj.$methods        // all methods including inherited
obj.$ownMethods     // own methods only
obj.description()   // call -description → ObjC.Object
obj.retain()  obj.release()  obj.autorelease()

// ── Enumerate classes / protocols ─────────────────────────────────────────
ObjC.enumerateLoadedClasses()   // → string[]
const proto = ObjC.protocols.NSURLSessionDelegate;
proto.methods   // → { methodName: { types, read, write } }

// ── Blocks ────────────────────────────────────────────────────────────────
// Create a new ObjC block from JS
const block = new ObjC.Block({
  retType: 'void',
  argTypes: ['pointer'],
  implementation(arg) { console.log('block called', arg); }
});
// Intercept an existing block passed as a function argument
const existing = new ObjC.Block(args[3]);
existing.implementation = (arg) => { /* replace body */ };

// ── Selectors ─────────────────────────────────────────────────────────────
ObjC.selector('viewDidLoad')         // JS string → SEL (NativePointer)
ObjC.selectorAsString(selPtr)        // SEL → JS string

// ── Main queue scheduling ─────────────────────────────────────────────────
ObjC.schedule(ObjC.mainQueue, () => {
  const pool = ObjC.classes.NSAutoreleasePool.alloc().init();
  // ObjC code here runs on the main thread
  pool.release();
});
```

---

## 15. Java Bridge (Android)

Exposes the Android ART/JVM runtime, enabling you to hook Java methods, access static fields, instantiate classes, enumerate live objects on the heap, and work with custom class loaders.

```javascript
// Force isUserPremium() to always return true
Java.perform(() => {
  const GameManager = Java.use('com.example.game.GameManager');
  GameManager.isUserPremium.implementation = function() {
    console.log('[+] isUserPremium hooked → true');
    return true;
  };
});
```

```javascript
// ── Availability ──────────────────────────────────────────────────────────
Java.available   // boolean

// frida-tools 14+ REPL auto-loads Java.
// TypeScript agent: import "frida-java-bridge";

// ── All Java API work must be wrapped in Java.perform() ───────────────────
Java.perform(() => {

  // Get a class wrapper
  const Activity = Java.use('android.app.Activity');

  // Hook instance method (simple overwrite)
  Activity.onResume.implementation = function() {
    console.log('[+] onResume:', this.getClass().getName());
    this.onResume();   // call original
  };

  // Hook overloaded method (specify full signature)
  Activity.startActivity
    .overload('android.content.Intent')
    .implementation = function(intent) {
      console.log('[+] intent:', intent.toString());
      this.startActivity(intent);
    };

  // Read / write a static field
  const Build = Java.use('android.os.Build');
  console.log('Model:', Build.MODEL.value);
  Build.MODEL.value = 'Pixel 9 Pro';

  // Instantiate a class
  const Intent = Java.use('android.content.Intent');
  const i = Intent.$new('android.intent.action.VIEW');

  // Cast a raw pointer to a Java type
  const Runnable = Java.use('java.lang.Runnable');
  const r = Java.cast(somePtr, Runnable);

  // Find all live instances of a class on the heap
  Java.choose('com.example.game.GameManager', {
    onMatch(instance) { console.log('[+] found:', instance); },
    onComplete() {}
  });

  // Prevent GC of a Java object across callbacks
  const retained = Java.retain(instance);
  // Java.release(retained) when done

  // Run code on the ART main thread
  Java.scheduleOnMainThread(() => { /* UI-safe code here */ });

  // Iterate all class loaders (useful for obfuscated / split APKs)
  Java.enumerateClassLoaders({
    onMatch(loader) {
      try { console.log(loader.loadClass('com.hidden.X')); } catch(e) {}
    },
    onComplete() {}
  });

  // List all currently loaded class names
  Java.enumerateLoadedClasses({
    onMatch(name) { if (name.includes('cheat')) console.log(name); },
    onComplete() {}
  });
});

// Access the raw JNI environment (outside Java.perform)
const env     = Java.vm.getEnv();
const jstring = env.newStringUtf('hello from JNI');
```

---

## 16. Socket

Creates outbound TCP/UDP connections or inbound listeners directly from within the agent, useful for building a side-channel without going through `send()`/`recv()`.

```javascript
// Connect to localhost and write a line
const conn = await Socket.connect({ family: 'ipv4', host: '127.0.0.1', port: 9999 });
await conn.output.writeAll(new TextEncoder().encode('hello\n'));
await conn.close();
```

```javascript
// ── Outbound connection ───────────────────────────────────────────────────
const conn = await Socket.connect({
  family: 'ipv4',     // 'ipv4' | 'ipv6' | 'unix'
  host:   '127.0.0.1',
  port:   1337
});
// conn: IOStream { input: InputStream, output: OutputStream }
await conn.output.writeAll(new Uint8Array([0x01, 0x02, 0x03]));
const data = await conn.input.read(256);   // → ArrayBuffer
await conn.close();

// ── Inbound listener ──────────────────────────────────────────────────────
const listener = await Socket.listen({ family: 'ipv4', host: '0.0.0.0', port: 9999 });
const accepted  = await listener.accept();
// accepted has the same IOStream shape as conn
```

---

## 17. File & I/O

Reads and writes files on the device filesystem directly from the agent — useful for dumping memory regions, reading `/proc` entries, or writing logs without going through the host.

```javascript
// Dump /proc/self/maps to the console
console.log(new File('/proc/self/maps', 'r').readText());
```

```javascript
// ── Open ──────────────────────────────────────────────────────────────────
const f = new File('/path/to/file', 'r');  // mode: 'r' 'w' 'rb' 'wb' 'ab' etc.

// ── Read ──────────────────────────────────────────────────────────────────
f.read(n)        // → ArrayBuffer (up to n bytes)
f.readText()     // → string (entire file)
f.readLine()     // → string (one line, including \n)

// ── Write ─────────────────────────────────────────────────────────────────
f.write(data)    // data: string | ArrayBuffer
f.flush()        // flush OS write buffer

// ── Seek / tell ───────────────────────────────────────────────────────────
f.seek(offset, whence)   // whence: 0=SEEK_SET, 1=SEEK_CUR, 2=SEEK_END
f.tell()                 // → current offset (number)

f.close()

// ── Common pattern: dump a memory region to disk ──────────────────────────
const out = new File('/tmp/memdump.bin', 'wb');
out.write(ptr('0x100000000').readByteArray(0x1000));
out.flush();
out.close();
```

---

## 18. Hexdump & Utilities

Pretty-prints memory as a hex + ASCII dump, and provides `Int64`/`UInt64` types for safely handling 64-bit values beyond JavaScript's safe integer range.

```javascript
// Dump 64 bytes from the main module base
console.log(hexdump(Process.mainModule.base, { length: 64, header: true, ansi: true }));
```

```javascript
// ── hexdump ───────────────────────────────────────────────────────────────
hexdump(target, options)
// target:  NativePointer | ArrayBuffer
// options: { offset?: number, length?: number, header?: boolean, ansi?: boolean }
// Returns a formatted string — pass directly to console.log()

// ── Int64 / UInt64 ────────────────────────────────────────────────────────
// Use when values exceed Number.MAX_SAFE_INTEGER (2^53 − 1)
const big = new Int64('0xDEADBEEFCAFEBABE');
const u   = new UInt64('18446744073709551615');

big.add(1)  big.sub(1)  big.and(mask)
big.or(v)   big.xor(v)  big.shl(n)  big.shr(n)  big.not()
big.compare(other)       // -1 | 0 | 1
big.toNumber()  big.toString()  big.toString(16)

// ── ArrayBuffer helpers ───────────────────────────────────────────────────
const ab  = somePtr.readByteArray(16);   // NativePointer → ArrayBuffer
const buf = Memory.alloc(16);
buf.writeByteArray(ab);                  // copy ArrayBuffer back to native memory
```

---

## 19. Script IPC (send / recv)

Provides bidirectional messaging between the in-process JS agent and the Python/Node.js host, and an `rpc.exports` object for synchronous remote procedure calls.

```javascript
// Agent reports every hook hit; host can query modules via RPC
Interceptor.attach(targetFn, {
  onEnter(args) { send({ type: 'hit', arg: args[0].readCString() }); }
});
rpc.exports = {
  getModules() {
    return Process.enumerateModules().map(m => ({ name: m.name, base: m.base.toString() }));
  }
};
```

```javascript
// ── Agent → Host ──────────────────────────────────────────────────────────
send({ type: 'log', msg: 'hello' })                // message only
send({ type: 'dump' }, somePtr.readByteArray(64))  // message + binary payload

// ── Host → Agent ──────────────────────────────────────────────────────────
recv('command', (msg) => {
  console.log('got command:', msg.payload.action);
  recv('command', arguments.callee);   // re-arm for next message
});

// ── RPC exports (synchronous call from host) ──────────────────────────────
rpc.exports = {
  dumpMemory(addrHex, size) {
    return ptr(addrHex).readByteArray(size);   // returned as bytes to Python
  },
  patchAddress(addrHex, value) {
    ptr(addrHex).writeU32(value);
  }
};
```

```python
# Python host side
import frida, sys

def on_message(msg, data):
    if msg['type'] == 'send':
        print('[agent]', msg['payload'])

device  = frida.get_usb_device()
session = device.attach('com.example.game')
script  = session.create_script(open('agent.js').read())
script.on('message', on_message)
script.load()

modules = script.exports.get_modules()                  # RPC call
dump    = script.exports.dump_memory('0x12345678', 256) # → bytes
script.post({'type': 'command', 'payload': {'action': 'start'}})
sys.stdin.read()
```

---

## 20. Frida.Compiler

Compiles TypeScript (or modern JavaScript with ESM imports) into a self-contained bundle loadable as a Frida agent, replacing any manual Node.js build step.

```bash
# Compile once
frida-compile agent/index.ts -o bundle.js

# Watch mode — recompile on save
frida-compile agent/index.ts -o bundle.js -w
```

```python
# Compile and inject programmatically from Python
import frida, asyncio

async def main():
    compiler = frida.Compiler()
    bundle   = await compiler.build('agent/index.ts', compression='terser')
    session  = await frida.get_usb_device_async().attach_async('com.example.App')
    script   = await session.create_script_async(bundle)
    await script.load_async()

asyncio.run(main())
```

```typescript
// agent/index.ts — minimal TypeScript agent structure
import "frida-objc-bridge";   // provides ObjC global
import "frida-java-bridge";   // provides Java global

const openAddr: NativePointer = Module.getGlobalExportByName('open');
Interceptor.attach(openAddr, {
  onEnter(args: InvocationArguments) {
    console.log('[open]', args[0].readCString());
  }
});
```

---

## 21. Arm64Writer / X86Writer / ThumbWriter

Emit machine instructions into a writable code buffer — used inside `Memory.patchCode()` to build patches, trampolines, or inline stubs without hand-encoding raw bytes.

```javascript
// NOP out 4 ARM64 instructions at a target address
Memory.patchCode(targetAddr, 16, (code) => {
  const w = new Arm64Writer(code, { pc: targetAddr });
  w.putNop(); w.putNop(); w.putNop(); w.putNop();
  w.flush();
});
```

```javascript
// ── Arm64Writer (iOS ARM64, Android ARM64) ────────────────────────────────
Memory.patchCode(targetAddr, 64, (code) => {
  const w = new Arm64Writer(code, { pc: targetAddr });

  w.putNop()                            // NOP
  w.putBImm(destAddr)                   // B <addr>  (unconditional branch)
  w.putBCondImm('eq', destAddr)         // B.EQ <addr>
  w.putBlImm(funcAddr)                  // BL <addr>  (branch with link / call)
  w.putLdrRegAddress('x0', dataAddr)    // LDR x0, =<addr>
  w.putMovRegReg('x1', 'x0')            // MOV x1, x0
  w.putRetReg('x30')                    // RET  (BR x30)
  w.putInstruction(0xD503201F)          // emit raw 32-bit encoding

  // Local labels for loops / conditional branches
  w.putLabel('loop_top')
  w.putBCondLabel('ne', 'loop_top')

  w.flush()   // MUST call flush() to finalise the patch
});

// ── X86Writer (Android x86 / x86_64) ─────────────────────────────────────
Memory.patchCode(targetAddr, 32, (code) => {
  const w = new X86Writer(code, { pc: targetAddr });
  w.putNop()
  w.putRet()
  w.putJmpAddress(destAddr)    // JMP <addr>
  w.putCallAddress(funcAddr)   // CALL <addr>
  w.flush()
});

// ── ThumbWriter (Android ARMv7 Thumb) ────────────────────────────────────
Memory.patchCode(targetAddr, 8, (code) => {
  const w = new ThumbWriter(code, { pc: targetAddr });
  w.putNop()
  w.putBImm(destAddr)
  w.flush()
});
```

---

## 22. Platform Tips: iOS ARM64

Practical patterns for working with iOS binaries: ASLR slide calculation, converting IDA Pro offsets to runtime addresses, Swift symbol demangling, and ObjC class discovery.

```javascript
// Convert an IDA Pro virtual address to its runtime address (ASLR aware)
const runtimeAddr = Process.mainModule.base.add(ptr('0x1000403F0').sub(ptr('0x100000000')));
Interceptor.attach(runtimeAddr, { onEnter() { console.log('hit'); } });
```

```javascript
// ── ASLR slide ────────────────────────────────────────────────────────────
const app   = Process.mainModule;
const slide = app.base.sub(ptr('0x100000000'));
console.log('App:', app.name, '@ base', app.base, '(slide', slide, ')');

// ── IDA offset → runtime address helper ───────────────────────────────────
const IDA_BASE = ptr('0x100000000');
const fromIDA  = (va) => app.base.add(ptr(va).sub(IDA_BASE));
Interceptor.attach(fromIDA('0x100123456'), { onEnter() { console.log('hit'); } });

// ── ObjC class discovery ──────────────────────────────────────────────────
Object.keys(ObjC.classes)
  .filter(n => n.startsWith('Game'))
  .forEach(n => console.log(n, '→', ObjC.classes[n].$ownMethods.slice(0, 5)));

// ── Swift symbol demangling ───────────────────────────────────────────────
const swiftCore   = Process.getModuleByName('libswiftCore.dylib');
const demangleFn  = swiftCore.findExportByName('swift_demangle_getDemangledName')
  ?? swiftCore.findExportByName('swift_demangle');
if (demangleFn) {
  const demangle = new NativeFunction(demangleFn, 'pointer',
    ['pointer', 'pointer', 'pointer', 'pointer', 'uint32']);
  const sym    = Memory.allocUtf8String('_$s9TargetApp14GameControllerC10checkCheatyyF');
  const outBuf = Memory.alloc(256);
  const result = demangle(sym, NULL, outBuf, ptr(256), 0);
  if (!result.isNull()) console.log('demangled:', result.readCString());
}

// ── Hook Swift method via mangled symbol ──────────────────────────────────
const swiftFn = app.findSymbolByName('_$s9TargetApp14GameControllerC10checkCheatyyF');
if (swiftFn) {
  Interceptor.attach(swiftFn, { onLeave(retval) { retval.replace(ptr(0)); } });
}

// ── Code signature note ────────────────────────────────────────────────────
// On jailbroken devices memory is already writable — no extra steps needed
```

---

## 23. Platform Tips: Android

Practical patterns for Android: waiting for native library load via `dlopen`, intercepting `RegisterNatives` to discover JNI bindings, and accessing ART internals.

```javascript
// Hook a native export as soon as its library loads
function whenLoaded(libName, cb) {
  if (Process.findModuleByName(libName)) { cb(Process.getModuleByName(libName)); return; }
  const dlopen = Module.getGlobalExportByName('android_dlopen_ext')
    ?? Module.getGlobalExportByName('dlopen');
  let done = false;
  Interceptor.attach(dlopen, {
    onLeave() {
      if (!done && Process.findModuleByName(libName)) {
        done = true; cb(Process.getModuleByName(libName));
      }
    }
  });
}
whenLoaded('libgame.so', mod => {
  const check = mod.findExportByName('checkLicense');
  if (check) Interceptor.attach(check, { onLeave(r) { r.replace(ptr(1)); } });
});
```

```javascript
// ── Read /proc/self/maps ──────────────────────────────────────────────────
console.log(new File('/proc/self/maps', 'r').readText());

// ── Intercept JNI RegisterNatives (discover dynamic JNI bindings) ─────────
const libart  = Process.getModuleByName('libart.so');
const regNat  = libart.findExportByName(
  '_ZN3art3JNI15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi');
if (regNat) {
  Interceptor.attach(regNat, {
    onEnter(args) {
      const count = args[3].toInt32();
      for (let i = 0; i < count; i++) {
        const entry = args[2].add(i * 3 * Process.pointerSize);
        const name  = entry.readPointer().readCString();
        const sig   = entry.add(Process.pointerSize).readPointer().readCString();
        const fn    = entry.add(Process.pointerSize * 2).readPointer();
        console.log(`[RegisterNatives] ${name}${sig} → ${fn}`);
      }
    }
  });
}

// ── ART internals via JNI ─────────────────────────────────────────────────
Java.perform(() => {
  const env = Java.vm.getEnv();
  const cls = env.findClass('com/example/Target');
  const mid = env.getMethodID(cls, 'secretMethod', '()V');
  console.log('Method ID:', mid);

  // Hook the generic JNI trampoline (covers @FastNative / @CriticalNative)
  const tramp = Process.getModuleByName('libart.so')
    .findExportByName('artQuickGenericJniTrampoline');
  if (tramp) Interceptor.attach(tramp, { onEnter(args) { /* … */ } });
});

// ── ART SDK version ───────────────────────────────────────────────────────
Java.perform(() => {
  const VMRuntime = Java.use('dalvik.system.VMRuntime');
  console.log('Target SDK:', VMRuntime.getRuntime().targetSdkVersion());
});
```

---

## 24. Quick Reference Table

| Goal | Frida 17 API |
|------|-------------|
| Get module base | `Process.getModuleByName('lib.so').base` |
| Get export address | `Process.getModuleByName('lib.so').getExportByName('fn')` |
| Global export (any module) | `Module.getGlobalExportByName('open')` |
| Hook function (observe) | `Interceptor.attach(addr, { onEnter, onLeave })` |
| Replace function | `Interceptor.replace(addr, new NativeCallback(…))` |
| Fast replace (no overhead) | `Interceptor.replaceFast(addr, new NativeCallback(…))` |
| Read memory | `ptr('0x…').readU32()` |
| Write memory | `ptr('0x…').writeU32(val)` |
| Chain writes | `ptr('0x…').add(4).writeU32(x).add(4).writeU16(y)` |
| Allocate buffer | `Memory.alloc(size)` |
| Patch code (W^X safe) | `Memory.patchCode(addr, size, writerCb)` |
| Scan memory for bytes | `Memory.scan(base, size, 'AA BB ?? DD', callbacks)` |
| Enumerate modules | `Process.enumerateModules()` |
| Enumerate memory ranges | `Process.enumerateRanges('r-x')` |
| Call native function | `new NativeFunction(ptr, retType, argTypes)(…)` |
| Hook ObjC method | `Interceptor.attach(ObjC.classes.Cls['- m'].implementation, …)` |
| Hook Java method | `Java.perform(() => Java.use('Cls').method.implementation = fn)` |
| Backtrace | `Thread.backtrace(this.context, Backtracer.ACCURATE)` |
| Resolve symbol | `DebugSymbol.fromAddress(addr).toString()` |
| Trace execution | `Stalker.follow(tid, { events: { block: true }, onReceive })` |
| Send to Python host | `send({ type: 'x', data: val })` |
| Receive from Python host | `recv('type', callback)` |
| Expose function as RPC | `rpc.exports = { fnName(args) { … } }` |
| Inline C for hot hooks | `new CModule('void f() { … }')` |
| Emit ARM64 instructions | `new Arm64Writer(code, { pc: addr }).putNop().flush()` |
| IDA offset → runtime addr | `app.base.add(ptr(ida_va).sub(ptr('0x100000000')))` |

---

*For ready-to-use script templates, see **[EXAMPLES.md](./EXAMPLES.md)**.*
