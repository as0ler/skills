# Frida Script Templates — iOS ARM64 & Android

> Frida 17.x compatible. All scripts use the modern API (no legacy `Sync`-suffix or `Memory.readXxx()` static methods).
> Platform bridges (`ObjC`, `Java`) are loaded via `frida-tools 14+` REPL/frida-trace automatically,
> or imported explicitly in TypeScript agents with `import "frida-objc-bridge"` / `import "frida-java-bridge"`.

---

## Table of Contents

1. [iOS ARM64 — ObjC Method Hook](#1-ios-arm64--objc-method-hook)
2. [iOS ARM64 — Swift Method Hook via Symbol](#2-ios-arm64--swift-method-hook-via-symbol)
3. [iOS ARM64 — Native Function Hook (Interceptor)](#3-ios-arm64--native-function-hook-interceptor)
4. [iOS ARM64 — Dump All ObjC Classes & Methods](#4-ios-arm64--dump-all-objc-classes--methods)
5. [iOS ARM64 — SSL Pinning Bypass](#5-ios-arm64--ssl-pinning-bypass)
6. [iOS ARM64 — Keychain Dump](#6-ios-arm64--keychain-dump)
7. [iOS ARM64 — Stalker Tracing](#7-ios-arm64--stalker-tracing)
8. [Android — Java Method Hook](#8-android--java-method-hook)
9. [Android — Native Library Hook](#9-android--native-library-hook)
10. [Android — SSL Pinning Bypass (OkHttp + TrustManager)](#10-android--ssl-pinning-bypass-okhttp--trustmanager)
11. [Android — Root Detection Bypass](#11-android--root-detection-bypass)
12. [Android — Frida Detection Bypass (Anti-Frida)](#12-android--frida-detection-bypass-anti-frida)
13. [Android — Memory Scan for Pattern](#13-android--memory-scan-for-pattern)
14. [Android — PLT/GOT Hook via CModule](#14-android--pltgot-hook-via-cmodule)
15. [Cross-platform — Interceptor.replaceFast + CModule](#15-cross-platform--interceptorreplacefastcmodule)
16. [Cross-platform — Send / Recv IPC](#16-cross-platform--send--recv-ipc)
17. [Cross-platform — Stalker Coverage Dump](#17-cross-platform--stalker-coverage-dump)

---

## 1. iOS ARM64 — ObjC Method Hook

```javascript
// Hook an ObjC instance method and log args + return value.
// Usage: frida -U -f com.example.App -l script.js

const TargetClass = ObjC.classes.NSURLSession;

Interceptor.attach(
  TargetClass['- dataTaskWithRequest:completionHandler:'].implementation,
  {
    onEnter(args) {
      // args[0] = self, args[1] = selector, args[2] = NSURLRequest, args[3] = block
      const req = new ObjC.Object(args[2]);
      console.log('[+] dataTaskWithRequest:', req.URL().absoluteString().toString());
      this.reqUrl = req.URL().absoluteString().toString();
    },
    onLeave(retval) {
      console.log('[+] Returned task:', retval);
    }
  }
);
```

---

## 2. iOS ARM64 — Swift Method Hook via Symbol

```javascript
// Frida 17: use Process.getModuleByName().findSymbolByName()
// Swift symbols are mangled; use `nm` or `rabin2 -s` to find them.

const appModule = Process.getModuleByName('TargetApp');
const sym = appModule.findSymbolByName('_$s9TargetApp14GameControllerC10checkCheatyyF');

if (sym) {
  Interceptor.attach(sym, {
    onEnter(args) {
      console.log('[+] checkCheat called');
    },
    onLeave(retval) {
      // Replace return value (bool → 0 = false)
      retval.replace(ptr(0));
      console.log('[+] checkCheat patched → false');
    }
  });
} else {
  console.error('[-] Symbol not found');
}
```

---

## 3. iOS ARM64 — Native Function Hook (Interceptor)

```javascript
// Hook a C function exported from a dylib.
// Frida 17: Module.getExportByName is gone → use Process.getModuleByName().getExportByName()

const libc = Process.getModuleByName('libSystem.B.dylib');
const openPtr = libc.getExportByName('open');

Interceptor.attach(openPtr, {
  onEnter(args) {
    const path = args[0].readUtf8String();
    console.log(`[open] path=${path}, flags=${args[1].toInt32()}`);
    this.path = path;
  },
  onLeave(retval) {
    console.log(`[open] fd=${retval.toInt32()} for ${this.path}`);
  }
});
```

---

## 4. iOS ARM64 — Dump All ObjC Classes & Methods

```javascript
// Enumerate all loaded ObjC classes and their methods.
// Frida 17: Process.enumerateModules() returns an array directly.

const seen = new Set();

for (const cls of Object.values(ObjC.classes)) {
  const name = cls.$name;
  if (seen.has(name)) continue;
  seen.add(name);

  // Only print app bundle classes (filter by module path if needed)
  const methods = cls.$ownMethods;
  if (methods.length > 0) {
    console.log(`\n[CLASS] ${name}`);
    for (const m of methods) {
      console.log(`  ${m}`);
    }
  }
}
```

---

## 5. iOS ARM64 — SSL Pinning Bypass

```javascript
// Bypass SecTrustEvaluate and SecTrustEvaluateWithError (iOS 12+)

const Security = Process.getModuleByName('Security');

// SecTrustEvaluate (deprecated but still used)
const SecTrustEvaluate = Security.getExportByName('SecTrustEvaluateWithError');
if (SecTrustEvaluate) {
  Interceptor.replace(SecTrustEvaluate, new NativeCallback(
    (trust, error) => {
      if (!error.isNull()) error.writePointer(ptr(0));
      return 1; // errSecSuccess
    },
    'int', ['pointer', 'pointer']
  ));
  console.log('[+] SecTrustEvaluateWithError patched');
}

// Also patch NSURLSession delegate (ObjC layer)
const SessionDelegate = ObjC.classes.NSURLSessionDelegate;
if (SessionDelegate) {
  // Standard HTTPS challenge
  const sel = '- URLSession:didReceiveChallenge:completionHandler:';
  if (SessionDelegate[sel]) {
    Interceptor.attach(SessionDelegate[sel].implementation, {
      onEnter(args) {
        const completionHandler = new ObjC.Block(args[4]);
        const originalImpl = completionHandler.implementation;
        completionHandler.implementation = (disposition, credential) => {
          // NSURLSessionAuthChallengeUseCredential = 0, credential = nil → trust all
          originalImpl(0, ObjC.classes.NSURLCredential.credentialForTrust_(args[3]));
        };
      }
    });
  }
}
```

---

## 6. iOS ARM64 — Keychain Dump

```javascript
// Dump Keychain items using SecItemCopyMatching

const SecItemCopyMatching = Process.getModuleByName('Security')
  .getExportByName('SecItemCopyMatching');

const kSecClassGenericPassword = ObjC.classes.NSString.stringWithString_('genp');
const query = ObjC.classes.NSMutableDictionary.dictionary();
query.setObject_forKey_(ObjC.classes.NSString.stringWithString_('genp'),
  ObjC.classes.NSString.stringWithString_('class'));
query.setObject_forKey_(
  ObjC.classes.NSNumber.numberWithBool_(true),
  ObjC.classes.NSString.stringWithString_('r_Data')
);
// Set limit to kSecMatchLimitAll
query.setObject_forKey_(
  ObjC.classes.NSString.stringWithString_('m_LimA'),
  ObjC.classes.NSString.stringWithString_('m_Lim')
);

const resultPtr = Memory.alloc(Process.pointerSize);
resultPtr.writePointer(ptr(0));

const fn = new NativeFunction(SecItemCopyMatching, 'int', ['pointer', 'pointer']);
const status = fn(query.handle, resultPtr);

if (status === 0) {
  const items = new ObjC.Object(resultPtr.readPointer());
  console.log('[Keychain]', items.description().toString());
} else {
  console.log('[-] SecItemCopyMatching status:', status);
}
```

---

## 7. iOS ARM64 — Stalker Tracing

```javascript
// Trace execution of a specific function using Stalker.
// Captures every basic block executed.

const appMod = Process.getModuleByName('TargetApp');
const targetFn = appMod.getExportByName('_computeHash') 
  ?? appMod.findSymbolByName('_computeHash');

if (!targetFn) { console.error('[-] target not found'); }

Interceptor.attach(targetFn, {
  onEnter(args) {
    Stalker.follow(Process.getCurrentThreadId(), {
      events: { call: true, ret: true, exec: false, block: true },
      onReceive(events) {
        const parsed = Stalker.parse(events, { annotate: true, stringify: true });
        for (const ev of parsed) {
          console.log(JSON.stringify(ev));
        }
      }
    });
  },
  onLeave(retval) {
    Stalker.unfollow(Process.getCurrentThreadId());
    Stalker.flush();
    Stalker.garbageCollect();
  }
});
```

---

## 8. Android — Java Method Hook

```javascript
// Hook a Java method with argument logging and return value override.
// Works with frida-tools 14+ (Java bridge auto-loaded in REPL).

Java.perform(() => {
  const Activity = Java.use('android.app.Activity');

  Activity.onCreate.overload('android.os.Bundle').implementation = function(bundle) {
    console.log('[+] Activity.onCreate called on:', this.getClass().getName());
    this.onCreate(bundle); // call original
  };

  // Hook a custom app class
  const GameManager = Java.use('com.example.game.GameManager');

  GameManager.isUserPremium.implementation = function() {
    console.log('[+] isUserPremium() hooked → returning true');
    return true;
  };

  // Hook overloaded method
  GameManager.calculateScore.overload('int', 'float').implementation = function(level, multiplier) {
    const original = this.calculateScore(level, multiplier);
    console.log(`[+] calculateScore(${level}, ${multiplier}) = ${original}`);
    return original * 10; // 10x score
  };
});
```

---

## 9. Android — Native Library Hook

```javascript
// Hook a native function inside a loaded .so library.
// Frida 17: use Process.getModuleByName() then getExportByName() / findExportByName()

Java.perform(() => {
  // Wait for the native lib to be loaded
  const libName = 'libgame.so';

  let hookInstalled = false;

  const tryHook = () => {
    const mod = Process.findModuleByName(libName);
    if (!mod) return false;

    const exportAddr = mod.findExportByName('Java_com_example_game_GameJNI_validateKey');
    if (!exportAddr) return false;

    Interceptor.attach(exportAddr, {
      onEnter(args) {
        // JNI: args[0]=JNIEnv*, args[1]=jclass/jobject, args[2+]=actual params
        const keyStr = Java.vm.tryGetEnv()?.getStringUtfChars(args[2], null);
        console.log('[+] validateKey called, key =', keyStr);
      },
      onLeave(retval) {
        retval.replace(ptr(1)); // always return JNI_TRUE
        console.log('[+] validateKey → patched to true');
      }
    });

    hookInstalled = true;
    return true;
  };

  if (!tryHook()) {
    // Library not yet loaded — use dlopen hook
    const linker = Process.findModuleByName('linker64') ?? Process.findModuleByName('linker');
    if (linker) {
      const dlopen = Module.getGlobalExportByName('android_dlopen_ext') 
        ?? Module.getGlobalExportByName('dlopen');

      Interceptor.attach(dlopen, {
        onLeave() {
          if (!hookInstalled) tryHook();
        }
      });
    }
  }
});
```

---

## 10. Android — SSL Pinning Bypass (OkHttp + TrustManager)

```javascript
// Comprehensive SSL bypass: OkHttp CertificatePinner + custom TrustManager.

Java.perform(() => {
  // --- OkHttp3 CertificatePinner ---
  try {
    const CertificatePinner = Java.use('okhttp3.CertificatePinner');
    CertificatePinner.check.overload('java.lang.String', 'java.util.List')
      .implementation = function(hostname, peerCertificates) {
        console.log('[+] OkHttp CertificatePinner.check bypassed for:', hostname);
        // Don't call original → bypass pinning
      };
    CertificatePinner['check$okhttp'].implementation = function() {
      console.log('[+] OkHttp check$okhttp bypassed');
    };
  } catch(e) { console.log('[-] OkHttp3 not found:', e.message); }

  // --- TrustManagerImpl (Android default) ---
  try {
    const TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    TrustManagerImpl.verifyChain.implementation = function(
      untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData
    ) {
      console.log('[+] TrustManagerImpl.verifyChain bypassed for:', host);
      return untrustedChain;
    };
  } catch(e) { console.log('[-] TrustManagerImpl not found:', e.message); }

  // --- WebViewClient onReceivedSslError ---
  try {
    const WebViewClient = Java.use('android.webkit.WebViewClient');
    WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
      handler.proceed();
      console.log('[+] WebViewClient SSL error suppressed');
    };
  } catch(e) { console.log('[-] WebViewClient not patched:', e.message); }

  console.log('[+] SSL Pinning bypass loaded');
});
```

---

## 11. Android — Root Detection Bypass

```javascript
// Bypass common root detection checks.

Java.perform(() => {
  // --- File existence checks (e.g., /system/xbin/su) ---
  const File = Java.use('java.io.File');
  File.exists.implementation = function() {
    const path = this.getAbsolutePath();
    const rootPaths = ['/system/xbin/su', '/system/bin/su', '/sbin/su',
      '/data/local/tmp/su', '/data/local/xbin/su'];
    if (rootPaths.includes(path)) {
      console.log('[+] Blocked file.exists() for:', path);
      return false;
    }
    return this.exists();
  };

  // --- Runtime.exec su check ---
  const Runtime = Java.use('java.lang.Runtime');
  Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
    if (cmd.includes('su') || cmd.includes('which su')) {
      console.log('[+] Blocked Runtime.exec:', cmd);
      throw Java.use('java.io.IOException').$new('Permission denied');
    }
    return this.exec(cmd);
  };

  // --- Build tag check ---
  const Build = Java.use('android.os.Build');
  Build.TAGS.value = 'release-keys';

  // --- RootBeer / common isRooted methods ---
  try {
    const RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
    RootBeer.isRooted.implementation = () => false;
    RootBeer.isRootedWithoutBusyBoxCheck.implementation = () => false;
    console.log('[+] RootBeer bypassed');
  } catch(e) { /* not present */ }

  console.log('[+] Root detection bypass loaded');
});
```

---

## 12. Android — Frida Detection Bypass (Anti-Frida)

```javascript
// Bypass common Frida self-detection techniques.

// 1. Hide frida-agent threads by name
const pthread_setname_np = Module.getGlobalExportByName('pthread_setname_np');
Interceptor.attach(pthread_setname_np, {
  onEnter(args) {
    const name = args[1].readCString();
    if (name && (name.includes('frida') || name.includes('gum-js'))) {
      args[1].writeUtf8String('kworker/u:0');
      console.log('[+] Renamed thread:', name, '→ kworker/u:0');
    }
  }
});

// 2. Hide /proc/self/maps entries for frida
const libc = Process.getModuleByName('libc.so');
const fgets = libc.getExportByName('fgets');
Interceptor.attach(fgets, {
  onLeave(retval) {
    if (retval.isNull()) return;
    const line = retval.readCString();
    if (line && (line.includes('frida') || line.includes('gum-') || line.includes('linjector'))) {
      retval.writeUtf8String(''); // blank out the line
    }
  }
});

// 3. Block port scan of 27042 (frida-server default)
Java.perform(() => {
  try {
    const Socket = Java.use('java.net.Socket');
    Socket.$init.overload('java.lang.String', 'int').implementation = function(host, port) {
      if (port === 27042 || port === 27043) {
        console.log('[+] Blocked connection to frida port:', port);
        throw Java.use('java.net.ConnectException').$new('Connection refused');
      }
      return this.$init(host, port);
    };
  } catch(e) {}
});

// 4. Hide frida from /proc/self/fd (dlopen path filter)
const openat = Module.getGlobalExportByName('openat');
if (openat) {
  Interceptor.attach(openat, {
    onEnter(args) {
      const path = args[1].readCString();
      if (path && path.includes('frida')) {
        // Redirect to /dev/null
        args[1].writeUtf8String('/dev/null');
      }
    }
  });
}

console.log('[+] Anti-Frida bypass loaded');
```

---

## 13. Android — Memory Scan for Pattern

```javascript
// Scan process memory for a byte pattern (e.g., AES key, magic bytes).
// Frida 17: Memory.scan is still async (callback-based).

const pattern = '7f 45 4c 46'; // ELF magic — replace with your target pattern

for (const range of Process.enumerateRanges('r--')) {
  Memory.scan(range.base, range.size, pattern, {
    onMatch(address, size) {
      console.log(`[+] Pattern found @ ${address} in range ${range.base}-${range.base.add(range.size)}`);
      // Dump surrounding bytes
      try {
        const dump = address.readByteArray(64);
        console.log('[dump]', hexdump(dump, { offset: 0, length: 64, header: false }));
      } catch(e) {}
    },
    onError(reason) {
      // silently skip unreadable ranges
    },
    onComplete() {}
  });
}
```

---

## 14. Android — PLT/GOT Hook via CModule

```javascript
// High-performance PLT/GOT hook using CModule for hot functions.
// Useful in anti-cheat contexts where overhead matters.

const libc = Process.getModuleByName('libc.so');
const mallocPtr = libc.getExportByName('malloc');
const freePtr   = libc.getExportByName('free');

// Store original via Interceptor.replaceFast
const originalMalloc = Interceptor.replaceFast(mallocPtr, 
  new NativeCallback((size) => {
    // Inline fast path — no JS overhead
    return originalMalloc(size);
  }, 'pointer', ['size_t'])
);

// Or use CModule for zero-overhead native interception
const cm = new CModule(`
  #include <gum/gumstalker.h>
  #include <stdio.h>

  static void * (* original_malloc)(size_t size);

  void * replacement_malloc(size_t size) {
    void * result = original_malloc(size);
    return result;
  }
`, {
  original_malloc: mallocPtr
});

// Patch the PLT entry in a target library
const targetLib = Process.getModuleByName('libgame.so');
const plt_malloc = targetLib.findExportByName('malloc');
if (plt_malloc) {
  Memory.patchCode(plt_malloc, Process.pointerSize, code => {
    const writer = new Arm64Writer(code, { pc: plt_malloc });
    writer.putBImm(cm.replacement_malloc);
    writer.flush();
  });
}
```

---

## 15. Cross-platform — Interceptor.replaceFast + CModule

```javascript
// replaceFast: lower overhead than replace(), no onEnter/onLeave.
// Best for hot functions (e.g., anti-cheat tick functions).

const targetMod = Process.getModuleByName('libUE4.so') 
  ?? Process.getModuleByName('UnrealGame');

const processEventAddr = targetMod.findSymbolByName('UObject::ProcessEvent');

if (processEventAddr) {
  const cm = new CModule(`
    #include <gum/guminterceptor.h>

    extern void original_ProcessEvent(void * obj, void * func, void * parms);

    void replacement_ProcessEvent(void * obj, void * func, void * parms) {
      // Custom fast-path logic here
      original_ProcessEvent(obj, func, parms);
    }
  `, {
    original_ProcessEvent: Interceptor.replaceFast(processEventAddr, 
      new NativeCallback(
        (obj, func, parms) => { /* will be replaced by CModule */ },
        'void', ['pointer', 'pointer', 'pointer']
      )
    )
  });

  console.log('[+] ProcessEvent replaced via CModule');
}
```

---

## 16. Cross-platform — Send / Recv IPC

```javascript
// Two-way communication between Frida agent and Python host.

// --- Agent side (this script) ---

// Send data to Python host
function reportHit(functionName, args) {
  send({ type: 'hit', function: functionName, args: args });
}

// Receive commands from Python host
recv('command', (message) => {
  console.log('[+] Received command:', JSON.stringify(message));
  if (message.payload.action === 'dump_memory') {
    const addr = ptr(message.payload.address);
    const size = message.payload.size;
    const data = addr.readByteArray(size);
    send({ type: 'memory_dump', address: message.payload.address }, data);
  }
  // Re-register for next message
  recv('command', arguments.callee);
});

// Example hook that uses IPC
const mod = Process.getModuleByName('libgame.so');
const fn  = mod.findExportByName('checkIntegrity');
if (fn) {
  Interceptor.attach(fn, {
    onEnter(args) {
      reportHit('checkIntegrity', [args[0].toString(), args[1].toString()]);
    }
  });
}
```

```python
# --- Python host side ---
import frida, sys

def on_message(message, data):
    if message['type'] == 'send':
        payload = message['payload']
        if payload.get('type') == 'hit':
            print(f"[HIT] {payload['function']}({', '.join(payload['args'])})")
        elif payload.get('type') == 'memory_dump':
            with open('dump.bin', 'wb') as f:
                f.write(data)
            print(f"[DUMP] {len(data)} bytes from {payload['address']}")
    elif message['type'] == 'error':
        print('[ERROR]', message['stack'])

device  = frida.get_usb_device()
session = device.attach('com.example.game')
script  = session.create_script(open('script.js').read())
script.on('message', on_message)
script.load()

# Send a command to the agent
script.post({'type': 'command', 'payload': {'action': 'dump_memory', 'address': '0x12345678', 'size': 256}})
sys.stdin.read()
```

---

## 17. Cross-platform — Stalker Coverage Dump

```javascript
// Collect basic-block coverage for all threads.
// Useful for fuzzing feedback or anti-cheat analysis.

const coverage = new Map(); // address → hit count

function followThread(threadId) {
  Stalker.follow(threadId, {
    events: { block: true, compile: false },
    onReceive(events) {
      const parsed = Stalker.parse(events);
      for (const [type, start, end] of parsed) {
        if (type === 'block') {
          coverage.set(start.toString(), (coverage.get(start.toString()) ?? 0) + 1);
        }
      }
    }
  });
}

// Follow all threads
for (const thread of Process.enumerateThreads()) {
  followThread(thread.id);
}

// Dump coverage after 5 seconds
setTimeout(() => {
  for (const thread of Process.enumerateThreads()) {
    Stalker.unfollow(thread.id);
  }
  Stalker.flush();

  const sorted = [...coverage.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 50);

  console.log('\n[Coverage Top-50 Blocks]');
  for (const [addr, count] of sorted) {
    const sym = DebugSymbol.fromAddress(ptr(addr));
    console.log(`  ${addr}  hits=${count}  ${sym}`);
  }
  Stalker.garbageCollect();
}, 5000);
```

---

*See [SKILL.md](./SKILL.md) for the full Frida 17 JavaScript API reference.*
