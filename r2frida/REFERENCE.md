# r2frida Advanced Reference

## Android-Specific Analysis

### Finding Device and App Information

```bash
# List USB devices
frida-ls-devices

# List apps on device
frida-ps -Ua

# Get package names
frida-ps -Uai | grep -i target

# Connect via r2frida
r2 frida://spawn/usb//com.example.app
```

### Analyzing Native Libraries

```bash
# List all loaded libraries
:il

# Find app's native libraries
:il~arm64
:dm~lib/arm64

# Focus on specific library
:dm~libnative
# Example output:
# 0x7f5bf72000 - 0x7f5bf74000 r-x /data/app/com.app/lib/arm64/libnative.so

# Get base address for calculations
s 0x7f5bf72000
```

### JNI Function Analysis

```bash
# Find JNI_OnLoad (library initialization)
:iE libnative.so~JNI
:iEa libnative.so JNI_OnLoad

# Trace JNI_OnLoad execution
:dt `iEa libnative.so JNI_OnLoad`
:dtf `iEa libnative.so JNI_OnLoad` v^+
:dc

# Find registered native methods
:iE libnative.so~Java_
```

### Frida Anti-Detection Bypass

```bash
# Search for frida detection strings
:\/ frida
:\/ "frida-server"
:\/ xposed

# Find common detection functions
:iE~pthread_create
:iE~open
:iE~strstr

# Trace file opens for detection attempts
:dtf `iEa libc.so open` z^+

# Hook and monitor
:dt fopen
:dth fopen z z
:dc
```

### Crypto Library Analysis

```bash
# Find crypto libraries
:il~crypto
:il~ssl

# Analyze OpenSSL functions
:iE libcrypto.so~AES
:iE libcrypto.so~EVP

# Trace encryption
:dt `iEa libcrypto.so EVP_EncryptUpdate`
:dtf `iEa libcrypto.so EVP_EncryptUpdate` xhhhh^

# Trace key derivation
:dt `iEa libcrypto.so PKCS5_PBKDF2_HMAC`
```

### Anti-Tampering Analysis

```bash
# Search for integrity check strings
:\/ "signature"
:\/ "tamper"
:\/ "checksum"

# Find ptrace (anti-debug)
:iE libc~ptrace
:dt `iEa libc.so ptrace`
:di0 `iEa libc.so ptrace`

# Find getppid (parent process check)
:dt `iEa libc.so getppid`
```

## iOS-Specific Analysis

### Connecting to iOS Device

```bash
# List iOS processes
r2 frida://list/usb//

# List installed apps
r2 frida://apps/usb//

# Spawn by bundle identifier
r2 frida://spawn/usb//com.example.app

# Attach to running app
r2 frida://attach/usb//AppName

# Attach to Frida Gadget
r2 frida://attach/usb//Gadget
```

### Objective-C Runtime Analysis

```bash
# List all ObjC classes
:ic

# Find view controllers
:ic~ViewController
:ic~Login

# List methods of class
:ic LoginViewController

# Find specific patterns
:ic~+Jailbreak
:ic~+SSL
:ic~+Certificate
```

### Analyzing ObjC Methods

```bash
# Get method address
:iEa AppBinary "-[LoginViewController validateCredentials:]"

# Trace ObjC method
:dtf 0x100045678 O^+

# Trace with multiple ObjC object arguments
:dtf 0x100045678 OOO^

# Intercept and modify return
:di1 0x100045678  # Return YES/true
:di0 0x100045678  # Return NO/false
```

### Swift Analysis

```bash
# Find Swift classes (mangled names)
:iE~_TtC
:iE~swift

# Find Swift standard library
:il~Swift
:dm~libswift
```

### Keychain Analysis

```bash
# Find Keychain functions
:iE~SecItem
:iE~Keychain

# Trace Keychain queries
:dt `iEa Security SecItemCopyMatching`
:dtf `iEa Security SecItemCopyMatching` OO^+
```

### SSL Pinning Investigation

```bash
# Find SSL/TLS classes
:ic~SSL
:ic~NSURL
:ic~AFSecurity
:ic~TrustKit

# Find verification methods
:iE~SSL_CTX_set_verify
:iE~SecTrustEvaluate

# Trace certificate evaluation
:dt `iEa Security SecTrustEvaluateWithError`
```

### Jailbreak Detection Analysis

```bash
# Common detection classes
:ic~Jailbreak
:ic~JailbreakDetection
:ic~DeviceCheck

# Common checked paths
:\/ "/Applications/Cydia"
:\/ "/bin/bash"
:\/ "/usr/sbin/sshd"
:\/ "/etc/apt"

# Common detection methods
:ic~+isJailbroken
:ic~+detectJailbreak

# Bypass by returning false
:di0 `iEa AppBinary "-[JBDetector isJailbroken]"`
```

## Advanced Tracing Techniques

### Multi-Function Tracing

```bash
# Trace multiple related functions
:dt malloc
:dt free
:dt realloc
:dt calloc

# With format
:dtf `iEa libc.so malloc` i^
:dtf `iEa libc.so free` x^

# Resume
:dc
```

### Conditional Tracing with Scripts

```javascript
// conditional_trace.js
var targetAddr = Module.findExportByName("libc.so", "strcmp");

Interceptor.attach(targetAddr, {
    onEnter: function(args) {
        var s1 = args[0].readCString();
        var s2 = args[1].readCString();
        
        // Only log if contains "password"
        if (s1.indexOf("password") !== -1 || s2.indexOf("password") !== -1) {
            console.log("strcmp: " + s1 + " vs " + s2);
            console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
                .map(DebugSymbol.fromAddress).join("\n"));
        }
    }
});
```

```bash
:. conditional_trace.js
:dc
```

### Register Tracing

```bash
# Trace specific registers at address
:dtr 0x12345678 x0 x1 x2   # ARM64
:dtr 0x12345678 rdi rsi    # x86_64

# Example output:
# Trace at 0x12345678
#   x0 = 0x7fff12345678
#   x1 = 0x0000000000001234
```

### Stalker (Code Coverage)

```bash
# Trace function with Stalker
:dtSf 0x12345678

# Trace all threads for N seconds
:dtS 10

# Get results
:dtS*

# Configure Stalker events
:e stalker.event=call      # trace calls
:e stalker.event=ret       # trace returns
:e stalker.event=exec      # trace all instructions
:e stalker.event=block     # trace basic blocks
:e stalker.event=compile   # trace on first execution (default)
```

## Memory Manipulation

### Patching Code

```bash
# Enable code patching
:e patch.code=true

# Read current bytes
px 16 @ 0x12345678

# Write bytes
wx 9090 @ 0x12345678        # NOP slide (x86)
wx 1f2003d5 @ 0x12345678    # NOP (ARM64)

# Patch return value (ARM64: mov x0, #1; ret)
wx 200080d2c0035fd6 @ 0x12345678
```

### Memory Protection

```bash
# Make memory writable
:dmp 0x12345000 0x1000 rwx

# Check current protection
:dm. @ 0x12345000
```

### Heap Analysis

```bash
# List heap allocations
:dmh

# Get heap statistics
:dmhm

# Allocate and track
:dmas "test_string"
:dma 1024
:dmal

# Search heap
:\/ "sensitive_data"
```

## Scripting and Automation

### r2frida Plugin Development

```javascript
// myplugin.js
r2frida.pluginRegister('hookfunc', function(name) {
    if (name === 'hookfunc') {
        return function(args) {
            if (args.length < 1) {
                return "Usage: :hookfunc <address>";
            }
            
            var addr = ptr(args[0]);
            
            Interceptor.attach(addr, {
                onEnter: function(args) {
                    console.log("[*] Function called");
                    console.log("    arg0: " + args[0]);
                    console.log("    arg1: " + args[1]);
                },
                onLeave: function(retval) {
                    console.log("    ret: " + retval);
                }
            });
            
            return "Hooked " + addr;
        }
    }
});
```

```bash
:. myplugin.js
:hookfunc 0x12345678
```

### Complex JavaScript Evaluation

```bash
# Get module base
:eval Module.findBaseAddress("libnative.so")

# Find and hook export
:eval Interceptor.attach(Module.findExportByName("libc.so", "strcmp"), { onEnter: function(args) { console.log(args[0].readCString()); } })

# Replace implementation
:eval Interceptor.replace(ptr(0x12345678), new NativeCallback(function() { return 1; }, 'int', []))

# Enumerate modules
:eval Process.enumerateModules().forEach(function(m) { console.log(m.name + " @ " + m.base); })
```

### Batch Operations

```bash
# Create r2 script for repeated analysis
cat > analyze.r2 << 'EOF'
:il~target
:dm~target
:iE target.so~important
:dt `iEa target.so important_func`
:dtf `iEa target.so important_func` zz^
:dc
EOF

# Run with r2
r2 -i analyze.r2 frida://spawn/usb//com.target.app
```

## Debugging Techniques

### Breakpoint Workflow

```bash
# Set breakpoint
:db 0x12345678

# List breakpoints
:db

# Continue to breakpoint
:dc

# When hit, examine state
:dr        # registers
:dm.       # current memory region
px 64 @ sp # stack dump
px 64 @ x0 # buffer at arg0

# Single step (not directly supported, use Stalker)
:dc        # continue

# Remove breakpoint
:db- 0x12345678
```

### Crash Analysis

```bash
# If app crashes, get report
:dkr

# Output includes:
# - Signal info
# - Register state
# - Backtrace
# - Build info
```

### Thread Analysis

```bash
# List threads
:dpt

# Show registers for all threads
:dr

# Focus on specific thread
# (done through Frida script if needed)
```

## Integration Patterns

### Combining with Static Analysis

```bash
# 1. Static analysis first
r2 -A libtarget.so
afl > functions.txt
pdf @ sym.check_license > check_license.txt

# 2. Note offsets from static analysis
# check_license is at 0x1234

# 3. Dynamic analysis
r2 frida://spawn/usb//com.target.app

# 4. Get runtime base
:dm~target
# 0x7f5bf70000 r-x libtarget.so

# 5. Calculate runtime address
? 0x7f5bf70000 + 0x1234
# = 0x7f5bf71234

# 6. Hook at runtime address
:dtf 0x7f5bf71234 iii^
:dc
```

### r2pipe Integration

```python
#!/usr/bin/env python3
import r2pipe

# Connect to r2frida session
r2 = r2pipe.open("frida://spawn/usb//com.target.app")

# Get target info
info = r2.cmdj(":ij")
print(f"PID: {info['pid']}, Arch: {info['arch']}")

# Find libraries
libs = r2.cmd(":il")
for lib in libs.split('\n'):
    if 'target' in lib:
        print(f"Found: {lib}")

# Setup trace
r2.cmd(":dt strcmp")
r2.cmd(":dth strcmp z z")
r2.cmd(":dc")

# Continue interaction...
```

## Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| "Script is destroyed" | Process crashed, check `:dkr` |
| Empty output from `:iE` | Module not loaded yet, wait or use spawn |
| "Cannot attach" | Process running as different user, or protected |
| Frida version mismatch | Update both frida-server and r2frida |
| Commands not working | Use `:` prefix (not `\`) in current versions |

### Verification Steps

```bash
# Check Frida is working
:?V

# Check module is loaded
:il~modulename

# Check address is valid
:dm. @ 0xaddress

# Check function exists
:iEa libname funcname
```

### Debug Logging

```bash
# Enable verbose output
:e search.quiet=false

# Check configuration
:e

# Test with known good target
r2 frida://0
:i
```