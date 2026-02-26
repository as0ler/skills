---
name: r2frida
description: Use this skill for dynamic binary analysis combining radare2 static analysis with Frida's runtime instrumentation. Triggers include any mention of r2frida, dynamic instrumentation, runtime analysis, memory hooking, function tracing,n runtime manipulation, live debugging, or combining radare2 with Frida. Also use when the user needs to trace function calls, hook native functions, dump memory at runtime, modify return values, search memory patterns in running processes, or analyze obfuscated mobile applications.
---

# r2frida Dynamic Analysis Guide

## Overview

r2frida is a radare2 plugin that bridges static analysis capabilities of radare2 with Frida's dynamic instrumentation. This allows you to analyze running processes, hook functions, trace calls, modify memory, and manipulate program execution in real-time.

**Important**: In current versions of r2frida, commands start with `:` (colon) instead of the legacy `\` (backslash). Both `=!` and `:` prefixes work, but `:` is preferred.

## Installation

```bash
# Install via radare2 package manager (recommended)
r2pm -ci r2frida

# Verify installation
r2 frida://0
:?V  # Should show Frida version
```

## Connection Methods

### URI Syntax

```
r2 frida://[action]/[link]/[device]/[target]

Actions: list | apps | attach | spawn | launch
Links:   local | usb | remote host:port
Device:  '' | host:port | device-id
Target:  pid | appname | process-name | program-path
```

### Local Process Analysis

```bash
# List local processes
r2 frida://

# Attach to frida-helper (test session, no spawn needed)
r2 frida://0

# Spawn a local binary
r2 frida:///usr/bin/ls
r2 "frida:///usr/bin/wget google.com"  # with arguments

# Attach to running process by PID
r2 frida://attach/local//1234

# Attach by process name
r2 frida://notepad.exe
```

### Android Device Analysis

```bash
# List processes on USB device
r2 frida://list/usb//

# List apps on USB device
r2 frida://apps/usb//

# Attach to running app by PID
r2 frida://attach/usb//12345

# Spawn app by package name
r2 frida://spawn/usb//com.target.app

# Spawn and resume immediately (launch)
r2 frida://launch/usb//com.target.app

# With specific device ID
r2 frida://spawn/usb/DEVICE_ID/com.target.app
```

### iOS Device Analysis

```bash
# List processes
r2 frida://list/usb//

# Spawn iOS app
r2 frida://spawn/usb//com.example.app

# Attach to Frida Gadget
r2 frida://attach/usb//Gadget
```

### Remote Frida Server

```bash
# Connect to remote frida-server
r2 frida://attach/remote/192.168.1.100:27042/target
```

## Core Commands Reference

### Getting Help

```
:?              Show all r2frida commands
:?V             Show Frida version as JSON
```

### Information Commands (`:i`)

```
:i              Target information (arch, bits, os, pid, etc.)
:i*             Target information in radare2 format
.:i*            Import target info into radare2 session

:il             List loaded libraries/modules
:il.            Show library at current offset

:ii             List all imports
:ii <lib>       List imports of specific library
:ii* <lib>      List imports in radare2 format

:iE             List all exports (WARNING: large output)
:iE <lib>       List exports of specific library
:iE* <lib>      Exports in radare2 format
.:iE* <lib>     Import exports as flags

:iEa <lib> <sym>    Get address of export symbol
:iEa* <lib> <sym>   Get address in radare2 format

:is <lib>       List symbols (local and global)
:isa <sym>      Get address of symbol
:isa <lib> <sym>    Get address of symbol in library
```

### Objective-C / Swift Commands

```
:ic             List all Objective-C classes
:ic <class>     List methods of class
:ic*            Classes in radare2 format

:ip             List all protocols
:ip <protocol>  List methods of protocol
```

### Java / Android Commands

```
:icj            List Java classes (Android)
:icj <class>    List methods of Java class
```

### Memory Commands (`:dm`)

```
:dm             Show memory regions (like /proc/PID/maps)
:dm.            Show memory region at current offset
:dm. @ addr     Show memory region containing address
:dmj            Memory regions as JSON
:dm*            Memory regions as radare2 flags

:dmm            List named/squashed maps
:dmh            List heap chunks
:dmhj           Heap chunks as JSON
:dmh*           Heap chunks as radare2 flags
:dmhm           Show maps used for heap allocation

:dma <size>     Allocate bytes on heap, returns address
:dmas <string>  Allocate string on heap, returns address
:dmad <addr> <size>  Allocate and copy from address
:dmal           List live allocations from dma/dmas
:dma- [addr]    Free allocation (all if no addr)

:dmp <addr> <size> <perms>  Change memory protection (rwx)
```

### Search Commands (`:\/`)

```
:\/ <string>    Search string in memory
:\/j <string>   Search with JSON output
:\/x <hex>      Search hex pattern
:\/xj <hex>     Search hex with JSON output
:\/w <string>   Search wide string (UTF-16)
:\/v4 <value>   Search 4-byte value
:\/v8 <value>   Search 8-byte value
```

### Debugging Commands (`:d`)

```
:dp             Show current PID
:dpt            List threads
:dr             Show thread registers

:db <addr|sym>  Set breakpoint
:db             List breakpoints
:db- <addr>     Remove breakpoint
:db- *          Remove all breakpoints
:dc             Continue execution / resume spawned process

:dd             List file descriptors
:dd- <fd>       Close file descriptor
:dd <fd> <newfd>  Duplicate file descriptor (dup2)
```

### Tracing Commands (`:dt`)

```
:dt <addr|sym>          Add trace at address/symbol
:dt- [addr]             Remove trace (all if no addr)

:dth <addr> <args>      Define trace with argument types
                        Types: z=string, i=int, v=hex array, s=byte array

:dtf <addr> <fmt>       Trace with format specifiers
:dtf?                   Show format help

:dtr <addr> <regs>      Trace register values

:dtSf <addr>            Trace with Stalker (code tracing)
:dtS <seconds>          Trace all threads with Stalker
```

#### Trace Format Specifiers (`:dtf`)

```
^       Trace onEnter instead of onExit
+       Show backtrace
p/x     Show pointer in hexadecimal
c       Show value as char
i       Show decimal integer
z       Show pointer to UTF-8 string
w       Show pointer to UTF-16 string
a       Show pointer to ANSI string
h       Hexdump from pointer (h16 = 16 bytes)
H       Hexdump with length from argument (H1 = args[1] bytes)
s       Show string in place
O       Show pointer to ObjC object
```

### Interceptor Commands (`:di`)

```
:di?            Interceptor help
:di0 <addr>     Make function return 0
:di1 <addr>     Make function return 1
:di-1 <addr>    Make function return -1
:dii <addr>     Intercept and return custom int
:dis <addr>     Intercept and return custom string
:div <addr>     Intercept as void

:dif0 <addr>    Replace function return with 0
:dif1 <addr>    Replace function return with 1
:dif-1 <addr>   Replace function return with -1
```

### Function Call Commands (`:dx`)

```
:dxc <addr> [args...]   Call function at address with arguments
:dxo <sel> [args...]    Call Objective-C method
:dxs <num> [args...]    Perform syscall
```

### Script Loading (`:\.`)

```
:. <script.js>      Load and run Frida script
:.                  List loaded plugins
:.- <name>          Unload plugin
:.. <script.js>     Eternalize script (survives detach)

:eval <code>        Evaluate JavaScript in agent
```

### Environment Variables

```
:env                List all environment variables
:env <var>          Get specific variable
:env <var>=<val>    Set variable
```

### Configuration (`:e`)

```
:e                  List evaluable variables
:e <var>=<val>      Set configuration

# Available variables:
patch.code=true         Enable code patching
search.in=perm:r--      Memory search permissions
search.quiet=false      Quiet search output
stalker.event=compile   Stalker event type
stalker.timeout=300     Stalker timeout
stalker.in=raw          Stalker input mode
```

### Library Loading

```
:dl <libname>       dlopen a library
:dl2 <libname>      Inject library (Frida >= 8.2)
```

## Practical Examples

### Example 1: Basic Target Analysis

```bash
# Get target info
:i

# Import info into r2
.:i*

# List loaded libraries
:il

# Find crypto libraries
:il~crypto
:il~ssl
```

### Example 2: Finding and Tracing Functions

```bash
# Find base address
:dm~wget
# Output: 0x560be7abb000 - 0x560be7b2e000 r-x /usr/bin/wget

# Seek to library
s 0x560be7abb000

# List exports
:iE~open
:iE~fopen

# Get fopen address from libc
:dm~libc
# Seek to libc and find fopen
:iE libc~fopen

# Trace fopen with symbol name
:dt <fopen_address> z^

# Trace fopen with address and format
:dtf <fopen_address> z^

```

### Example 3: Function Tracing with Arguments

```bash
# Trace fopen with string arguments
# z = string, ^ = trace onEnter, + = backtrace
:dtf 0x7ff0a9e37de0 zz^+

# Resume execution
:dc

# Output shows calls like:
# [TRACE] fopen("/etc/hosts", "r")
#   backtrace...
```

### Example 4: Tracing strcmp for Password Analysis

```bash
# Find strcmp
:dm~libc
:iEa libc.so strcmp

# Trace with two string arguments
:dt strcmp
:dtf strcmp zz

# Resume and watch comparisons
:dc
# [TRACE] strcmp("user_input", "secret_password")
```

### Example 5: Memory Search

```bash
# Search for string in memory
:\/ "root"

# Search for hex pattern
:\/x 7f454c46    # ELF magic

# Search for specific value (4-byte)
:\/v4 1234

# JSON output for parsing
:\/j "password"
```

### Example 6: Heap Manipulation

```bash
# Allocate string on heap
:dmas "injected_string"
# Returns: 0x7fd21c121cb0

# Allocate buffer
:dma 256

# List allocations
:dmal

# Free specific allocation
:dma- 0x7fd21c121cb0
```

### Example 7: Calling Functions Dynamically

```bash
# Find function address
:iEa libc.so system

# Allocate command string
:dmas "id"
# Returns: 0xaabbccdd

# Call system() with our string
:dxc 0x7f12345678 0xaabbccdd
```

### Example 8: Return Value Manipulation

```bash
# Find isJailbroken function
:ic~Jailbreak
:ic JailbreakDetection

# Get method address
:iEa AppBinary isJailbroken

# Make it always return 0 (false)
:di0 0x100123456

# Or use JavaScript interceptor
:eval Interceptor.attach(ptr(0x100123456), {onLeave: function(retval) {retval.replace(0x0)}})
```

### Example 9: iOS Class Analysis

```bash
# Spawn iOS app
r2 frida://spawn/usb//com.example.app

# Resume
:dc

# List Objective-C classes
:ic~ViewController

# List methods of a class
:ic LoginViewController

# Find method address
:iEa AppBinary "-[LoginViewController validatePassword:]"

# Trace the method
:dtf 0x100045678 O^
```

### Example 10: Android Native Library Analysis

```bash
# Spawn Android app
r2 frida://spawn/usb//com.target.app

# Find native library
:dm~libnative
# 0x7f5bf70000 - 0x7f5bf90000 r-x /data/app/.../lib/arm64/libnative.so

# List JNI exports
:iE libnative.so~JNI

# Trace JNI_OnLoad
:dt `iEa libnative.so JNI_OnLoad`
:dth `iEa libnative.so JNI_OnLoad` v
:dc
```

### Example 11: Anti-Debug Bypass

```bash
# Trace ptrace calls
:dt ptrace
:dth ptrace i i i i

# Make ptrace return 0
:di0 `iEa libc.so ptrace`

# For more complex bypass, use script
:. antiroot.js
:dc
```

### Example 12: Dynamic Disassembly

```bash
# Find function address
:dm~target
s 0x55bf4aefa000

# Calculate real address from offset
# base + offset
? 0x55bf4aefa000 + 0x71a

# Analyze function
af @ 0x55bf4aefa71a

# Disassemble
pdf @ 0x55bf4aefa71a
```

### Example 13: SSL Pinning Bypass Analysis

```bash
# Find SSL verification functions
:iE libssl~verify
:iE libssl~SSL_CTX

# Trace certificate validation
:dt SSL_CTX_set_verify
:dtf `iEa libssl.so SSL_CTX_set_verify` ii^+
:dc
```

### Example 14: Breakpoint Debugging

```bash
# Set breakpoint at function
:db `iEa libc.so strcmp`

# Resume execution
:dc

# When hit, inspect registers
:dr

# Continue
:dc

# Remove breakpoint
:db- `iEa libc.so strcmp`
```

### Example 15: Custom Frida Script Integration

```javascript
// agent.js - Example r2frida plugin
r2frida.pluginRegister('myhook', function(name) {
    if (name === 'myhook') {
        return function(args) {
            var target = args[0];
            Interceptor.attach(ptr(target), {
                onEnter: function(args) {
                    console.log("Called with: " + args[0]);
                },
                onLeave: function(retval) {
                    console.log("Returned: " + retval);
                }
            });
            return "Hook installed at " + target;
        }
    }
});
```

```bash
# Load the plugin
:. agent.js

# Use it
:myhook 0x12345678
```

## Workflow Tips

### Importing Dynamic Data to radare2

```bash
# Import all target info
.:i*

# Import exports as flags
.:iE* libtarget.so

# Import imports as flags  
.:ii* libtarget.so

# Now use standard r2 commands
afl        # list functions
pdf @ sym.func  # disassemble
```

### Using r2 Internal Grep

```bash
# Filter output with ~
:il~ssl                    # libraries containing "ssl"
:dm~r-x                    # executable memory regions
:iE libc~strcmp            # exports containing "strcmp"
:ic~View                   # classes containing "View"

# Column selection
:dm~ssl[0]                 # first column only (address)
:iE libc~open[0,2]         # columns 0 and 2
```

### Combining Static and Dynamic Analysis

```bash
# 1. Analyze statically first
r2 -A target.so
afl  # list functions
pdf @ main  # get offsets

# 2. Then use r2frida dynamically
r2 frida://spawn/usb//com.target.app

# 3. Calculate runtime addresses
:dm~target.so  # get base address
# real_addr = base + static_offset
```

## Error Handling

```bash
# Check if Frida is working
:?V

# If script errors
:dkr    # Print crash report

# Verify module loaded
:il~module_name

# Check if address is valid
:dm. @ 0xaddress
```

## Security Research Patterns

### Root/Jailbreak Detection Bypass

1. Find detection functions via class/method enumeration
2. Trace to confirm they're called
3. Use `:di0` or `:di1` to manipulate returns
4. Or load comprehensive bypass script

### Certificate Pinning Analysis

1. Find SSL/TLS related exports
2. Trace verification functions
3. Identify where pinning occurs
4. Hook and modify as needed

### Native Library Analysis

1. Find library load address with `:dm`
2. List exports with `:iE`
3. Trace interesting functions with `:dtf`
4. Analyze call patterns and arguments

## Quick Reference Card

| Task | Command |
|------|---------|
| Show help | `:?` |
| Target info | `:i` |
| List libraries | `:il` |
| List exports | `:iE <lib>` |
| Find export address | `:iEa <lib> <sym>` |
| Memory map | `:dm` |
| Search string | `:\/ <str>` |
| Allocate string | `:dmas <str>` |
| Trace function | `:dtf <addr> <fmt>` |
| Set breakpoint | `:db <addr>` |
| Continue | `:dc` |
| Call function | `:dxc <addr> [args]` |
| Return 0 | `:di0 <addr>` |
| Return 1 | `:di1 <addr>` |
| Load script | `:. script.js` |
| Eval JS | `:eval <code>` |