# Agent Skills

A collection of agent skills for reverse engineering and dynamic instrumentation: radare2, Frida, and r2frida.

## Skills

| Skill   | Description |
|--------|-------------|
| **radare2** | Reverse engineering and binary analysis with r2: analyze executables (ELF, PE, Mach-O), disassemble, decompile (r2ghidra), extract imports/exports/strings, patch binaries, and debug. |
| **frida**   | Frida 17.x instrumentation: writing and debugging Frida scripts for iOS ARM64 and Android, hooking, Interceptor, Stalker, ObjC/Java bridges, SSL pinning bypass, and related tooling. |
| **r2frida** | Dynamic analysis combining radare2 with Frida: attach to running processes, hook functions, trace calls, dump memory, and analyze obfuscated or live targets. |
| **unreal5** | Unreal Engine 5 internal structures and memory layouts: UObject hierarchy, FNamePool, FUObjectArray, FProperty system, UFunction, FField, GWorld, Large World Coordinates, and key enums/flags for UE5 RE. |

Each skill lives in its own directory with a `SKILL.md` (and optional `REFERENCE.md` / `EXAMPLES.md`).

## Structure

```
agent-skills/
├── radare2/       # r2 binary analysis
│   ├── SKILL.md
│   ├── EXAMPLES.md
│   └── REFERENCE.md
├── frida/         # Frida instrumentation
│   ├── SKILL.md
│   ├── REFERENCE.md
│   └── EXAMPLES.md
├── r2frida/       # radare2 + Frida
│   ├── SKILL.md
│   ├── EXAMPLES.md
│   └── REFERENCE.md
├── unreal5/       # Unreal Engine 5 structures & memory layouts
│   └── SKILL.md
├── README.md
└── LICENSE
```

## Using These Skills

1. Add this repo (or a copy of it) to your skills location.
2. Reference a skill in chat when you want that expertise, e.g. “use the radare2 skill to analyze this binary” or “with the frida skill, write a hook for …”.
3. Skills are applied when the agent follows the instructions and triggers defined in each `SKILL.md`.

## License

See [LICENSE](LICENSE).
