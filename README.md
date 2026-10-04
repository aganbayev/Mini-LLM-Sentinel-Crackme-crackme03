# Reverse Engineering & Unpacking: Custom Windows PE Protector (KaBan Crackme)
## Sample Identification & Metadata
* **Original File Name:** `0LLRi9C10LHQuCDQvNC10L3Rjw.exe`
* **Unpacked Output:** `unpacked_SCY.exe` / `custom_protector_unpacked.exe`
* **File Type:** PE32+ executable (Console) x86-64
* **MD5:** `63809c874f7ca1de998cecf519a5fe95`
* **SHA-256:** `269F66EB409A8076E60F9CF7402B6D5DBA94A33331D19BD2CD49DA220A769E53`
* **File Size:** ~1.04 MB (1,094,656 bytes)
* **Archive Password:** `infected`
## Executive Summary
This repository contains a technical reverse engineering write-up for a custom 64-bit Windows PE protector (`custom protector`). The target binary implements dynamic API resolution, memory protection manipulation, and anti-debugging mechanisms (`IsDebuggerPresent`) to obfuscate its execution flow. 

Through dynamic tracing, OEP discovery, IAT reconstruction, and binary patching, the underlying executable was fully restored (`unpacked_SCY.exe`) and analyzed in IDA Pro.

---

## Binary Technical Specifications
* **Architecture:** PE32+ (64-bit Executable)
* **Target String:** `"Reverse this shit, find where this message is printed."`
* **Toolchain:** PE-bear, x64dbg, Scylla x64 (v0.9.8), IDA Pro / IDA Free

---

## Technical Walkthrough

### 1. Static Triage & Import Inspection
Initial inspection using **PE-bear** revealed a modified PE header with obfuscated import tables. Standard static analysis tools were unable to resolve the complete WINAPI import list due to runtime packing.

![PE-bear Initial Analysis](images/1.png)
![PE-bear Initial Analysis](images/2.png)
![PE-bear Initial Analysis](images/3.png)

---

### 2. Dynamic Unpacking & OEP Discovery
The sample was executed inside **x64dbg** to trace the memory allocation and unpacking stub:
1. **Memory Permission Manipulation:** Set a breakpoint on `kernel32.VirtualProtect` to intercept memory allocation shifts to executable states (`PAGE_EXECUTE_READWRITE`).
2. **Unpacking Loop:** Executed until returning to the main module space (`CTRL + F9`), observing dynamic API resolution using `LoadLibraryExW` and `GetProcAddress`.
3. **Tail Jump:** Located the OEP transition at `0x00007FF7DE47944F` on a `ret` instruction. Single-stepping (`F7`) led directly to the CRT initialization routine at the Original Entry Point.

* **Discovered OEP (RVA):** `0x00007FF7DE478289`

![x64dbg OEP Transition](images/4.png)

---

### 3. IAT Reconstruction & Memory Dumping
With the process paused at OEP, **Scylla x64** was attached to rebuild the Import Address Table:
* **IAT Address / Size:** `0x00007FF7DE49AF08` / `0x0280`
* **Import Resolution:** Successfully resolved **80/80 valid API imports** (`KERNEL32.dll`) with `0` invalid entries.
* **Fix Dump:** Dumped the memory space and fixed the IAT structure, appending a new `.SCY` section (`Characteristics: 0xE0000600`) to create the clean executable (`unpacked_SCY.exe`).

![Scylla IAT Reconstruction](images/5.jfif)
![PE-bear Re-alignment Verification](images/6.png)

---

### 4. Anti-Debugging Bypass (Static Patching)
During static disassembly of `unpacked_SCY.exe` in **IDA Pro**, an anti-analysis routine was identified within `sub_7FF7DE477CC0`:
* The binary executed `call cs:IsDebuggerPresent` followed by conditional branch jumps (`jnz`, `jz`) to terminate execution under a debugger.
* **Bypass Strategy:** The conditional jump instructions were patched with **NOP (`0x90`)** opcodes, forcing execution flow into the main routine regardless of debugger presence.

![IDA Pro NOP Patching](images/7.png)
![IDA Pro NOP Patching](images/8.png)

---

### 5. Disassembly & Core Logic Analysis
Disassembling the unpacked binary in IDA Pro's Graph View revealed the core function (`sub_7FF7DE461340` / `main`):
* The routine loads the target string via `lea rdx, aReverseThisShi` (`"Reverse this shit, find where this message is printed."`).
* The string is passed to `sub_7FF7DE461530` for standard C++ `std::cout` console output.
* Analysis confirmed no secondary password checks, obfuscated license loops, or hidden flag validation routines exist—reversing the unpacking stub and isolating the console output call fulfilled the complete challenge objective.

![IDA Pro Core Logic Graph View](images/9.png)

---

## Detection Signature (YARA)

```yara
rule Custom_Protector_Unpacked {
    meta:
        description = "Detection rule for KaBan Custom Protector Crackme sample"
        author = "DeepDominance"
        date = "2026-10-04"
        sample_md5 = "63809c874f7ca1de998cecf519a5fe95"

    strings:
        // Unique Target String
        $s1 = "Reverse this shit, find where this message is printed." ascii
        
        // Import Artifacts
        $s2 = "KERNEL32.dll" ascii
        
        // Opcode Pattern: lea rdx, string followed by print function call
        $hex_pattern = { 48 8D 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 90 }

    condition:
        // Check for PE Header (MZ Magic Bytes)
        uint16(0) == 0x5A4D and 
        (
            $s1 or ($s2 and$hex_pattern)
        )
}