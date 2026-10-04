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