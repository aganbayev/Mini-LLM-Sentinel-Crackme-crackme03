rule KamilLLM_Sentinel_Crackme03
{
    meta:
        description = "Detection rule for kamil123's 'Mini LLM Sentinel' crackme (crackme03)"
        author      = "DeepDominance"
        date        = "2026-10-08"
        reference    = "Crackme #3 - Mini LLM Sentinel"

    strings:
        // Challenge banner / narrative strings
        $banner1 = "Crackme #3 - Mini LLM Sentinel" ascii
        $banner2 = "An embedded language model guards this program." ascii
        $banner3 = "Note : defeating the sentinel is allowed - it is part of" ascii

        // Sentinel / AI verdict strings
        $ai1 = "[AI] sentinel armed." ascii
        $ai2 = "[AI] sentinel verdict: HOSTILE ENVIRONMENT detected!" ascii
        $ai3 = "[AI] shutting down." ascii
        $ai4 = "language-model verdict" ascii
        $ai5 = "[llm] sensor details: %s" ascii
        $ai6 = "[llm] inconclusive after rescan - treating as clean" ascii

        // Outcome strings
        $out1 = "[+] ACCESS GRANTED - you beat the LLM sentinel. Well done!" ascii
        $out2 = "[-] Wrong password." ascii
        $out3 = "[-] Too many failed attempts. Goodbye." ascii
        $out4 = "Enter password:" ascii

        // Debug/self-test environment variables
        $env1 = "CRACKME_AI_VERBOSE" ascii
        $env2 = "CRACKME_LLM_SELFTEST" ascii

        // Import artifact
        $imp = "KERNEL32.dll" ascii

    condition:
        uint16(0) == 0x5A4D and
        (
            2 of ($banner*) or
            3 of ($ai*) or
            (2 of ($out*) and $imp) or
            all of ($env*)
        )
}