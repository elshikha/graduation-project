/*
    Academic Malware Intelligence Pipeline - YARA Rules
    Focus: Generic Behavior Enrichment
    Constraint: Frozen at 4 Behaviors
*/

rule Behavior_Process_Injection {
    meta:
        description = "Detects cross-process memory manipulation APIs."
        behavior = "process_injection"
    strings:
        $api1 = "VirtualAllocEx"
        $api2 = "WriteProcessMemory"
        $api3 = "CreateRemoteThread"
        $api4 = "NtWriteVirtualMemory"
    condition:
        uint16(0) == 0x5A4D and 2 of ($api*)
}

rule Behavior_Persistence_Mechanism {
    meta:
        description = "Detects combination of registry and service-based persistence."
        behavior = "persistence"
    strings:
        // Registry indicators
        $reg1 = "\\CurrentVersion\\Run" nocase
        $reg2 = "RegSetValueEx"
        
        // Service indicators
        $svc1 = "CreateService"
        $svc2 = "StartServiceCtrlDispatcher"
    condition:
        uint16(0) == 0x5A4D and (any of ($reg*)) and (any of ($svc*))
}

rule Behavior_Anti_Analysis {
    meta:
        description = "Detects environment or debugger detection strings and APIs."
        behavior = "anti_analysis"
    strings:
        $d1 = "IsDebuggerPresent"
        $d2 = "CheckRemoteDebuggerPresent"
        $d3 = "VMware" nocase
        $d4 = "VBOX" nocase
    condition:
        uint16(0) == 0x5A4D and 1 of ($d*)
}

rule Behavior_Packing_Obfuscation {
    meta:
        description = "Detects common section names for software packers."
        behavior = "packing_obfuscation"
    strings:
        $p1 = ".UPX"
        $p2 = ".aspack"
        $p3 = ".nspack"
    condition:
        uint16(0) == 0x5A4D and 1 of ($p*)
}
