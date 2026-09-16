rule SuspiciousPowerShell {
    meta:
        description = "Encoded or obfuscated PowerShell command"
        severity = "high"
        author = "Exploidus Labs"
    strings:
        $enc = "EncodedCommand" nocase
        $iex = "IEX(" nocase
        $b64 = "FromBase64String" nocase
        $bypass = "-ExecutionPolicy bypass" nocase
    condition:
        2 of them
}

rule ProcessInjection {
    meta:
        description = "Windows process injection APIs"
        severity = "high"
        author = "Exploidus Labs"
    strings:
        $a = "CreateRemoteThread"
        $b = "VirtualAllocEx"
        $c = "WriteProcessMemory"
        $d = "NtCreateThread"
    condition:
        2 of them
}

rule SuspiciousDownloader {
    meta:
        description = "File that downloads and executes payloads"
        severity = "medium"
        author = "Exploidus Labs"
    strings:
        $wget  = "wget " nocase
        $curl  = "curl " nocase
        $http  = "http://" nocase
        $https = "https://" nocase
        $exec  = "WinExec" nocase
        $shell = "ShellExecute" nocase
    condition:
        ($wget or $curl) and ($http or $https) and ($exec or $shell)
}

rule MimikatzStrings {
    meta:
        description = "Strings associated with the Mimikatz credential dumper"
        severity = "critical"
        author = "Exploidus Labs"
    strings:
        $a = "mimikatz" nocase
        $b = "sekurlsa" nocase
        $c = "lsadump" nocase
        $d = "privilege::debug" nocase
    condition:
        2 of them
}

rule MetasploitPayload {
    meta:
        description = "Common Metasploit/Meterpreter strings"
        severity = "critical"
        author = "Exploidus Labs"
    strings:
        $a = "meterpreter" nocase
        $b = "reverse_tcp" nocase
        $c = "bind_tcp" nocase
        $d = "payload" nocase
        $e = "shellcode" nocase
    condition:
        2 of them
}
