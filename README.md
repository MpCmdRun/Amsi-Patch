# Amsi Memory Patch

Type: In-memory runtime patch

Target: AmsiScanBuffer function (inside amsi.dll)

Patch Action: Overwrites function prologue with custom bytes

Patch Payload: Forces the function to immediately return an error code instead of scanning the buffer

Architecture: Supports x64 and x86

Persistence: Temporary (Process-Only non Permenant)

Purpose: Disable AMSI scanning for that process only

This could end up being used for other projects such as in crypter's where it is needed.

# What Happens inside memory

When your process loads amsi.dll it brings in AmsiScanBuffer which normally scans memory buffers for malware
signatures.

This overwrites the beginning of AmsiScanBuffer with these assembly instructions
(x64 example)

```asm
mov eax, 0x80070057    ; Move "Invalid Argument" error code into eax
mov rax, [rsp]         ; Grab original return address
add rsp, 8             ; Clean stack
jmp rax                ; Jump back (exit early)
```

meaning: instead of scanning anything it just immediatly returns an error and windows defender just gives up checking.

Name for technique: AMSI Bypass, AMSI Patch, In-memory AMSI Hook

# Detections

Most EDR's will monitor if VirtualProtect is used suspciously on amsi.dll
But normal Windows Defender usually won't catch this

Now when I did my scan I was very surprised to see the results that it bypasses ESET, ThreatDown and Many more (I was expecting only defender)

![image](https://github.com/user-attachments/assets/2808e3f7-da38-4eab-abc5-0ca267709037)

