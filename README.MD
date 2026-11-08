Platforms: Linux (/proc), macOS (Mach APIs), Windows (Win32 via ctypes).
Dependencies: Python 3.8+ standard library only. No subprocess, no shell.
 
Output, written to a NEW directory procdump_<pid>_<UTC timestamp>/ :
  memory.bin     every readable memory region, concatenated back to back
  manifest.json  host and process metadata, SHA-256 hashes, and a map of
                 virtual address -> offset in memory.bin for each segment
 
Run only on systems you are authorized to investigate, elevated
(root / Administrator). A memory dump can contain passwords, tokens and keys:
store it on encrypted or access-restricted storage and handle it as sensitive.
 
Limitations:
  * The process is not suspended, so memory can change while it is read.
  * Windows: use 64-bit Python to dump 64-bit processes.
  * macOS: task_for_pid is refused for Apple-signed and hardened processes
    (SIP / hardened runtime) even as root.
