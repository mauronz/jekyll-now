---
layout: post
title: "A hook to rule them all: Flare-On 5 - challenge 9"
---

Flare-On is one of the most challenging CTFs of the year when it comes to reverse engineering. In this post I will present an approach to solve level 9 based on hooking program functions with the aid of my library [APIhooklib](https://github.com/mauronz/APIhooklib){:target="_blank"}. This will not be a complete solution, the focus will be on the decryption of the VB script, which I consider the hardest part to tackle in this challenge. For a full walkthrough I recommend the one posted by the Flare team itself ([link](https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/2018_flareon_writeup_mykill_leet_editr.pdf){:target="_blank"}).

## The challenge

First, a quick summary of the challenge. The program writes an encrypted shellcode in a dynamically allocated memory region, which is then set to `PAGE_NO_ACCESS` permission. The same is done for an encrypted VB script. A vectored exception handler is registered before calling the encrypted shellcode. Since the memory region of the shellcode has no access permissions, an exception is triggered, causing the exception handler to execute. The handler decrypts the current instruction and resumes the normal execution. The instruction is executed, after that a `EXCEPTION_SINGLE_STEP` exception is thrown. Once again the exception handler kicks in, this time re-encrypting the instruction. This mechanism makes sure that only one instruction is "in clear" at any given time. The shellcode performs the following actions: set up a COM class, create three objects of that class (later used by the VB script), run the VB script. When the system library tries to parse the encrypted VB script in the `PAGE_NO_ACCESS` region, the same mechanism as before decrypts it on the fly.

The big difference between the shellcode and the VB script is in the encryption: the shellcode is encrypted with a single-byte XOR (`0xFE`), which is pretty simple to identify either by reversing the encryption routine or with a bit of bruteforcing; the script, on the other hand, is encrypted with a combination of ciphers, making the static approach a real pain. Even with dynamic analysis things do not look pretty, because running the program inside a debugger becomes a constant fight against the continuous exceptions. 

The solution presented by the Flare team leverages the possibility of disabling specific exceptions in WinDbg. Since I was oblivious to this feature, I came up with a solution that revolves around setting hooks on the encryption/decryption routine.

### The exception handler

To better understand my approach we need to take a closer look at the heart of the problem, the exception handler. Its structure is almost symmetrical: one half handles `EXCEPTION_ACCESS_VIOLATION`, for the decryption; the other handles `EXCEPTION_SINGLE_STEP`, for re-encryption. 

{: .center}
![VM directory]({{ site.baseurl }}/images/2018-11-10-flareon-apihooklib/handler.jpg)

There is a single routine for decryption and encryption of both the shellcode and the VB script. It accepts four parameters:
- global data structure: not interesting for us
- target address: address of the data to encrypt/decrypt
- algorithm flag: binary flag to choose between the shellcode algorithm and the script algorithm
- encryption/decryption flag: binary flag to decide which operation to perform

{: .center}
![VM directory]({{ site.baseurl }}/images/2018-11-10-flareon-apihooklib/ida.jpg)

The image shows the section of the exception handler that performs the decryption and adjusts the protection of the memory region. In both cases the 4th parameter is 0 (meaning decryption). The call that has the 3rd paramater set to 0 (red arrow), is followed by a `PAGE_EXECUTE_READ`, so we expect it to be for the shellcode. On the other hand, the call with the 3rd parameter set to 1 (green arrow) is followed by a `PAGE_READONLY`, which is enough for the parsing of the VB script. Keep in mind this information as it will be used in our hooks.

## APIhooklib

A couple of words to describe APIhooklib. It is a static library that contains routines to set hooks on any function of the local process, either by address or by name (API functions). Hooks can be set before and/or after the execution of the target function. Moreover, the return value can be overridden and the execution of the function itself can be inhibited. The main use case is inside a DLL which is loaded by/injected into the target process.
For more technical details, here is the [blogpost]({{ site.baseurl }}/apihooklib) about APIhooklib. Note that it refers to a previous version of the library, but the core mechanisms remain the same.

## Hooking the decryption routine

The goal is to "intercept" the bytes of the script between decryption and re-encryption. This can be achieved by either setting a hook after `cipher_routine` is executed for decryption or before it is executed for encryption. Here we have an example of the former. To have an idea of how many bytes are accessed in each iteration, we log the target address: 

```c
VOID __stdcall ah_Encryption(
  LPVOID arg1,
  BYTE *targetAddr,
  DWORD isVBScriptAlgo,
  DWORD isEncryption,
  DWORD retvalue
) {
  CHAR line[1024];
  HANDLE hFile;
  DWORD dwBytes;
  if (isVBScriptAlgo == 1 && isEncryption == 0) {
    wsprintfA(line, "%08x\n", targetAddr);
    hFile = CreateFileA("addr_log.txt", GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    SetFilePointer(hFile, 0, NULL, FILE_END);
    WriteFile(hFile, line, lstrlenA(line), &dwBytes, NULL);
    CloseHandle(hFile);
  }
}
```

(The hook routine has the same prototype of the hooked function, plus an additional parameter for the return value)

The content of *addr_log.txt* is something like this:

{: .center}
001d0000  
001d0004  
001d0004  
001d0006  
001d0008  
001d000a  
001d000c  
001d000e  
001d0010  
001d0012    
...

With the exception of the first, each cycle accesses two bytes. In hindsight this makes sense, since the script is encoded in UTF-16, which means that each character is stored in two bytes.  
Note: there are also some reads at odd addresses. I cannot explain them, but we can just filter them out.

At this point we add also the two bytes to the log.

```c
VOID __stdcall ah_Encryption(
  LPVOID arg1,
  BYTE *targetAddr,
  DWORD isVBScriptAlgo,
  DWORD isEncryption,
  DWORD retvalue
) {
  CHAR line[1024];
  HANDLE hFile;
  DWORD dwBytes;
  if (isVBScriptAlgo == 1 && isEncryption == 0) {
    wsprintfA(line, "%08x %02x %02x\n", targetAddr, targetAddr[0], targetAddr[1]);
    hFile = CreateFileA("log.txt", GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    SetFilePointer(hFile, 0, NULL, FILE_END);
    WriteFile(hFile, line, lstrlenA(line), &dwBytes, NULL);
    CloseHandle(hFile);
  }
}
```

Finally we feed *log.txt* to a Python script to build the VB script:

```python
with open("log.txt", "r") as f:
  # sort entries by address
  lines = sorted(f.read().split("\n"))

last = 0
res = ""
for line in lines:
  split = line.split(" ")
  addr = int(split[0], 16)
  # avoid odd addresses and repeating same bytes multiple times
  if addr % 2 == 0 and addr != last:
    last = addr
    res += (split[1] + split[2]).decode("hex")

with open("decoded.txt", "wb") as f:
  f.write(res)
```

And get our desired result.

{: .center}
![VM directory]({{ site.baseurl }}/images/2018-11-10-flareon-apihooklib/decoded.jpg)

I will leave here a link to the DLL project: [https://github.com/mauronz/CTF_stuff/tree/master/2018_flareon/9/injector](https://github.com/mauronz/CTF_stuff/tree/master/2018_flareon/9/injector){:target="_blank"}

It is pretty straight forward to use:

{: .center}
rundll32.exe injector.dll inject *path_to_exe.exe args*

`inject` creates a new suspended process with the given executable and arguments, then it loads the DLL in it via thread injection and finally resumes the process execution. The required hooks are set in `DllMain`.

## Conclusion

This was a very simple example of practical usage of APIhooklib. If you, like myself, like playing with code instrumentation and you are looking for a lightweight alternative to PIN, consider trying it. Just use the DLL project as a base template for whatever tool you want to build. For any question, suggestion, contact me on Twitter. Also, if by any chance you are reading this but haven't tried the Flare-On challenge, please go for it. It is an awesome mental gym and a source of valuable study material.