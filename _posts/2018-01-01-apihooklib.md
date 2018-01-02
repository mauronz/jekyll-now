---
layout: post
title: "API call inspection with APIhooklib"
---

[Github repository](https://github.com/mauronz/APIhookerlib/)

Windows API hooks are among the best friends of infosec people. For example, bad guys use them for stealing information or hiding their files/processes; on the other hand they are found in security tools to detect malicious behaviors. 

There is a number of tools and frameworks for this job, with different features and scopes. I would like to cite two of them: [APIMonitor](http://www.rohitab.com/apimonitor)  is extremely useful to get both the input and the output of an API call, but lacks the possibility of setting custom hooks. [Pin](https://software.intel.com/en-us/articles/pin-a-dynamic-binary-instrumentation-tool), the Intel dynamic binary instrumentation framework, is powerful, as it allows to perform analysis at a very low level, even for each instruction that is executed. Unfortunately this power comes at the price of performances, as Pin instroduces a considerable overhead in the execution. Moreover, as personal critic, developing  programs that use Pin (aka Pin Tools) is not exactly straightforward. 

My goal for APIhooklib was to have an instrument that stands in between these two, which means custom hooks, low overhead and simple development.  

## Features

The workflow of a tool that uses APIhooklib is simple and occurs inside the memory of a single process (no remote hooks yet):

1. Set the desired hooks for any API function
2. Load the executable under test, with relocation and import table resolution
3. Jump to the entry point of the loaded executable

As of now a single function performs all the operations regarding hooks. Here is the prototype:

```c
FARPROC set_hook(
	LPSTR dll_name, 
	LPSTR func_name, 
	DWORD n_args, 
	FARPROC before_hook, 
	FARPROC after_hook,
	BOOL do_call,
	BOOL override_ret
);
```
Required information:

- DLL name
- function name
- number of arguments it accepts. 

It is possible (not mandatory) to set hooks both before the API call and right after it. `before_hook` has the same prototype of the API function, so that it can inspect the arguments passed to it. `after_hook` has once again the same prototye, plus one more argument which is the return value. An example of hooks for `ReadFile`:

```c
BOOL __stdcall before_hook_ReadFile(
	HANDLE       hFile,
	LPVOID       lpBuffer,
	DWORD        nNumberOfBytesToRead,
	LPDWORD      lpNumberOfBytesRead,
	LPOVERLAPPED lpOverlapped
);

BOOL __stdcall after_hook_ReadFile(
	HANDLE       hFile,
	LPVOID       lpBuffer,
	DWORD        nNumberOfBytesToRead,
	LPDWORD      lpNumberOfBytesRead,
	LPOVERLAPPED lpOverlapped,
	BOOL         returnValue
);
```

**Note**: both callbacks must use the **stdcall** calling convention - the same of API functions.

If `do_call` is true, the API is actually called, instead if it is false it is completely bypassed.
Finally it is possible to override the return value. If that flag is true, the return value for the caller will be the return value of the last executed hook. Note that if no hook is set, the return value is undetermined and can cause an unkown behavior in the caller.

`set_hook` returns the address of the trampoline that is needed to call the API function without hooks. This is necessary if the function is used in any of the other hooks. For example, if we hook `WriteFile` and we want to log function calls in a file, we cannot write in it calling directly `WriteFile`, otherwise we would log also those calls; instead the correct way to do it is to call the trampoline returned by `set_hook`.

## Overview of the internal mechanism

A (hopefully understandable) general scheme:

{: .center}
![VM directory]({{ site.baseurl }}/images/2018-01-01-apihooklib/apihooklib_scheme.jpg)

The first thing to mention is that the library uses inline hooks, which allow to "find" also calls to functions that are resolved at runtime. Since my main field of operation is malware analysis, this is a mandatory requirement because malware usually hide the API functions they need, so that they do not appear in the import table of the executable.  
The inline hook redirects the execution to a stub that is generated at runtime. Its code depends on the parameters of `set_hook`, but in general its role is to perform three calls, to the before-hook, the API trampoline (i.e. the function itself) and to the after-hook. Finally it returns back to the original caller.

## A simple example

The following example displays **net_hook**, a simple tool based on APIhooklib which hooks the Windows socket API, specifically `socket`, `connect`, `send` and `recv`. Important information for each function is printed out, and for `recv`, the received data is overwritten with "Nope!!".
The program under test is PuTTY, performing a raw socket connection to an echo server.

{: .center}
![VM directory]({{ site.baseurl }}/images/2018-01-01-apihooklib/net_example.gif)

## External components of APIhooklib

- Inline hooks use [this code](https://github.com/MalwareTech/BasicHook) by MalwareTechBlog
- The loading of the executable and its execution are done via [libpeconv](https://github.com/hasherezade/libpeconv) by hasherezade

## Future developments

- Support to x64 architecture
- Generalization of the hooking process to any function inside the executable under test, assuming its address and calling convention are known
- Actually useful tools that use this library

The library is in a very early alpha state, but I still wanted to release it to get some feedback and ideas. If you have any, feel free to contact me [on twitter](https://twitter.com/FraMauronz).
