---
layout: post
title: "whack-a-proc: catch hidden executables as they are injected"
---

Nowadays it is fairly common for malware authors to use some form of process injection. The real malicious PE file (dll or exe) is hidden beneath one or more layers of wrappers which try to execute it as stealthly as possible, for example by injecting it in a seemingly harmless process. There is a wide variety of techniques to achieve process injection (check out this nice [summary](https://www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process)). For malware analysts the external layers of protection are just a nuance, and the most interesting code is in the final executable that is injected, so getting to it as quickly as possible is a primary goal. That is why I wanted to automate as much as possible the extraction procedure, for which I built a tool called **whack-a-proc**.

<br />
<br />

## whack-a-proc

The idea behind *whack-a-proc* is fairly simple: we let the external layer decrypt/unpack its payload and inject it in a target process, and then just before its execution, we dump it from the process memory. This is actually one of the most common approaches used during manual analysis.  
*whack-a-proc* is built on top of two components:

- [APIhooklib](https://github.com/mauronz/APIhooklib) - a library I have developed that allows to set inline hooks before and after the execution of target functions. 
- [pe-sieve](https://github.com/hasherezade/pe-sieve) - a powerful scanning tool created by [hasherezade](https://twitter.com/hasherezade), which analyzes the memory of a target process in order fo find suspicious implants, such as rogue loaded modules, shellcode or hooks.

As an example we can take the case of process hollowing:

1. The injector process creates a new suspended process with a harmless image (for example *svchost.exe*).
2. It then unmaps the original image from the process memory and replaces it with the malicious PE file.
3. Finally it resumes the main thread of the target process.

The new process appears to be a normal *svchost.exe* from the outside, while it is actually executing malicious code.

*whack-a-proc* puts itself in between point 2 and 3 by hooking a set of low level system APIs in order to scan the target process before its execution is resumed.

{: .center}
![VM directory]({{ site.baseurl }}/images/2019-03-11-whack-a-proc/scheme.jpg)

<br />
<br />

Lets see a couple of examples with real malware samples.

## Practical cases

### Kronos

Sample: [2a550956263a22991c34f076f3160b49](https://www.hybrid-analysis.com/sample/8389dd850c991127f3b3402dce4201cb693ec0fb7b1e7663fcfa24ef30039851?environmentId=100)

Kronos is an infamous banking trojan which first appeared in 2014. The sample we will look at is from 2017. This malware uses the already mentioned technique of process hollowing. If we take a look at the report of Hybrid Analysis, we can see that it creates a new process of itself, and then a new *svchost* process.

{: .center}
![VM directory]({{ site.baseurl }}/images/2019-03-11-whack-a-proc/ha-kronos.jpg)

In this case the ability of *whack-a-proc* to monitor subprocesses as well becomes handy.
Here it is in action:

{: .center}
![VM directory]({{ site.baseurl }}/images/2019-03-11-whack-a-proc/kronos.gif)

In each folder *pe-sieve* writes the suspicious PE file if has found, together with a JSON report. In the first subprocess (2328) an executable of 290 KB is injected. Instead in the second one (3120) we get two different PE files. The first is the same as the previous, meaning that it is injected also in the *svchost* process; the second one, of only 21 KB, is actually the real *svchost.exe* image, which is still in the process memory because the malware does not bother unmapping it.

### Osiris

Sample: [5e6764534b3a1e4d3abacc4810b6985d](https://www.hybrid-analysis.com/sample/e7d3181ef643d77bb33fe328d1ea58f512b4f27c8e6ed71935a2e7548f2facc0?environmentId=100)

Osiris is a newer version of Kronos that uses a more advanced injection technique known as [process doppelganging](https://www.blackhat.com/docs/eu-17/materials/eu-17-Liberman-Lost-In-Transaction-Process-Doppelganging.pdf). This technique makes use of transactions, a feature of NTFS that allows to group together a set of actions on the file system, and if any of those actions fails, a complete rollback occurs. The injector process creates a new transaction, inside of which it creates a new file containing the malicious payload. It then maps the file inside the target process and finally rolls back the transaction. In this way it  appears as if the file has never existed, even though its content is still inside the process memory.

{: .center}
![VM directory]({{ site.baseurl }}/images/2019-03-11-whack-a-proc/osiris.gif)

In this case we can see that the malware creates a new *wermgr.exe* process (3752) and it injects its payload in it. Once again the malicious second stage is dumped from memory.


## About the project 

At the moment *whack-a-proc* supports only the x86 architecture.  
Binaries are available [here](https://github.com/mauronz/malware_analysis/tree/master/whack_a_proc/Release).  
If you want to check out the source code, you can find it on [GitHub](https://github.com/mauronz/malware_analysis/tree/master/whack_a_proc).