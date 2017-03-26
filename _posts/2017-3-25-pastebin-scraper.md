---
layout: post
title: Need a malware? No problem, I'll copy it on pastebin
---

We can find many different means for malwares to spread: just to name a couple, the evergreen of email spam, with that nasty _invoice.pdf.exe_ attachment, or some Viagra malvertising leading to an Exploit Kit.  But malware authors also look for more "unusual" ways to move around their products. A very interesting one is [pastebin](http://pastebin.com/), the well-known service to quickly distribute chunks of text online. The idea of monitoring pastebin comes from [sudosev](https://twitter.com/sudosev), who proposed to look for Base64 encodings of Windows executables (i.e. PE files) among the content that goes through pastebin. To achieve this goal he used used [pastemonitor](https://www.pastemonitor.com): the name is self-explanatory, this service stores pastes and allows the user to look for specific strings or regular expressions. sev perfomed the analysis manually, so I decided to take his very good idea and automatize it.

## Hunting the samples
First of all, a detailed description of the monitoring procedure. As it is universally known (to the malware hunters at least), Windows executable start with a signature of two characters, **MZ**. To be precise this is actually the signature of MS-DOS executables, which was used for backward compatibility back in the days. Our goal is to catch any paste that contains the Base64 encoding of this signature. Base64 is a format that encodes a group of 3 bytes into a group of 4 characters, therefore we need an additional byte after our MZ sequence. It turns out there are only 6 possible choices of bytes after the signature, which means that the encoding of the signature is matched by 6 different sequences. The following regular expression summaries all the possibilities:

<center>TV(oA|pB|pQ|qQ|qA|ro)</center>

This regular expression is fed to PasteMonitor in order to find any matching pastes among those that are stored.

{: .center}
![Matches]({{ site.baseurl }}/images/2017-3-25-pastebin-scraper/matches.png)

Here is an example of the results from PasteMonitor, which has the very useful feature of keeping a copy of the paste, allowing us to analyze it even if the corresponding element in pastebin has been deleted.

We can decode the pastes and do whatever we want with them, e.g. scan them with VirusTotal.

{: .center}
![Scan]({{ site.baseurl }}/images/2017-3-25-pastebin-scraper/scan.png)

## Automation

Once the regular expression is set and matches start coming, the remaining work is tedious and repetitive. The solution to any tedious and repetive job? Automation!
Unfortunately, PasteMonitor is not really bot-frendly (yet!) as it does not provide any API to access the results of the monitoring. This fact made me opt for **mechanize**, a Python library for "stateful programmatic web browsing" ([github](https://github.com/python-mechanize/mechanize)). With this I created a script to log in PasteMonitor and go through all the matches' links, basically like a human would do. Decoded binaries are both stored locally and scanned using VirusTotal API.

To put some order in the findings and make future analysis quicker I decided to store results in a simple SQLite database, containting basic information such as scan rate and example naming.

{: .center}
![Scan]({{ site.baseurl }}/images/2017-3-25-pastebin-scraper/database.png)

## Results

So far the research is surprisingly prolific. In just three days, **110 pastes** were caught by PasteMonitor, leading to **88 unique malicious binaries**. One more interesting result is the low amount of false positives, i.e. pastes which matched the regular expression but were not Base64 encoded executables. Of the 110, only **5 were FP** (4.55%).
As far as the malware types and families are concerned, the vast majority is made of .NET trojans, with just a little presence of Win32 executables. In particular samples of the Bladabindi family are the most numerous.

Considering how well this research has started, I will keep on with it, hoping that a longer period of time will give more interesting results, maybe with the possibility of identifying trends in the malware presence over pastebin.

In case anyone is interested, [here](https://github.com/mauronz/malware_analysis/tree/master/pastebin_scraper) is the source code for the automated process. Make sure to put the needed information in the configuration file.
