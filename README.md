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

## Links
http://blog.talosintelligence.com/2017/10/cyber-conflict-decoy-document.html

http://www.securityweek.com/russian-fancy-bear-hackers-abuse-blogspot-phishing

http://www.securityweek.com/russia-linked-spies-deliver-malware-dde-attack

https://www.politico.eu/article/russian-hackers-fancy-bear-behind-leak-of-un-diplomats-email-report/
https://threatpost.com/latest-sofacy-campaign-targeting-security-researchers/128576/
http://www.informationsecuritybuzz.com/expert-comments/fancy-bear-hackers-race-exploit-flash-bug-us-europe/
https://www.tripwire.com/state-of-security/security-data-protection/microsoft-advisory-office-dde-malware/

https://www.wired.com/story/russia-fancy-bear-hackers-microsoft-office-flaw-and-nyc-terrorism-fears/?mbid=nl_110817_daily_list1_p3

https://www.bleepingcomputer.com/news/security/russian-cyberspies-carry-out-the-silliest-cyber-espionage-campaign-of-the-year/

http://www.bbc.com/news/technology-42056555

https://threatpost.com/latest-sofacy-campaign-targeting-security-researchers/128576/

https://fancybear.net/ - their site...

https://www.facebook.com/FancyBearsHackTeam1/ - appears to be taken down

https://twitter.com/FancyBears

https://www.darkreading.com/attacks-breaches/russias-fancy-bear-apt-group-gets-more-dangerous/d/d-id/1330702

http://www.securityweek.com/dhs-uses-cyber-kill-chain-analyze-russia-linked-election-hacks

http://www.securityweek.com/xtunnel-malware-specifically-built-dnc-hack-report

http://www.securityweek.com/russian-cyberspies-use-new-mac-malware-steal-data

https://www.threatconnect.com/blog/finding-nemohost-fancy-bear-infrastructure/

https://www.sans.org/summit-archives/file/summit-archive-1492179725.pdf

https://netzpolitik.org/2015/digital-attack-on-german-parliament-investigative-report-on-the-hack-of-the-left-party-infrastructure-in-bundestag/

https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/

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
