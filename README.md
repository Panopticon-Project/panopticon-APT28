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

https://www.wired.com/story/fancy-bear-hotel-hack/?mbid=nl_81117_p1&CNDID=50740756

http://www.ciol.com/russian-hackers-targeting-indian-hospitality-industry-for-user-data/

https://arstechnica.com/gadgets/2017/08/ukraine-malware-author-turns-witness-in-russian-dnc-hacking-investigation/

https://www.nytimes.com/2017/08/16/world/europe/russia-ukraine-malware-hacking-witness.html?smprod=nytcore-ipad&smid=nytcore-ipad-share

http://www.startribune.com/ukraine-malware-expert-may-blow-whistle-on-russian-hacking/440791753/

https://nakedsecurity.sophos.com/2017/08/15/fancy-bear-bites-hotel-networks-as-eternalblue-mystery-deepens/?utm_source=feedburner&utm_medium=feed&utm_campaign=Feed%3A+nakedsecurity+%28Naked+Security+-+Sophos%29

https://www.scmagazine.com/ukrainian-malware-author-is-key-witness-against-russia-in-dnc-hack-investigation/article/682137/

http://www.zdnet.com/article/us-election-hack-microsoft-wins-latest-round-in-court-against-fancy-bear-phishers/#ftag=RSSbaffb68

http://www.esecurityplanet.com/network-security/travelers-beware-russian-apt28-hackers-hit-hotels-in-europe-middle-east.html

https://www.tripwire.com/state-of-security/featured/german-parliament-malware-mystery/#new_tab

https://www.salon.com/2017/09/24/russian-hackers-exploited-a-google-flaw-and-google-wont-fix-it/

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
