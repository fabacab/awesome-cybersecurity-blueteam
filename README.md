# Awesome Cybersecurity Blue Team [![Awesome](https://awesome.re/badge-flat2.svg)](https://awesome.re)

> A collection of awesome resources, tools, and other shiny things for cybersecurity blue teams.

[Cybersecurity blue teams](https://en.wikipedia.org/wiki/Blue_team_(computer_security)) are groups of individuals who identify security flaws in information technology systems, verify the effectiveness of security measures, and monitor the systems to ensure that implemented defensive measures remain effective in the future. While not exclusive, this list is heavily biased towards [Free Software](https://www.gnu.org/philosophy/free-sw.html) projects and against proprietary products or corporate services. For offensive TTPs, please see [awesome-pentest](https://github.com/fabacab/awesome-pentest).

Your contributions and suggestions are heartily♥ welcome. (✿◕‿◕). Please check the [Contributing Guidelines](CONTRIBUTING.md) for more details. This work is licensed under a [Creative Commons Attribution 4.0 International License](http://creativecommons.org/licenses/by/4.0/).

## Contents

- [Automation](#automation)
- [Cloud platform security](#cloud-platform-security)
- [Communications security (COMSEC)](#communications-security-comsec)
- [DevSecOps](#devsecops)
  - [Application or Binary Hardening](#application-or-binary-hardening)
  - [Fuzzing](#Fuzzing)
  - [Policy enforcement](#policy-enforcement)
- [Honeypots](#honeypots)
  - [Tarpits](#tarpits)
- [Host-based tools](#host-based-tools)
  - [Sandboxes](#sandboxes)
- [Incident Response tools](#incident-response-tools)
  - [IR management consoles](#ir-management-consoles)
  - [Evidence collection](#evidence-collection)
- [Network perimeter defenses](#network-perimeter-defenses)
  - [Firewall appliances or distributions](#firewall-appliances-or-distributions)
- [Operating System distributions](#operating-system-distributions)
- [Phishing awareness and reporting](#phishing-awareness-and-reporting)
- [Preparedness training and wargaming](#preparedness-training-and-wargaming)
- [Security monitoring](#security-monitoring)
  - [Endpoint Detection and Response (EDR)](#endpoint-detection-and-response-edr)
  - [Network Security Monitoring (NSM)](#network-security-monitoring-nsm)
  - [Security Information and Event Management (SIEM)](#security-information-and-event-management-siem)
  - [Service and performance monitoring](#service-and-performance-monitoring)
  - [Threat hunting](#threat-hunting)
- [Threat intelligence](#threat-intelligence)
- [Tor Onion service defenses](#tor-onion-service-defenses)
- [Transport-layer defenses](#transport-layer-defenses)
- [macOS-based defenses](#macos-based-defenses)
- [Windows-based defenses](#windows-based-defenses)

## Automation

- [Ansible Lockdown](https://ansiblelockdown.io/) - Curated collection of information security themed Ansible roles that are both vetted and actively maintained.
- [Clevis](https://github.com/latchset/clevis) - Plugable framework for automated decryption, often used as a Tang client.
- [Dev-Sec.io](https://dev-sec.io/) - Server hardening framework providing Ansible, Chef, and Puppet implementations of various baseline security configurations.
- [DShell](https://github.com/USArmyResearchLab/Dshell) - Extensible network forensic analysis framework written in Python that enables rapid development of plugins to support the dissection of network packet captures.
- [MultiScanner](https://github.com/mitre/multiscanner) - File analysis framework written in Python that assists in evaluating a set of files by automatically running a suite of tools against them and aggregating the output.
- [Posh-VirusTotal](https://github.com/darkoperator/Posh-VirusTotal) - PowerShell interface to VirusTotal.com APIs.
- [censys-python](https://github.com/censys/censys-python) - Python wrapper to the Censys REST API.
- [libcrafter](https://github.com/pellegre/libcrafter) - High level C++ network packet sniffing and crafting library.
- [peepdf](https://eternal-todo.com/tools/peepdf-pdf-analysis-tool) - Scriptable PDF file analyzer.
- [python-dshield](https://github.com/rshipp/python-dshield) - Pythonic interface to the Internet Storm Center/DShield API.
- [python-sandboxapi](https://github.com/InQuest/python-sandboxapi) - Minimal, consistent Python API for building integrations with malware sandboxes.
- [python-stix2](https://github.com/oasis-open/cti-python-stix2) - Python APIs for serializing and de-serializing Structured Threat Information eXpression (STIX) JSON content, plus higher-level APIs for common tasks.

## Cloud platform security

See also [asecure.cloud/tools](https://asecure.cloud/tools/).

- [Checkov](https://www.checkov.io/) - Static analysis for Terraform (infrastructure as code) to help detect CIS policy violations and prevent cloud security misconfiguration.
- [Falco](https://falco.org/) - Behavioral activity monitor designed to detect anomalous activity in containerized applications, hosts, and network packet flows by auditing the Linux kernel and enriched by runtime data such as Kubernetes metrics.
- [Prowler](https://github.com/toniblyx/prowler) - Tool based on AWS-CLI commands for Amazon Web Services account security assessment and hardening.
- [Scout Suite](https://github.com/nccgroup/ScoutSuite) - Open source multi-cloud security-auditing tool, which enables security posture assessment of cloud environments.

## Communications security (COMSEC)

- [GPG Sync](https://github.com/firstlookmedia/gpgsync) - Centralize and automate OpenPGP public key distribution, revocation, and updates amongst all members of an organization or team.

## DevSecOps

See also [awesome-devsecops](https://github.com/devsecops/awesome-devsecops).

- [BlackBox](https://github.com/StackExchange/blackbox) - Safely store secrets in Git/Mercurial/Subversion by encrypting them "at rest" using GnuPG.
- [Cilium](https://cilium.io/) - Open source software for transparently securing the network connectivity between application services deployed using Linux container management platforms like Docker and Kubernetes.
- [Clair](https://github.com/coreos/clair) - Static analysis tool to probe for vulnerabilities introduced via application container (e.g., Docker) images.
- [CodeQL](https://securitylab.github.com/tools/codeql) - Discover vulnerabilities across a codebase by performing queries against code as though it were data.
- [DefectDojo](https://www.defectdojo.org/) - Application vulnerability management tool built for DevOps and continuous security integration.
- [Gauntlt](http://gauntlt.org/) - Pentest applications during routine continuous integration build pipelines.
- [Git Secrets](https://github.com/awslabs/git-secrets) - Prevents you from committing passwords and other sensitive information to a git repository.
- [Vault](https://www.vaultproject.io/) - Tool for securely accessing secrets such as API keys, passwords, or certificates through a unified interface.
- [git-crypt](https://www.agwa.name/projects/git-crypt/) - Transparent file encryption in git; files which you choose to protect are encrypted when committed, and decrypted when checked out.
- [Snyk](https://snyk.io/) - Finds and fixes vulnerabilities and license violations in open source dependencies and container images.
- [SonarQube](https://sonarqube.org) - Continuous inspection tool that provides detailed reports during automated testing and alerts on newly introduced security vulnerabilities.

### Application or Binary Hardening

- [Egalito](https://egalito.org/) - Binary recompiler and instrumentation framework that can fully disassemble, transform, and regenerate ordinary Linux binaries designed for binary hardening and security research.

### Fuzzing

See also [Awesome-Fuzzing](https://github.com/secfigo/Awesome-Fuzzing).

* [FuzzBench](https://google.github.io/fuzzbench/) - Free service that evaluates fuzzers on a wide variety of real-world benchmarks, at Google scale.

### Policy enforcement

- [OpenPolicyAgent](https://www.openpolicyagent.org/) - Unified toolset and framework for policy across the cloud native stack.
- [Tang](https://github.com/latchset/tang) - Server for binding data to network presence; provides data to clients only when they are on a certain (secured) network.

## Honeypots

See also [awesome-honeypots](https://github.com/paralax/awesome-honeypots).

- [CanaryTokens](https://github.com/thinkst/canarytokens) - Self-hostable honeytoken generator and reporting dashboard; demo version available at [CanaryTokens.org](https://canarytokens.org/).
- [Kushtaka](https://kushtaka.org) - Sustainable all-in-one honeypot and honeytoken orchestrator for under-resourced blue teams.

### Tarpits

- [Endlessh](https://github.com/skeeto/endlessh) - SSH tarpit that slowly sends an endless banner.
- [LaBrea](http://labrea.sourceforge.net/labrea-info.html) - Program that answers ARP requests for unused IP space, creating the appearance of fake machines that answer further requests very slowly in order to slow down scanners, worms, etcetera.

## Host-based tools

- [Artillery](https://github.com/BinaryDefense/artillery) - Combination honeypot, filesystem monitor, and alerting system designed to protect Linux and Windows operating systems.
- [chkrootkit](http://chkrootkit.org/) - Locally checks for signs of a rootkit on GNU/Linux systems.
- [Crowd Inspect](https://www.crowdstrike.com/resources/community-tools/crowdinspect-tool/) - Free tool for Windows systems aimed to alert you to the presence of malware that may be communicating over the network.
- [Fail2ban](https://www.fail2ban.org/) - Intrusion prevention software framework that protects computer servers from brute-force attacks.
- [OpenSCAP Base](https://www.open-scap.org/tools/openscap-base/) - Both a library and a command line tool (`oscap`) used to evaluate a system against SCAP baseline profiles to report on the security posture of the scanned system(s). 
- [Open Source HIDS SECurity (OSSEC)](https://www.ossec.net/) - Fully open source and free, feature-rich, Host-based Instrusion Detection System (HIDS).
- [Rootkit Hunter (rkhunter)](http://rkhunter.sourceforge.net/) - POSIX-compliant Bash script that scans a host for various signs of malware.

### Sandboxes

- [Firejail](https://firejail.wordpress.com/) - SUID program that reduces the risk of security breaches by restricting the running environment of untrusted applications using Linux namespaces and seccomp-bpf.

## Incident Response tools

See also [awesome-incident-response](https://github.com/meirwah/awesome-incident-response).

- [aws_ir](https://github.com/ThreatResponse/aws_ir) - Automates your incident response with zero security preparedness assumptions.

### IR management consoles

- [CIRTKit](https://github.com/opensourcesec/CIRTKit) - Scriptable Digital Forensics and Incident Response (DFIR) toolkit built on Viper.
- [Fast Incident Response (FIR)](https://github.com/certsocietegenerale/FIR) - Cybersecurity incident management platform allowing for easy creation, tracking, and reporting of cybersecurity incidents.
- [Rekall](http://www.rekall-forensic.com/) - Advanced forensic and incident response framework.
- [TheHive](https://thehive-project.org/) - Scalable, free Security Incident Response Platform designed to make life easier for SOCs, CSIRTs, and CERTs, featuring tight integration with MISP.
- [threat_note](https://github.com/defpoint/threat_note) - Web application built by Defense Point Security to allow security researchers the ability to add and retrieve indicators related to their research.

### Evidence collection

- [AutoMacTC](https://github.com/CrowdStrike/automactc) - Modular, automated forensic triage collection framework designed to access various forensic artifacts on macOS, parse them, and present them in formats viable for analysis.
- [OSXAuditor](https://github.com/jipegit/OSXAuditor) - Free macOS computer forensics tool.
- [OSXCollector](https://github.com/Yelp/osxcollector) - Forensic evidence collection & analysis toolkit for macOS.
- [ir-rescue](https://github.com/diogo-fernan/ir-rescue) - Windows Batch script and a Unix Bash script to comprehensively collect host forensic data during incident response.
- [Margarita Shotgun](https://github.com/ThreatResponse/margaritashotgun) - Command line utility (that works with or without Amazon EC2 instances) to parallelize remote memory acquisition.

## Network perimeter defenses

- [fwknop](https://www.cipherdyne.org/fwknop/) - Protects ports via Single Packet Authorization in your firewall.
- [ssh-audit](https://github.com/jtesta/ssh-audit) - Simple tool that makes quick recommendations for improving an SSH server's security posture.

### Firewall appliances or distributions

- [OPNsense](https://opnsense.org/) - FreeBSD based firewall and routing platform.
- [pfSense](https://www.pfsense.org/) - Firewall and router FreeBSD distribution.

## Operating System distributions

- [Computer Aided Investigative Environment (CAINE)](https://caine-live.net/) - Italian GNU/Linux live distribution that pre-packages numerous digital forensics and evidence collection tools.
- [Security Onion](https://securityonion.net/) - Free and open source GNU/Linux distribution for intrusion detection, enterprise security monitoring, and log management.

## Phishing awareness and reporting

See also [awesome-pentest § Social Engineering Tools](https://github.com/fabacab/awesome-pentest#social-engineering-tools).

- [CertSpotter](https://github.com/SSLMate/certspotter) - Certificate Transparency log monitor from SSLMate that alerts you when a SSL/TLS certificate is issued for one of your domains.
- [Gophish](https://getgophish.com/) - Powerful, open-source phishing framework that makes it easy to test your organization's exposure to phishing.
- [Phishing Reporter](https://github.com/0dteam/Phishing-Reporter) - An Outlook Plugin to report phishing emails easier. It has full integration with GoPhish phishing Framework.
- [King Phisher](https://github.com/securestate/king-phisher) - Tool for testing and promoting user awareness by simulating real world phishing attacks.
- [NotifySecurity](https://github.com/certsocietegenerale/NotifySecurity) - Outlook add-in used to help your users to report suspicious e-mails to security teams.
- [Phishing Intelligence Engine (PIE)](https://github.com/LogRhythm-Labs/PIE) - Framework that will assist with the detection and response to phishing attacks.
- [Swordphish](https://github.com/certsocietegenerale/swordphish-awareness) - Platform allowing to create and manage (fake) phishing campaigns intended to train people in identifying suspicious mails. 
- [mailspoof](https://github.com/serain/mailspoof) - Scans SPF and DMARC records for issues that could allow email spoofing.
- [phishing_catcher](https://github.com/x0rz/phishing_catcher) - Configurable script to watch for issuances of suspicious TLS certificates by domain name in the Certificate Transparency Log (CTL) using the [CertStream](https://certstream.calidog.io/) service.

## Preparedness training and wargaming

(Also known as *adversary emulation*, *threat simulation*, or similar.)

- [APTSimulator](https://github.com/NextronSystems/APTSimulator) - Toolset to make a system look as if it was the victim of an APT attack.
- [Atomic Red Team](https://atomicredteam.io/) - Library of simple, automatable tests to execute for testing security controls.
- [DumpsterFire](https://github.com/TryCatchHCF/DumpsterFire) - Modular, menu-driven, cross-platform tool for building repeatable, time-delayed, distributed security events for Blue Team drills and sensor/alert mapping.
- [Metta](https://github.com/uber-common/metta) - Automated information security preparedness tool to do adversarial simulation.
- [Network Flight Simulator (`flightsim`)](https://github.com/alphasoc/flightsim) - Utility to generate malicious network traffic and help security teams evaluate security controls and audit their network visibility.
- [RedHunt OS](https://github.com/redhuntlabs/RedHunt-OS) - Ubuntu-based Open Virtual Appliance (`.ova`) preconfigured with several threat emulation tools as well as a defender's toolkit.

## Security monitoring

### Endpoint Detection and Response (EDR)

- [Wazuh](https://wazuh.com/) - Open source, multiplatform agent-based security monitoring based on a fork of OSSEC HIDS.

### Network Security Monitoring (NSM)

See also [awesome-pcaptools](https://github.com/caesar0301/awesome-pcaptools).

- [ChopShop](https://github.com/MITRECND/chopshop) - Framework to aid analysts in the creation and execution of pynids-based decoders and detectors of APT tradecraft.
- [Maltrail](https://github.com/stamparm/maltrail) - Malicious network traffic detection system.
- [Moloch](https://github.com/aol/moloch) - Augments your current security infrastructure to store and index network traffic in standard PCAP format, providing fast, indexed access.
- [OwlH](https://www.owlh.net/) - Helps manage network IDS at scale by visualizing Suricata, Zeek, and Moloch life cycles.
- [Respounder](https://github.com/codeexpress/respounder) - Detects the presence of the Responder LLMNR/NBT-NS/MDNS poisoner on a network.
- [Snort](https://snort.org/) - Widely-deployed, Free Software IPS capable of real-time packet analysis, traffic logging, and custom rule-based triggers.
- [SpoofSpotter](https://github.com/NetSPI/SpoofSpotter) - Catch spoofed NetBIOS Name Service (NBNS) responses and alert to an email or log file.
- [Suricata](https://suricata-ids.org/) - Free, cross-platform, IDS/IPS with on- and off-line analysis modes and deep packet inspection capabilities that is also scriptable with Lua.
- [VAST](https://github.com/tenzir/vast) - Free and open-source network telemetry engine for data-driven security investigations.
- [Wireshark](https://www.wireshark.org) - Free and open-source packet analyzer useful for network troubleshooting or forensic netflow analysis.
- [Zeek](https://zeek.org/) - Powerful network analysis framework focused on security monitoring, formerly known as Bro.
- [netsniff-ng](http://netsniff-ng.org/) -  Free and fast GNU/Linux networking toolkit with numerous utilities such as a connection tracking tool (`flowtop`), traffic generator (`trafgen`), and autonomous system (AS) trace route utility (`astraceroute`).


### Security Information and Event Management (SIEM)

- [AlienVault OSSIM](https://www.alienvault.com/open-threat-exchange/projects) - Single-server open source SIEM platform featuring asset discovery, asset inventorying, behavioral monitoring, and event correlation, driven by AlienVault Open Threat Exchange (OTX).
- [Prelude SIEM OSS](https://www.prelude-siem.org/) - Open source, agentless SIEM with a long history and several commercial variants featuring security event collection, normalization, and alerting from arbitrary log input and numerous popular monitoring tools.

### Service and performance monitoring

See also [awesome-sysadmin#monitoring](https://github.com/n1trux/awesome-sysadmin#monitoring).

- [Icinga](https://icinga.com/) - Modular redesign of Nagios with pluggable user interfaces and an expanded set of data connectors, collectors, and reporting tools.
- [Locust](https://locust.io/) - Open source load testing tool in which you can define user behaviour with Python code and swarm your system with millions of simultaneous users.
- [Nagios](https://nagios.org) - Popular network and service monitoring solution and reporting platform.
- [OpenNMS](https://opennms.org/) - Free and feature-rich networking monitoring system supporting multiple configurations, a variety of alerting mechanisms (email, XMPP, SMS), and numerous data collection methods (SNMP, HTTP, JDBC, etc).
- [osquery](https://github.com/facebook/osquery) - Operating system instrumentation framework for macOS, Windows, and Linux, exposing the OS as a high-performance relational database that can be queried with a SQL-like syntax.

### Threat hunting

(Also known as *hunt teaming* and *threat detection*.)

See also [awesome-threat-detection](https://github.com/0x4D31/awesome-threat-detection).

- [CimSweep](https://github.com/PowerShellMafia/CimSweep) - Suite of CIM/WMI-based tools enabling remote incident response and hunting operations across all versions of Windows.
- [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI) - PowerShell module for hunt teaming via Windows Event logs.
- [GRR Rapid Response](https://github.com/google/grr) - Incident response framework focused on remote live forensics consisting of a Python agent installed on assets and Python-based server infrastructure enabling analysts to quickly triage attacks and perform analysis remotely.
- [Hunting ELK (HELK)](https://github.com/Cyb3rWard0g/HELK) - All-in-one Free Software threat hunting stack based on Elasticsearch, Logstash, Kafka, and Kibana with various built-in integrations for analytics including Jupyter Notebook.
- [MozDef](https://github.com/mozilla/MozDef) - Automate the security incident handling process and facilitate the real-time activities of incident handlers.
- [PSHunt](https://github.com/Infocyte/PSHunt) - PowerShell module designed to scan remote endpoints for indicators of compromise or survey them for more comprehensive information related to state of those systems.
- [PSRecon](https://github.com/gfoss/PSRecon) - PSHunt-like tool for analyzing remote Windows systems that also produces a self-contained HTML report of its findings.
- [PowerForensics](https://github.com/Invoke-IR/PowerForensics) - All in one PowerShell-based platform to perform live hard disk forensic analysis.
- [rastrea2r](https://github.com/rastrea2r/rastrea2r) - Multi-platform tool for triaging suspected IOCs on many endpoints simultaneously and that integrates with antivirus consoles.
- [Redline](https://www.fireeye.com/services/freeware/redline.html) - Freeware endpoint auditing and analysis tool that provides host-based investigative capabilities, offered by FireEye, Inc.

## Threat intelligence

See also [awesome-threat-intelligence](https://github.com/hslatman/awesome-threat-intelligence).

- [Active Directory Control Paths](https://github.com/ANSSI-FR/AD-control-paths) - Visualize and graph Active Directory permission configs ("control relations") to audit questions such as "Who can read the CEO's email?" and similar.
- [AttackerKB](https://attackerkb.com/) - Free and public crowdsourced vulnerability assessment platform to help prioritize high-risk patch application and combat vulnerability fatigue.
- [DATA](https://github.com/hadojae/DATA) - Credential phish analysis and automation tool that can acccept suspected phishing URLs directly or trigger on observed network traffic containing such a URL.
- [Forager](https://github.com/opensourcesec/Forager) - Multi-threaded threat intelligence gathering built with Python3 featuring simple text-based configuration and data storage for ease of use and data portability.
- [GRASSMARLIN](https://github.com/nsacyber/GRASSMARLIN) - Provides IP network situational awareness of industrial control systems (ICS) and Supervisory Control and Data Acquisition (SCADA) by passively mapping, accounting for, and reporting on your ICS/SCADA network topology and endpoints.
- [MLSec Combine](https://github.com/mlsecproject/combine) - Gather and combine multiple threat intelligence feed sources into one customizable, standardized CSV-based format.
- [Malware Information Sharing Platform and Threat Sharing (MISP)](https://misp-project.org/) - Open source software solution for collecting, storing, distributing and sharing cyber security indicators.
- [ThreatIngestor](https://github.com/InQuest/ThreatIngestor) - Extendable tool to extract and aggregate IOCs from threat feeds including Twitter, RSS feeds, or other sources.
- [Unfetter](https://nsacyber.github.io/unfetter/) - Identifies defensive gaps in security posture by leveraging Mitre's ATT&CK framework.
- [Viper](https://github.com/viper-framework/viper) - Binary analysis and management framework enabling easy organization of malware and exploit samples.

## Tor Onion service defenses

See also [awesome-tor](https://github.com/ajvb/awesome-tor).

- [OnionBalance](https://onionbalance.readthedocs.io/) - Provides load-balancing while also making Onion services more resilient and reliable by eliminating single points-of-failure.
- [Vanguards](https://github.com/mikeperry-tor/vanguards) - Version 3 Onion service guard discovery attack mitigation script (intended for eventual inclusion in Tor core).

## Transport-layer defenses

- [Certbot](https://certbot.eff.org/) - Free tool to automate the issuance and renewal of TLS certificates from the [LetsEncrypt Root CA](https://letsencrypt.org/) with plugins that configure various Web and e-mail server software.
- [MITMEngine](https://github.com/cloudflare/mitmengine) - Golang library for server-side detection of TLS interception events.
- [OpenVPN](https://openvpn.net/) - Open source, SSL/TLS-based virtual private network (VPN).
- [Tor](https://torproject.org/) - Censorship circumvention and anonymizing overlay network providing distributed, cryptographically verified name services (`.onion` domains) to enhance publisher privacy and service availability.

## macOS-based defenses

- [BlockBlock](https://objective-see.com/products/blockblock.html) - Monitors common persistence locations and alerts whenever a persistent component is added, which helps to detect and prevent malware installation.
- [LuLu](https://objective-see.com/products/lulu.html) - Free macOS firewall.
- [Santa](https://github.com/google/santa) - Binary whitelisting/blacklisting system for macOS.
- [Stronghold](https://github.com/alichtman/stronghold) - Easily configure macOS security settings from the terminal.
- [macOS Fortress](https://github.com/essandess/macOS-Fortress) - Automated configuration of kernel-level, OS-level, and client-level security features including privatizing proxying and anti-virus scanning for macOS.

## Windows-based defenses

See also [awesome-windows#security](https://github.com/Awesome-Windows/Awesome#security) and [awesome-windows-domain-hardening](https://github.com/PaulSec/awesome-windows-domain-hardening).

- [HardenTools](https://github.com/securitywithoutborders/hardentools) - Utility that disables a number of risky Windows features.
- [NotRuler](https://github.com/sensepost/notruler) - Detect both client-side rules and VBScript enabled forms used by the [Ruler](https://github.com/sensepost/ruler) attack tool when attempting to compromise a Microsoft Exchange server.
- [Sandboxie](https://www.sandboxie.com/) - Free and open source general purpose Windows application sandboxing utility.
- [Sigcheck](https://docs.microsoft.com/en-us/sysinternals/downloads/sigcheck) - Audit a Windows host's root certificate store against Microsoft's [Certificate Trust List (CTL)](https://docs.microsoft.com/en-us/windows/desktop/SecCrypto/certificate-trust-list-overview).
- [Sticky Keys Slayer](https://github.com/linuz/Sticky-Keys-Slayer) - Establishes a Windows RDP session from a list of hostnames and scans for accessibility tools backdoors, alerting if one is discovered.
- [Windows Secure Host Baseline](https://github.com/nsacyber/Windows-Secure-Host-Baseline) - Group Policy objects, compliance checks, and configuration tools that provide an automated and flexible approach for securely deploying and maintaining the latest releases of Windows 10.
- [WMI Monitor](https://github.com/realparisi/WMI_Monitor) - Log newly created WMI consumers and processes to the Windows Application event log.

## License

[![CC-BY](https://mirrors.creativecommons.org/presskit/buttons/88x31/svg/by.svg)](https://creativecommons.org/licenses/by/4.0/)

This work is licensed under a [Creative Commons Attribution 4.0 International License](https://creativecommons.org/licenses/by/4.0/).
