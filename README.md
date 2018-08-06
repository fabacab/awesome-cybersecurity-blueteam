# Awesome Cybersecurity Blue Team [![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)

> A collection of awesome resources, tool, and other shiny things for cybersecurity blue teams.

[Cybersecurity blue teams](https://en.wikipedia.org/wiki/Blue_team_(computer_security)) are groups of individuals who identify security flaws in information technology systems, verify the effectiveness of security measures, and monitor the systems to ensure that implemented defensive measures remain effective in the future. While not exclusive, this list is heavily biased towards [Free Software](https://www.gnu.org/philosophy/free-sw.html) projects and against proprietary products or corporate services. For offensive TTPs, please see [awesome-pentest](https://github.com/meitar/awesome-pentest).

Your contributions and suggestions are heartily♥ welcome. (✿◕‿◕). Please check the [Contributing Guidelines](CONTRIBUTING.md) for more details. This work is licensed under a [Creative Commons Attribution 4.0 International License](http://creativecommons.org/licenses/by/4.0/).

## Contents

- [Automation](#automation)
- [Firewalling distributions](#firewalling-distributions)
- [Honeypots](#honeypots)
- [Host-based tools](#host-based-tools)
- [Incident Response tools](#incident-response-tools)
    - [IR management consoles](#ir-management-consoles)
    - [Evidence collection](#evidence-collection)
    - [Threat hunting](#threat-hunting)
- [Network Security Monitoring (NSM)](#network-security-monitoring-nsm)
- [Network perimeter defenses](#network-perimeter-defenses)
- [Preparedness training and wargaming](#preparedness-training-and-wargaming)
- [Security Information and Event Management (SIEM)](#security-information-and-event-management-siem)
- [Service and performance monitoring](#service-and-performance-monitoring)
- [Threat intelligence](#threat-intelligence)
- [Tor Onion service defenses](#tor-onion-service-defenses)
- [Transport-layer defense](#transport-layer-defenses)
- [Windows-based defenses](#windows-based-defenses)

## Automation

- [Autosnort](https://github.com/da667/Autosnort) - Series of bash shell scripts designed to install a fully functional, fully updated stand-alone snort sensor with an IDS event review console of your choice, on a variety of Linux distributions.
- [Posh-VirusTotal](https://github.com/darkoperator/Posh-VirusTotal) - PowerShell interface to VirusTotal.com APIs.

## Firewalling distributions

- [OPNsense](https://opnsense.org/) - FreeBSD based firewall and routing platform.
- [pfSense](https://www.pfsense.org/) - Firewall and router FreeBSD distribution.

## Honeypots

See also [awesome-honeypots](https://github.com/paralax/awesome-honeypots).

- [CanaryTokens](https://github.com/thinkst/canarytokens) - Self-hostable honeytoken generator and reporting dashboard; demo version available at [CanaryTokens.org](https://canarytokens.org/).

## Host-based tools

- [Artillery](https://github.com/BinaryDefense/artillery) - Combination honeypot, filesystem monitor, and alerting system designed to protect Linux and Windows operating systems.
- [Fail2ban](https://www.fail2ban.org/) - Intrusion prevention software framework that protects computer servers from brute-force attacks.

## Incident Response tools

See also [awesome-incident-response](https://github.com/meirwah/awesome-incident-response).

### IR management consoles

- [CIRTKit](https://github.com/opensourcesec/CIRTKit) - Scriptable Digital Forensics and Incident Response (DFIR) toolkit built on Viper.
- [Fast Incident Response (FIR)](https://github.com/certsocietegenerale/FIR) - Cybersecurity incident management platform allowing for easy creation, tracking, and reporting of cybersecurity incidents.
- [TheHive](https://thehive-project.org/) - Scalable, free Security Incident Response Platform designed to make life easier for SOCs, CSIRTs, and CERTs, featuring tight integration with MISP.
- [threat_note](https://github.com/defpoint/threat_note) - Web application built by Defense Point Security to allow security researchers the ability to add and retrieve indicators related to their research.

### Evidence collection

- [OSXAuditor](https://github.com/jipegit/OSXAuditor) - Free macOS computer forensics tool.
- [OSXCollector](https://github.com/Yelp/osxcollector) - Forensic evidence collection & analysis toolkit for macOS.
- [ir-rescue](https://github.com/diogo-fernan/ir-rescue) - Windows Batch script and a Unix Bash script to comprehensively collect host forensic data during incident response.

### Threat hunting

(Also known as *hunt teaming*.)

- [CimSweep](https://github.com/PowerShellMafia/CimSweep) - Suite of CIM/WMI-based tools enabling remote incident response and hunting operations across all versions of Windows.
- [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI) - PowerShell module for hunt teaming via Windows Event logs.
- [GRR Rapid Response](https://github.com/google/grr) - Incident response framework focused on remote live forensics consisting of a Python agent installed on assets and Python-based server infrastructure enabling analysts to quickly triage attacks and perform analysis remotely.
- [Mozilla InvestiGator (MIG)](https://mig.mozilla.org/) - Platform to perform investigative surgery on remote endpoints.
- [PSHunt](https://github.com/Infocyte/PSHunt) - PowerShell module designed to scan remote endpoints for indicators of compromise or survey them for more comprehensive information related to state of those systems.
- [PowerForensics](https://github.com/Invoke-IR/PowerForensics) - All in one PowerShell-based platform to perform live hard disk forensic analysis.
- [Redline](https://www.fireeye.com/services/freeware/redline.html) - Freeware endpoint auditing and analysis tool that provides host-based investigative capabilities, offered by FireEye, Inc.

## Network Security Monitoring (NSM)

- [Bro](https://www.bro.org/) - Powerful network analysis framework focused on security monitoring.
- [ChopShop](https://github.com/MITRECND/chopshop) - Framework to aid analysts in the creation and execution of pynids-based decoders and detectors of APT tradecraft.
- [Maltrail](https://github.com/stamparm/maltrail) - Malicious network traffic detection system.
- [Respounder](https://github.com/codeexpress/respounder) - Detects the presence of the Responder LLMNR/NBT-NS/MDNS poisoner on a network.
- [Security Monkey](https://github.com/Netflix/security_monkey) - Monitors your AWS and GCP accounts for policy changes and alerts on insecure configurations.
- [Snort](https://snort.org/) - Widely-deployed, Free Software IPS capable of real-time packet analysis, traffic logging, and custom rule-based triggers.
- [SpoofSpotter](https://github.com/NetSPI/SpoofSpotter) - Catch spoofed NetBIOS Name Service (NBNS) responses and alert to an email or log file.
- [Suricata](https://suricata-ids.org/) - Free, cross-platform, IDS/IPS with on- and off-line analysis modes and deep packet inspection capabilities that is also scriptable with Lua.
- [Wireshark](https://www.wireshark.org) - Free and open-source packet analyzer useful for network troubleshooting or forensic netflow analysis.
- [netsniff-ng](http://netsniff-ng.org/) -  Free and fast GNU/Linux networking toolkit with numerous utilities such as a connection tracking tool (`flowtop`), traffic generator (`trafgen`), and autonomous system (AS) trace route utility (`astraceroute`).

## Network perimeter defenses

- [fwknop](https://www.cipherdyne.org/fwknop/) - Protects ports via Single Packet Authorization in your firewall.

## Preparedness training and wargaming

(Also known as *adversary emulation* or  *threat simulation*.)

- [APTSimulator](https://github.com/NextronSystems/APTSimulator) - Toolset to make a system look as if it was the victim of an APT attack.
- [DumpsterFire](https://github.com/TryCatchHCF/DumpsterFire) - Modular, menu-driven, cross-platform tool for building repeatable, time-delayed, distributed security events for Blue Team drills and sensor/alert mapping.
- [Metta](https://github.com/uber-common/metta) - Automated information security preparedness tool to do adversarial simulation.

## Security Information and Event Management (SIEM)

- [AlienVault OSSIM](https://www.alienvault.com/open-threat-exchange/projects) - Single-server open source SIEM platform featuring asset discovery, asset inventorying, behavioral monitoring, and event correlation, driven by AlienVault Open Threat Exchange (OTX).
- [Prelude SIEM OSS](https://www.prelude-siem.org/) - Open source, agentless SIEM with a long history and several commercial variants featuring security event collection, normalization, and alerting from arbitrary log input and numerous popular monitoring tools.

## Service and performance monitoring

See also [awesome-sysadmin#monitoring](https://github.com/n1trux/awesome-sysadmin#monitoring).

- [Icinga](https://icinga.com/) - Modular redesign of Nagios with pluggable user interfaces and an expanded set of data connectors, collectors, and reporting tools.
- [Nagios](https://nagios.org) - Popular network and service monitoring solution and reporting platform.
- [OpenNMS](https://opennms.org/) - Free and feature-rich networking monitoring system supporting multiple configurations, a variety of alerting mechanisms (email, XMPP, SMS), and numerous data collection methods (SNMP, HTTP, JDBC, etc).
- [osquery](https://github.com/facebook/osquery) - Operating system instrumentation framework for macOS, Windows, and Linux, exposing the OS as a high-performance relational database that can be queried with a SQL-like syntax.

# Threat intelligence

See also [awesome-threat-intelligence](https://github.com/hslatman/awesome-threat-intelligence).

- [Active Directory Control Paths](https://github.com/ANSSI-FR/AD-control-paths) - Visualize and graph Active Directory permission configs ("control relations") to audit questions such as "Who can read the CEO's email?"
- [DATA](https://github.com/hadojae/DATA) - Credential phish analysis and automation tool that can acccept suspected phishing URLs directly or trigger on observed network traffic containing such a URL.
- [Forager](https://github.com/opensourcesec/Forager) - Multi-threaded threat intelligence gathering built with Python3 featuring simple text-based configuration and data storage for ease of use and data portability.
- [GRASSMARLIN](https://github.com/nsacyber/GRASSMARLIN) - Provides IP network situational awareness of industrial control systems (ICS) and Supervisory Control and Data Acquisition (SCADA) by passively mapping, accounting for, and reporting on your ICS/SCADA network topology and endpoints.
- [MLSec Combine](https://github.com/mlsecproject/combine) - Gather and combine multiple threat intelligence feed sources into one customizable, standardized CSV-based format.
- [Malware Information Sharing Platform and Threat Sharing (MISP)](https://misp-project.org/) - Open source software solution for collecting, storing, distributing and sharing cyber security indicators.
- [Unfetter](https://nsacyber.github.io/unfetter/) - Identifies defensive gaps in security posture by leveraging Mitre's ATT&CK framework.
- [Viper](https://github.com/viper-framework/viper) - Binary analysis and management framework enabling easy organization of malware and exploit samples.

## Tor Onion service defenses

See also [awesome-tor](https://github.com/ajvb/awesome-tor).

- [OnionBalance](https://onionbalance.readthedocs.io/) - Provides load-balancing while also making Onion services more resilient and reliable by eliminating single points-of-failure.
- [Vanguards](https://github.com/mikeperry-tor/vanguards) - Version 3 Onion service guard discovery attack mitigation script (intended for eventual inclusion in Tor core).

## Transport-layer defenses

- [OpenVPN](https://openvpn.net/) - Open source, SSL/TLS-based virtual private network (VPN).

## Windows-based defenses

See also [awesome-windows#security](https://github.com/Awesome-Windows/Awesome#security) and [awesome-windows-domain-hardening](https://github.com/PaulSec/awesome-windows-domain-hardening).

- [HardenTools](https://github.com/securitywithoutborders/hardentools) - Utility that disables a number of risky Windows features.
- [NotRuler](https://github.com/sensepost/notruler) - Detect both client-side rules and VBScript enabled forms used by the [Ruler](https://github.com/sensepost/ruler) attack tool when attempting to compromise a Microsoft Exchange server.
- [Sticky Keys Slayer](https://github.com/linuz/Sticky-Keys-Slayer) - Establishes a Windows RDP session from a list of hostnames and scans for accessibility tools backdoors, alerting if one is discovered.
- [Windows Secure Host Baseline](https://github.com/nsacyber/Windows-Secure-Host-Baseline) - Group Policy objects, compliance checks, and configuration tools that provide an automated and flexible approach for securely deploying and maintaining the latest releases of Windows 10.
- [WMI Monitor](https://github.com/realparisi/WMI_Monitor) - Log newly created WMI consumers and processes to the Windows Application event log.

# License

[![CC-BY](https://mirrors.creativecommons.org/presskit/buttons/88x31/svg/by.svg)](https://creativecommons.org/licenses/by/4.0/)

This work is licensed under a [Creative Commons Attribution 4.0 International License](https://creativecommons.org/licenses/by/4.0/).
