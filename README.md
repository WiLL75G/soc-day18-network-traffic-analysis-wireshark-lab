# Network Traffic Analysis, NetSupport RAT C2

A SIEM alert says something is talking to a bad IP. Wireshark says what it is saying, how often, and which machine on the floor is doing it.

## At a Glance

| Field | Detail |
| --- | --- |
| Alert Type | RAT command and control beaconing |
| Severity | High, active infection confirmed |
| Malware | NetSupport Manager RAT |
| Infected Host | brads-MBP, 10.2.28.88, 00:19:d1:b2:4d:ad |
| C2 Server | 45.131.214.85, HTTP POST to /fakeurl.htm over TCP 443 |
| Capture Size | 15,512 packets, 550 relevant |
| Outcome | Host identified by name and MAC, full IOC set produced |

## What Happened

A SIEM signature fired on NetSupport Manager RAT traffic to 45.131.214.85 over port 443. The PCAP was pulled and worked in Wireshark.

The alert gave an IP. The capture gave a hostname, a MAC address, a beacon interval, a C2 URI, and a person's name. That gap is why the PCAP gets opened rather than the ticket getting closed on the signature.

Scope stated plainly: this is a published training capture from a malware traffic analysis exercise, not an incident on a network I defend. The malware, the C2, and the beaconing are real. The environment is not mine.

## PCAP Overview

![Wireshark PCAP Loaded](./screenshots/04_pcap_loaded_overview.png)

15,512 packets loaded. Protocol mix of DHCP, ARP, DNS, HTTP, and TCP. Initial DHCP discover and request present from an unassigned host.

Read the shape before filtering. Total volume and protocol distribution tell you what kind of capture you are holding, and the DHCP at the top is already a gift, because it means the host will name itself later.

## C2 Traffic Isolated

![C2 Traffic Filtered](./screenshots/05_c2_traffic_filtered.png)

```
ip.addr == 45.131.214.85
```

550 packets, 3.5 percent of the capture.

Repeated HTTP POST requests to http://45.131.214.85/fakeurl.htm, at regular intervals, all over TCP 443.

Three findings sit in that one filter.

The URI is the signature. /fakeurl.htm is a known NetSupport Manager RAT callback. The name is the malware author's joke and it is also the thing that identifies the family without needing a sample.

The regularity is the proof. Humans do not generate traffic at a fixed interval. A clean rhythm in the timestamps means a scheduler, and a scheduler talking to an external host is a beacon.

Port 443 carrying plain HTTP is the evasion. Port 443 is expected outbound and rarely inspected, because everyone assumes it is TLS. Putting cleartext HTTP on it buys the attacker a hole in most egress rules. Reading the protocol rather than the port number is what catches it.

## Connection Direction

![HTTP POST Details](./screenshots/06_tcp_syn_http_post_details.png)

Packet 2569, TCP SYN from 10.2.28.88 to 45.131.214.85:443. Source MAC 00:19:d1:b2:4d:ad.

The SYN direction settles the case. The infected host initiated the connection outbound. Nothing knocked on the door.

That distinction is the whole triage. Inbound to an internal host is someone probing. Outbound from an internal host, repeatedly, on a schedule, is malware already resident and calling home. One is an attempt. The other is a compromise.

## Host Identification via DHCP

![DHCP Packets](./screenshots/07_dhcp_packets_analysis.png)

![Hostname Discovered](./screenshots/08_hostname_mac_discovered.png)

```
dhcp
```

Four DHCP packets. Expanding the Discover packet, Option 12 Host Name:

Hostname brads-MBP.

IP 10.2.28.88.

MAC 00:19:d1:b2:4d:ad.

This is the step that turns an alert into an action.

10.2.28.88 is a lease. It is not a machine, and by tomorrow it may belong to something else entirely. Nobody can walk to an IP address.

The DHCP hostname and MAC are the machine. brads-MBP is a laptop with a person attached, and the MAC follows that hardware regardless of what address it holds. That is what the IT team needs to physically find it and pull it off the network.

Worth flagging: a MacBook on a Windows AD domain. Possibly BYOD, possibly an exception nobody documented. Either way it is a policy question the incident should raise.

## DNS Analysis

![DNS Traffic](./screenshots/09_dns_traffic_analysis.png)

```
dns
```

All queries from the infected host reviewed and correlated against the C2 timeline.

DNS is the wishlist. Every domain the malware tried to reach is here, including the ones that failed. Malware carries fallback infrastructure, so the C2 in the alert is often one of several, and the ones that never answered are the ones that will answer next week.

## Conversation Statistics

![TCP Conversations](./screenshots/10_tcp_conversations.png)

![IPv4 Conversations](./screenshots/11_ipv4_conversations.png)

Statistics, Conversations. 352 TCP and 219 UDP conversations.

Top transfer: 10.2.28.88 to 10.2.28.2, 112 kB, internal domain controller traffic.

External connection to 4.149.160.182, not yet explained.

Multiple Microsoft ranges contacted, consistent with update activity.

The conversation view answers the question the filter cannot: what else was this host doing. Filtering on the known C2 confirms the known C2. It finds nothing new by definition.

The 112 kB to the DC is the one worth sitting with. Domain controller traffic from a workstation is normal. Volume is what makes it a question, and the honest answer here is that it is within range for authentication and policy traffic. Noted, not escalated, and it goes in the handoff so Tier 2 decides with the endpoint in front of them.

4.149.160.182 is the loose end. It is not in the alert, it is not obviously Microsoft, and it does not get cleared just because the investigation already found what it was looking for.

## IOC Table

| Type | Value | Verdict |
| --- | --- | --- |
| Infected host IP | 10.2.28.88 | Compromised |
| Hostname | brads-MBP | Compromised, isolate |
| MAC address | 00:19:d1:b2:4d:ad | Compromised device |
| C2 IP | 45.131.214.85 | Malicious, RAT C2 |
| C2 URI | /fakeurl.htm | NetSupport RAT callback |
| C2 port | TCP 443 | Evasion, HTTP on the HTTPS port |
| Unexplained IP | 4.149.160.182 | Requires investigation |
| Malware | NetSupport Manager RAT | Confirmed active |

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
| --- | --- | --- | --- |
| Command and Control | Remote access software | T1219 | NetSupport Manager RAT resident on host |
| Command and Control | Application layer protocol, web | T1071.001 | HTTP POST beaconing to C2 |
| Command and Control | Non standard port | T1571 | Plain HTTP carried over TCP 443 |
| Command and Control | Data encoding | T1132 | Form urlencoded POST body to C2 |
| Exfiltration | Exfiltration over C2 channel | T1041 | Data sent outbound to 45.131.214.85 |

## Analyst Conclusion

NetSupport Manager RAT confirmed active on brads-MBP, 10.2.28.88.

550 packets of C2 traffic to 45.131.214.85, beaconing at regular intervals.

Connections initiated outbound by the infected host, confirming resident malware rather than external probing.

Host identified by hostname and MAC via DHCP, making physical isolation possible.

/fakeurl.htm over port 443 confirms both the family and the evasion technique.

Domain controller traffic reviewed and within normal range. No lateral movement evidence in this capture.

4.149.160.182 unexplained and carried forward.

## Recommended Response

Isolate brads-MBP immediately, identified by MAC so the isolation survives a DHCP lease change.

Block 45.131.214.85 at the perimeter and /fakeurl.htm at the proxy.

Alert on any future connection to the C2 IP, and on plain HTTP over port 443, which is the technique rather than the indicator.

Submit the device for endpoint forensics. The PCAP proves the RAT is talking. It does not say how it arrived.

Investigate 4.149.160.182 rather than closing on the alert that was already answered.

Escalate to Tier 2 with the IOC set and the DC traffic note attached.

## What This Lab Demonstrates

Working a real malicious capture down from 15,512 packets to the 550 that matter.

Reading beacon regularity as automation rather than counting volume.

Recognising plain HTTP on port 443 as evasion, and knowing why the port alone is not the finding.

Using SYN direction to distinguish resident malware from inbound probing.

Converting an IP into a hostname and MAC via DHCP, which is what makes an alert actionable.

Checking what else the host did rather than only confirming what the alert said.

Leaving an unexplained IP open instead of closing the investigation early.

## Repository Structure

```text
network-traffic-analysis-wireshark-lab/
├── README.md
└── screenshots/
    ├── 01_wireshark_version.png
    ├── 02_malware_traffic_analysis_site.png
    ├── 03_exercise_background.png
    ├── 04_pcap_loaded_overview.png
    ├── 05_c2_traffic_filtered.png
    ├── 06_tcp_syn_http_post_details.png
    ├── 07_dhcp_packets_analysis.png
    ├── 08_hostname_mac_discovered.png
    ├── 09_dns_traffic_analysis.png
    ├── 10_tcp_conversations.png
    └── 11_ipv4_conversations.png
```

---

[![LinkedIn](https://img.shields.io/badge/LinkedIn-WilliamInCyber-blue?style=flat&logo=linkedin)](https://linkedin.com/in/WilliamInCyber)
[![X](https://img.shields.io/badge/X-WilliamInCyber-black?style=flat&logo=x)](https://x.com/WilliamInCyber)
