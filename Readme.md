

## Differences between Intrusion Detection System (IDS) and Firewalls

- Firewalls block traffic from untrusted sources, but advanced hackers can easily manipulate this by manipulating the data packet by highjacking or impersonating a trusted machine. 
- **Firewall** Inspects data packet labels
- In contrast IDS - analyzes traffic as well as the malacious signatures- it has the additional capacity to read the data. 
- IDS detects and alerts 

## Intrusion Detection System (IDS)

- Purpose is to enforce a cyber kill chain and capture information in the form of logs
- NIDS and HIDS

- Note that NSM (Network Security monitoring) and IDS are two different things. 

**Network Intrusion Detection System (NIDS)**
- Matches traffic to attack signatures
- Difficult todetect by the attackers
- First line of defence

**Host Based Intrusion System (HIDS)**
- Second line of defence
- Compares files system of the host to baseline and then issues alerts if there are significant differences

-IDS connects via network TAP(test access port) or SPAN (Switched Port Analyzer)
- IDS examins what is flagged

> Components of IDS

- IDS can be connected to a network in two ways
- **Network tap (Test Access Port)** hardware that lets you connect to a network - tracks inbound and outbound data
- **SPAN (Switched Port Analyzer)** Sends an exact copy of a transmission at a port to anayze the traffic

- In IDS if the network tap and the SPAN detect a problem the alert will need to be looked at by the admininstrators. In contrast the IPS will take action when a particular attack is detected 

- MSM= IOA+IOC
- IOA Indicators of attack, when intrusion is occuring and is detected while it is happening
- IOC Indicators of compromise, when attack has previously occurred. 

- Being proactive means identifying the vulnerabilities.



## Intrusion Prevention System- It is different from IDS

- Located b/w firewall and switch(from the attacker's perspctive) in the order (internet, firewall,IPS,Switch)
- Has the capability of responding to an intrusion by blocking traffic from being delivered to a host
- Being reactive means that the system deliverd a response after detecting intrusion

## NSM (Network Security monitoring)

- Its different from IDS
- Devices are placed between 

**Steps**
1. Detection - Alert in Sguil analyst console
2. Collection - Creation of PCAP file (host data, net data, application logs, data from third party, data from constituent)
3. Analysis - Documentation of the alert (IOC centric/matching or IOC free/hunting)
4. Response - The security team then decides to notify the relevant indivisuals about the incident or process containment or remediation 
5. Escalation 
6. Resolution


**Weakness**
- NSM and IDS cannot read encrypted traffic
- Underpoweed hardware
- NSM can be detected by hackers
- Fails when hackers target mobiles and use mobile radio communications

- NSM Sensor Connectivity 

## Snort IDS ( part of Intrusion Detection System) Rules and Alerts

**Steps of operation**
- Reads configuration file that contains the rules
- Loads those rules
- Captures packets for monitoring traffic patterns
- Matches rules with the defined patterns

- `variables`: IP vs TCP data, direction of traffic (source vs destination), byte sequences in the malware


**Components of Snort**
   - Perimeter IDS and IPS architecture
   - Network IDS and IPS architecture
   - Host IDS and IPS architecture

**Modes of Snort**
- Sniffer Mode- Reads packets and load rules
- Packet Logger Mode - Captures packet and loggs all traffic to the disk
- Newtork Intrusion Detection Mode- Matches logged traffic with the administratively defined rules

- `Snort utilizes all three modes`

`alert ip any any -> any any {msg: "IP Packet Detected";}`

`alert tcp any 21 -> 10.199.12.8 any {msg: "TCP Packet Detected";}`
 - The destination ip is the network and the source ip is that of the hacker
   - This rules triggers an alert whenever a TCP packet from port `21`, with any source IP address, is sent to the IP `10.199.12.8`. With each alert, it will print the message "TCP Packet Detected."

   - Rule Header
      - `alert`: The action that Snort will take when triggered. 
      - `tcp`: Applies the rule to all TCP packets.
      - `any`: Applies the rule to packets coming from any source IP address.
      - `21`: Applies the rule to packets from port `21`.
      - `->`: Indicates the direction of traffic.
      - `10.199.12.8`: Applies the rule to any packet with this destination IP address.
      - `any`: Applies the rule to traffic to any destination port.

  - Rule Option

    - `{msg: "TCP Packet Detected";}`: The message printed with the alert.


- `Network Security Monitoring (NSM)` 
- Its main components include network security monitoring (NSM) and security onion
- Network Security Monitoring and the Snort IDS are the sh*t - the next level from firewal
- There are two primary types of IDS

**Signature Based**
- predifined signatures are investigated in the traffic data packets
- Only most effective against well known attacks 
- Need updates with the release of new signatures and the latest versions
- Still can be manipulated, can be tricked by the 

**Anomaly-based** 
- Traffic pattern is compared with the baseline and then you look for any changes
- Prone to give false alerts
- Can detct when a hacker is probing a network
- Can detect zero-day attacks


- Analyzes traffic *like traditional firewall) +malacious signatures in the the data packets
There are other types of IDS, but SNORT is the most popular worldwide
```
NIDS (Network Intrusion Detection System)
HIDS (Host Intrusion Detection System)
IPS (Intrusion Prevention System)
TTPs (Tactics, Techniques and Procedures)
```
- Reading writing and interpreting the snort rules


**Security Onion**
Security Onion NSM suite of tools

- A security Onion is a Linux distribution derived from Ubuntu - It is open source and contains many NSM tools
- It uses IDS as its event-driven mechanism
- `sudo so-replay` to replay multiple PCAPS stored in the `/opt/samples` the latter stores hundreds of PCAPs

- PCAPS are live trafic snapshots captred in a momemnt of time

- Important to know how to replay the PCAPS using wireshirk

- Firewalls make decisions based on the rules set by adminstrators- Hackers can decieve these rules with packet manipulation - Note that firewalls only check labels, but not the actual contents of the  data component of the packet - the later is done with IDS where it specifically looks for specific malacious signatures in the data packet

- Tools of the Security Onion:
- `Sguil` - Pulls rogether alert data form Snort- provides context for alerts, allows queries into alert and session data, helps classify events

- `transcript` - Provides view of PCAP transcripts, imilar to the TCP streams in Wireshark. 

- `NetworkMiner`- advanced network analysis including extration of pertinent data from the PCAP files: Allows the analyst to analyze, reassemble, and regenerate transmitted files and certificates from PCAP files.


- **Security Onion Setup**
- `sudo so-status` Ensure that all statuses are ok 
- `sudo so-restart` If all process statuses are not ok
- `sudo so-replay` after running *Sguil*


# Detecting Hacker's Intrusion or NSM (Network Security Monitoring)
NSM is the process of identifying any weakness in a network. It is the defence in depth approach


- NSM tools - Indicators of Attack (IOA) and Compromise (IOC)


## Inspecting PCAP on WireShark

## Firewal 
Decision regarding  based on the inspection of 
- IPs (source/destination)
- oort number(source/destination)
- protocol

## Cyber Threat hunting
Below are the approaches/
- Analytics Drive hypothosis to investigate
- Intellegence Driven - network forensics-- threat intelligence report 
- Situational Awareness Driven - Mitigate threats
- Tools used: Security Onion, ELK to gain insights into a network's security posture



## Enterprise Security management System using Cyber Threat Hunting

**Security Onion Setup** 