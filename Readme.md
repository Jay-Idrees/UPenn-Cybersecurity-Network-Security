

## Differences between Intrusion Detection System (IDS) and Firewalls

- Firewalls block traffic from untrusted sources, but advanced hackers can easily manipulate this by manipulating the data packet by highjacking or impersonating a trusted machine. 
- **Firewall** Inspects data packet labels
- In contrast IDS - analyzes traffic as well as the malacious signatures- it has the additional capacity to read the data. 

## Intrusion Detection System

- Purpose is to enforce a cyber kill chain and capture information in the form of logs


**Network Intrusion Detection System (NIDS)**
- Matches traffic to attack signatures
- Difficult todetect by the attackers
- First line of defence

**Host Based Intrusion System (HIDS)**
- Second line of defence
- Compares files system of the host to baseline and then issues alerts if there are significant differences

-IDS connects via network TAP(test access port) or SPAN (Switched Port Analyzer)
- IDS examins what is flagged

## Intrusion Prevention System

- Located b/w firewall and switch(from the attacker's perspctive) in the order (interet, firewall,IPS,Switch)
- 

## Snort IDS ( part of Intrusion Detection System) Rules and Alerts

**Modes of Snort**
- Sniffer Mode- Reads packets and load rules
- Packet Logger Mode - Captures packet and loggs all traffic to the disk
- Newtork Intrusion Detection Mode- Matches logged traffic with the loaded rules

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


- `Network Security Monitoring` 
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

- A security Onion is a Linux distribution derived from Ubuntu 
- It uses IDS as its event-driven mechanism
- `sudo so-replay` to replay multiple PCAPS stored in the `/opt/samples` the latter stores hundreds of PCAPs

- PCAPS are live trafic snapshots captred in a momemnt of time

- Important to know how to replay the PCAPS using wireshirk

- Firewalls make decisions based on the rules set by adminstrators- Hackers can decieve these rules with packet manipulation - Note that firewalls only check labels, but not the actual contents of the  data component of the packet - the later is done with IDS where it specifically looks for specific malacious signatures in the data packet




# Detecting Hacker's Intrusion or NSM (Network Security Monitoring)
NSM is the process of identifying any weakness in a network




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


## NSM tools - Indicators of Attack (IOA) and Compromise (IOC)


