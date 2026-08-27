# SOC-Analyst-PCAP-Nemotodes
SOC Analyst L1 Network Forensics: Investigation of a drive-by FakeUpdates campaign delivering NetSupport RAT, featuring PCAP analysis in Wireshark, Suricata alert triage, and complete IOC attribution


### 🚨 Suricata IDS Alert Breakdown (2024-11-26 Capture)

* **Victim IP Address:** `10.11.26.183`
* **Malicious Domain (FakeUpdates/ZPHP):** `modandcrackedapk[.]com` (`193.42.38[.]139`)
* **NetSupport C2 Server:** `194.180.191[.]64` (Port `443`)

**Key Findings:**
* **Drive-by Initial Access:** Host performed DNS and TLS SNI queries for `modandcrackedapk[.]com`.
* **C2 Activity:** Outbound HTTP POST traffic on Port 443 flagged as **ETPRO TROJAN NetSupport RAT CnC Activity** and **Malicious NetSupport Rat CnC Checkin**.
* **Reconnaissance:** Host executed an automated **NetSupport GeoLocation Lookup Request** to `104.26.1[.]231`.


### 👤 Kerberos Identity Breakdown (`02_kerberos_username.png`)

* **User Account:** `brolf`
* **Domain Realm:** `EASYAS123`
* **Target Host IP:** `10.2.28.88`
* **Domain Controller IP:** `10.2.28.2` (Port `88`)

**Key Findings:**
* **Authentication Request:** Packet 243 captures a Kerberos `AS-REQ` (`krb-as-req`) initiated from host `10.2.28.88` (`DESKTOP-TEYQ2NR`) to the Key Distribution Center (KDC) at `10.2.28.2`.
* **User Identification:** Expansion of `as-req` -> `req-body` -> `cname` confirms the active Windows username as **`brolf`** under the realm **`EASYAS123`**.
* **Filter Used:** `kerberos.CNameString`



### 🌐 DHCP Discovery Traffic Breakdown (`03_dhcp_hostname.png`)

* **Client Source MAC:** `00:e0:4c:68:08:00` (Realtek Semiconductor)
* **Assigned IP Address:** `10.2.28.88`
* **DHCP Gateway Server:** `10.2.28.1`
* **Transaction ID:** `0xba85cbb` (Discover) / `0xafa98645` (Request/ACK)

**Key Findings:**
* **Address Lease Negotiation:** Packet 1 captures an initial broadcast `DHCP Discover` sent to `255.255.255.255` on UDP ports 68/67 to request network configuration parameters.
* **Lease Completion:** Followed by `DHCP Request` (Packets 2 & 103) and the final `DHCP ACK` (Packet 104) assigning IP **`10.2.28.88`** from DHCP Gateway **`10.2.28.1`**.
* **Filter Used:** `dhcp`




### 🕵️‍♂️ NetSupport RAT C2 Traffic Breakdown (`04_netsupport_c2_traffic.png`)

* **Infected Source IP:** `10.2.28.88`
* **C2 Target IP:** `45.131.214.85` (Port `443`)
* **C2 Endpoint URI:** `/fakeurl.htm`
* **User-Agent String:** `NetSupport Manager/1.3`
* **Content Type:** `application/x-www-form-urlencoded`

**Key Findings:**
* **Continuous Beaconing:** Packets starting at Frame 2638 show repetitive outbound HTTP POST requests from host `10.2.28.88` to `http://45.131.214.85/fakeurl.htm` occurring at strict interval beacons.
* **Malware Signature:** The hex payload stream explicitly displays `User-Agent: NetSupport Manager/1.3`, a known indicator of **NetSupport Remote Access Trojan (RAT)** C2 check-in traffic.
* **Filter Used:** `ip.dst == 194.180.191.64 or http.request.uri contains "fakeurl.htm"`




### 📡 Active Directory DNS Query Breakdown (`05_dns_query.png`)

* **Query Source IP:** `10.2.28.88`
* **DNS Server Target IP:** `10.2.28.2` (Port `53`)
* **Query Type:** `SRV` (Service Record)
* **Requested Domain Target:** `_ldap._tcp.Default-First-Site-Name._sites.dc._msdcs.mshome.net`

**Key Findings:**
* **Domain Controller Discovery:** Packet 7 shows an automated standard DNS query (`0x7c4c`) sent from host `10.2.28.88` to local server `10.2.28.2` over UDP port 53.
* **Service Record Lookup:** The host is attempting to locate Active Directory LDAP domain controller services within the network environment by querying the `_ldap._tcp` SRV record structure.
* **Filter Used:** `dns`




### 🗂 LDAP Directory Query Breakdown (`07_ldap_user.png`)

* **Query Source IP:** `10.11.26.183`
* **Domain Controller Target IP:** `10.11.26.3` (Port `389`)
* **Extracted User CN:** `Oliver Q.. Boomwald`
* **Base Distinguished Name (DN):** `CN=Oliver Q.. Boomwald,CN=Users,DC=nemotodes,DC=health`
* **Authentication Method:** `SASL GSS-API Integrity`

**Key Findings:**
* **Directory Search Request:** Frame 21182 displays an encrypted/integrity-protected LDAP `searchRequest` sent from host `10.11.26.183` to Active Directory Domain Controller `10.11.26.3` over TCP port 389.
* **User Attribute Query:** The search targeted specific directory attributes (`givenName`, `sn`, `objectClass`), explicitly revealing user identity **Oliver Q.. Boomwald** within domain `nemotodes.health`.
* **Filter Used:** `ldap.AttributeDescription == "givenName"`





### 🔑 Kerberos Protocol Traffic Overview (`Screenshot 2026-08-27 095845_2.png`)

* **Source IP (Client Host):** `10.2.28.88`
* **Destination IP (Key Distribution Center):** `10.2.28.2` (Port `88`)
* **Extracted User (Hex View):** `brolf`
* **Target Realm (Hex View):** `EASYAS123`

**Key Findings:**
* **Authentication & Ticket Requests:** Wireshark list displays complete Kerberos protocol handshakes, including initial Authentication Service requests/responses (`AS-REQ` / `AS-REP`) starting at Frame 243, followed by Ticket Granting Service exchanges (`TGS-REP`).
* **Client Username Location:** Selected Frame 243 byte stream shows ASCII payload strings containing username **`brolf`** attempting domain authentication against realm **`EASYAS123`**.
* **Filter Used:** `kerberos.CNameString`
