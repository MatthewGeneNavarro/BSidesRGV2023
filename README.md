# NTLM Hardening for busy Sysadmins

### The NTLM family. 

Its important to audit your environment to see if you still have LM/NTLMv1 enabled. [If you do, it is recommend to enforce NTLMv2 and refuse LM & NTLMv1](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level).

###### Lan Manager --can allow for downgrade attacks
- Lan Manager Authentication Protocol 
- Lan Manager Hashing Algorithim

###### New Technology Lan Manager --can allow for downgrade attacks
- New Technology Lan Manager Authentication Protocol
- NT Hashing Algorithim

###### New Technology Lan Manager version 2
- New Technology Lan Manager version 2 Authentication Protocol
- NT Hashing Algorithim


###### Disabling LM & NTLMv1
How do we know what computers have LM/NTLMv1 version support. Here is what Microsoft has to say about it.  

> In Windows 7 and Windows Vista, this setting is undefined. In Windows Server 2008 R2 and later, this  is configured to **Send NTLMv2 responses only**.
> \- [Microsoft ](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level)

Operating System | Default Policy Value
---|---
Windows 2000 | send LM & NTLM responses
Windows XP | send LM & NTLM responses
Windows server 2003 | Send NTLM responses
Windows Vista | Send NTLMv2 response only
Windows Server 2008 |Send NTLMv2 response only
Windows 7 | Send NTLMv2 response only
Windows 2008 R2 | Send NTLMv2 response only
Windows 10 | not defined/do not change
Windows Server 2016 | not defined/do not change



###### Controlling NTLM Version usage via Group Policy Object
`Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options`

**Network security: LAN Manager authentication level**
- Send LM & NTLM responses
- Send LM & NTLM - use NTLMv2 session security if negotiated
- Send NTLM responses only
- Send NTLMv2 responses only
- Send NTLMv2 responses only. Refuse LM
- Send NTLMv2 responses only. Refuse LM & NTLM  <== Recommend option

###### Controlling NTLM Version usage via Registry
This is the path to the Registry key that would allow a sysadmin to control what NTLM family protocol is negotiated on the network.
`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel`

Key Type: DWORD (32-bit) 
Key Name: LmCompatibilityLevel
Key Value and corresponding behavior:
- 0: Send LM & NTLM responses
- 1: Send LM & NTLM - use NTLMv2 sessions security if negotiated
- 2: Send NTLM responses only
- 3: Send NTLMv2 responses only
- 4:Send NTLMv2 responses only. Refuse LM
- 5: Send NTLMv2 responses only. Refuse LM & NTLM <== Recommended Option 

```powershell
# To navigate to the key
(Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel")

# If you dont have the key and need to create it
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value $DesiredBehavior -PropertyType DWORD
```


### Server Message Block Mitigations
To prevent NTLM Relaying via the SMB Protocol you need to enable SMB Signing.
 
###### Controlling SMB signing via Group Policy Object
Path to SMB signing policy
`Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options`

The name of the policies.
- Microsoft network client: Digitally sign communications (always) = Enabled
- Microsoft network server: Digitally sign communications (always) = Enabled
You want to enforce the (always) policy on both clients and servers, and you want to apply **both** of those policies to workstations and servers. The reason is this, Server/client roles are interchangable. There is no hard requirement that a windows 10 computer can ONLY act as a client. A Windows 10 computer can act in the server role if the proper conditions are met.

###### Auditing SMB signing
To find machines that are not signing SMB, you can use CrackMapExec
look for SMBv1 service running and consider disabling. 
Windows 10 versions older than 1709 may have SMBv1 installed by default.
```python
crackmapexec smb $ip-subnet/CIDR --gen-relay-list relaytargets.txt
```

Some Microsoft SMB security links:
https://techcommunity.microsoft.com/t5/storage-at-microsoft/configure-smb-signing-with-confidence/ba-p/2418102
https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/using-computer-name-aliases-in-place-of-dns-cname-records/ba-p/259064
https://techcommunity.microsoft.com/t5/itops-talk-blog/how-to-defend-users-from-interception-attacks-via-smb-client/ba-p/1494995
https://techcommunity.microsoft.com/t5/itops-talk-blog/beyond-the-edge-how-to-secure-smb-traffic-in-windows/ba-p/1447159


### Link Layer Multicast Name Resolution Mitigation
###### Turning off LLMNR
Path to GPO policy
`Computer Configuration => Policies => Administrative Templates => Network => DNS Client`
Turn off multicast name resolution == ENABLED

##### Auditing your broadcast traffic
https://github.com/lgandx/Responder 
Must be ran on linux. I recommend you do a Kali vm.

Make sure you use the -A tack, -A is analyze and it will just passive sniff traffic.
```python
Responder -I <interface_with_internal_IP> -A
```



### LDAP Mitigations
To prevent NTLM Relaying via the LDAP Protocol you need to enable LDAP Signing.

This one is a little more complicated, and you run the risk of clients being unable to establish a LDAP session with the Domain Controller so ill just refer you to the documentation haha :P
https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/enable-ldap-signing-in-windows-server

It is also recommend that you add additional protection by enabling Channel Binding
https://msrc.microsoft.com/update-guide/en-US/vulnerability/ADV190023



## NTLM Hunting
Enable NTLM auditing. This will create 8001, 8003, 8004 logs.

Policy | Event ID | Where to enable
---|---|---
Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers = Audit All | 8001 | Servers and Clients
Network security: Restrict NTLM: Audit Incoming NTLM Traffic = Enable auditing for all accounts | 8003| Servers and Clients
Network security: Restrict NTLM: Audit NTLM authentication in this domain = Enable all | 8004| Servers and Clients

https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/ntlm-blocking-and-you-application-analysis-and-auditing/ba-p/397191
