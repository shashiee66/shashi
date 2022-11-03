
 
set PATH=%PATH%;C:\TH_SCL_v3.23.0\thirdPartyCode\openssl\tmwDLLsBuiltWith2010\32Bit\Release
 
mkdir certs
type nul > certs\index.txt
echo unique_subject=no > certs\index.txt.attr
echo 01 > certs\serial
  
  
# Generate the Authority DSA keys
openssl dsaparam -out ca_dsaparam.pem 1024
openssl req -newkey dsa:ca_dsaparam.pem -sha1 -keyout TMWTestAuthorityDsa1024PrvKey.pem -out ca_dsa1024.csr -config ca.cnf -passout pass:triangle
openssl x509 -req -in ca_dsa1024.csr -sha1 -extfile ca.cnf -extensions certificate_extensions -signkey TMWTestAuthorityDsa1024PrvKey.pem -days 9999 -out TMWTestAuthorityDsa1024Cert.pem -passin pass:triangle
openssl dsa -in TMWTestAuthorityDsa1024PrvKey.pem -out TMWTestAuthorityDsa1024PubKey.pem -pubout -outform PEM -passin pass:triangle

openssl dsaparam -out ca_dsaparam.pem 2048
openssl req -newkey dsa:ca_dsaparam.pem  -sha256 -keyout TMWTestAuthorityDsa2048PrvKey.pem -out ca_dsa2048.csr  -config ca.cnf  -passout pass:triangle
openssl x509 -req -in ca_dsa2048.csr -sha256 -extfile ca.cnf  -extensions certificate_extensions   -signkey TMWTestAuthorityDsa2048PrvKey.pem  -days 9999 -out TMWTestAuthorityDsa2048Cert.pem -passin pass:triangle
openssl dsa -in TMWTestAuthorityDsa2048PrvKey.pem -out TMWTestAuthorityDsa2048PubKey.pem -pubout -outform PEM -passin pass:triangle

openssl dsaparam -out ca_dsaparam.pem 3072
openssl req -newkey dsa:ca_dsaparam.pem  -sha256 -keyout TMWTestAuthorityDsa3072PrvKey.pem -out ca_dsa3072.csr  -config ca.cnf  -passout pass:triangle 
openssl x509 -req -in ca_dsa3072.csr -sha256 -extfile ca.cnf -extensions certificate_extensions -signkey TMWTestAuthorityDsa3072PrvKey.pem -days 9999 -out TMWTestAuthorityDsa3072Cert.pem -passin pass:triangle
openssl dsa -in TMWTestAuthorityDsa3072PrvKey.pem -out TMWTestAuthorityDsa3072PubKey.pem -pubout -outform PEM -passin pass:triangle

# Generate User DSA keys and X.509 Certificates and sign them.
openssl dsaparam -out dsa_param.pem 1024
openssl req -newkey dsa:dsa_param.pem -sha1 -keyout TMWTestUserDsa1024PrvKey.pem -out dsa1024.csr -days 9999 -config user.cnf -subj "/CN=Common/C=US/ST=North Carolina/L=Raleigh/O=Triangle MicroWorks, Inc./" -passout pass:triangle
openssl ca -in dsa1024.csr -out TMWTestUserDsa1024Cert.pem -cert TMWTestAuthorityDsa1024Cert.pem -keyfile TMWTestAuthorityDsa1024PrvKey.pem -config ca.cnf -passin pass:triangle -outdir certs -batch -noemailDN
openssl dsa -in TMWTestUserDsa1024PrvKey.pem  -out TMWTestUserDsa1024PubKey.pem -pubout -outform PEM -passin pass:triangle
  
openssl dsaparam -out dsa_param.pem 2048 
openssl req -newkey dsa:dsa_param.pem -sha256 -keyout TMWTestUserDsa2048PrvKey.pem -out dsa2048.csr -days 9999 -config user.cnf -subj "/CN=Common/C=US/ST=North Carolina/L=Raleigh/O=Triangle MicroWorks, Inc./" -passout pass:triangle
openssl ca -in dsa2048.csr -out TMWTestUserDsa2048Cert.pem -cert TMWTestAuthorityDsa2048Cert.pem -keyfile TMWTestAuthorityDsa2048PrvKey.pem -config ca.cnf -passin pass:triangle -outdir certs  -batch -noemailDN
openssl dsa -in TMWTestUserDsa2048PrvKey.pem  -out TMWTestUserDsa2048PubKey.pem -pubout -outform PEM -passin pass:triangle

openssl dsaparam -out dsa_param.pem 3072 
openssl req -newkey dsa:dsa_param.pem -sha256 -keyout TMWTestUserDsa3072PrvKey.pem -out dsa3072.csr -days 9999 -config user.cnf -subj "/CN=Common/C=US/ST=North Carolina/L=Raleigh/O=Triangle MicroWorks, Inc./" -passout pass:triangle
openssl ca -in dsa3072.csr -out TMWTestUserDsa3072Cert.pem -cert TMWTestAuthorityDsa3072Cert.pem -keyfile TMWTestAuthorityDsa3072PrvKey.pem -config ca.cnf -passin pass:triangle -outdir certs -batch -noemailDN
openssl dsa -in TMWTestUserDsa3072PrvKey.pem  -out TMWTestUserDsa3072PubKey.pem -pubout -outform PEM -passin pass:triangle


#Generate RSA private keys for Outstation
openssl genrsa -out TMWTestOSRsa1024PrvKey.pem 1024
openssl rsa -in TMWTestOSRsa1024PrvKey.pem -out TMWTestOSRsa1024PubKey.pem -pubout -outform PEM

openssl genrsa -out TMWTestOSRsa2048PrvKey.pem 2048
openssl rsa -in TMWTestOSRsa2048PrvKey.pem -out TMWTestOSRsa2048PubKey.pem -pubout -outform PEM

openssl genrsa -out TMWTestOSRsa3072PrvKey.pem 3072
openssl rsa -in TMWTestOSRsa3072PrvKey.pem -out TMWTestOSRsa3072PubKey.pem -pubout -outform PEM


# Generate the Authority RSA keys and the User RSA keys and Certificates and sign them for DNP3 TB2016-002
openssl genrsa -out TMWTestAuthorityRsa1024PrvKey.pem 1024 -config ca.cnf -passout pass:triangle 
openssl rsa -in TMWTestAuthorityRsa1024PrvKey.pem -out TMWTestAuthorityRsa1024PubKey.pem -pubout -outform PEM 
#this seems to come close, but think it is using 256 for signing... test this...
openssl x509 -req -in ca_dsa1024.csr -extfile ca.cnf -extensions certificate_extensions -signkey TMWTestAuthorityRsa1024PrvKey.pem -days 9999 -out TMWTestAuthorityRsa1024Cert.pem -passin pass:triangle
openssl genrsa -out TMWTestUserRsa1024PrvKey.pem 1024
openssl rsa -in TMWTestUserRsa1024PrvKey.pem -out TMWTestUserRsa1024PubKey.pem -pubout -outform PEM
openssl ca -in dsa1024.csr -out TMWTestUserRsa1024Cert.pem -cert TMWTestAuthorityRsa1024Cert.pem -keyfile TMWTestAuthorityRsa1024PrvKey.pem -config ca.cnf -passin pass:triangle -outdir certs -batch -noemailDN
 
openssl genrsa -out TMWTestAuthorityRsa2048PrvKey.pem 2048 -config ca.cnf -passout pass:triangle 
openssl rsa -in TMWTestAuthorityRsa2048PrvKey.pem -out TMWTestAuthorityRsa2048PubKey.pem -pubout -outform PEM
openssl x509 -req -in ca_dsa2048.csr -extfile ca.cnf -extensions certificate_extensions -signkey TMWTestAuthorityRsa2048PrvKey.pem -days 9999 -out TMWTestAuthorityRsa2048Cert.pem -passin pass:triangle
openssl genrsa -out TMWTestUserRsa2048PrvKey.pem 2048
openssl rsa -in TMWTestUserRsa2048PrvKey.pem -out TMWTestUserRsa2048PubKey.pem -pubout -outform PEM
openssl ca -in dsa2048.csr -out TMWTestUserRsa2048Cert.pem -cert TMWTestAuthorityRsa2048Cert.pem -keyfile TMWTestAuthorityRsa2048PrvKey.pem -config ca.cnf -passin pass:triangle -outdir certs -batch -noemailDN

openssl genrsa -out TMWTestAuthorityRsa3072PrvKey.pem 3072 -config ca.cnf -passout pass:triangle 
openssl rsa -in TMWTestAuthorityRsa3072PrvKey.pem -out TMWTestAuthorityRsa3072PubKey.pem -pubout -outform PEM
openssl x509 -req -in ca_dsa3072.csr -extfile ca.cnf -extensions certificate_extensions -signkey TMWTestAuthorityRsa3072PrvKey.pem -days 9999 -out TMWTestAuthorityRsa3072Cert.pem -passin pass:triangle
openssl genrsa -out TMWTestUserRsa3072PrvKey.pem 3072
openssl rsa -in TMWTestUserRsa3072PrvKey.pem -out TMWTestUserRsa3072PubKey.pem -pubout -outform PEM
openssl ca -in dsa3072.csr -out TMWTestUserRsa3072Cert.pem -cert TMWTestAuthorityRsa3072Cert.pem -keyfile TMWTestAuthorityRsa3072PrvKey.pem -config ca.cnf -passin pass:triangle -outdir certs -batch -noemailDN

 
del *.csr
del dsa_param.pem
del ca_dsaparam.pem
del  /Q certs
rmdir certs