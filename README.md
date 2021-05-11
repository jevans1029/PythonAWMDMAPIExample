# Python Airwatch API CMSURL Authorization Example
Example Python Airwatch API Authentication using CMSURL Authorization. 

This example requires the cryptography package. 

```python
import base64
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs7
import requests

host = "example.awmdm.com"
signing_data = "/api/mdm/devices/bulksettings" # the part of the url to be signed

url = "https://" + host + signing_data
certfile = open("certificate.p12", 'rb')
cert = certfile.read()
certfile.close()


#p12 format holds both a key and a certificate
key, certificate, additional_certs = pkcs12.load_key_and_certificates(cert, password="password".encode(), backend=None)



options = [pkcs7.PKCS7Options.NoCapabilities,  pkcs7.PKCS7Options.DetachedSignature]


signed_data = pkcs7.PKCS7SignatureBuilder().set_data(
    signing_data.encode("UTF-8")).add_signer(certificate, key, hashes.SHA1()).sign(serialization.Encoding.DER, options)
    
signed_data = base64.b64encode(signed_data)

signed_data = signed_data.decode()


headers = {
    "User-Agent": "username",
    "aw-tenant-code": "api_key",
    "Host": host,
    "Authorization": "CMSURL'1 {}".format(signed_data),
    'accept': 'application/json',
    "version": "1",
}
response = requests.get(url, headers=headers)
print(response.content)
```
# Example 2 Python Airwatch API Authentication using CMSURL Authorization. 

This example requires the chilkat package and requests. 

```python
# Python example for CMSURL authorization to the Airwatch/Workspace One API using chilkat

import chilkat
import requests


crypt = chilkat.CkCrypt2()


# Create cert object
cert = chilkat.CkCert()

# PKCS12 certificates contain both the certificate and private key
# This needs the path to the certificate and the password to access it
cert.LoadPfxFile("certpath", "certpassword")

# Set the signing certificate
crypt.SetSigningCert(cert)
# Indicate we want the resulting signature in base64 format:
crypt.put_EncodingMode("base64")

# Convert to utf-8 byte string before signing
crypt.put_Charset("utf-8")

# This is the part of the url that needs signed:
signing_url = "/api/mdm/devices/bulksettings"

# host and full url
host = "example.awmdm.com"
url = "https://" + host + signing_url


# Signed data in base 64 format
signed = crypt.signStringENC(signing_url)


# Generate headers
headers = {
           
            "aw-tenant-code": api_key,
            "Host": host ,
            "Authorization": "CMSURL'1 {}".format(signed), # This is the format of the authorization header
            'accept': 'application/json',
        }

response = requests.get(url, headers=headers)
```
