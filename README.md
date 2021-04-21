# Python Airwatch API CMSURL Authorization Example

Example Python Airwatch API Authentication using CMSURL Authorization. 

This example requires the chilkat package and requests. 

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
