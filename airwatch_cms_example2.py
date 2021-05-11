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


