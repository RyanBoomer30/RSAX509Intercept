import subprocess
import base64
from lxml import etree
import sys

def get_modulus_exponent():
    # Extract modulus
    modulus_hex = subprocess.check_output(
        ["openssl", "rsa", "-in", "key.pem", "-modulus", "-noout"]
    ).decode().strip().split('=')[1]
    modulus_bytes = bytes.fromhex(modulus_hex)
    modulus_base64 = base64.b64encode(modulus_bytes).decode('utf-8')
    
    # Extract exponent
    exponent_hex = subprocess.check_output(
        ["openssl", "rsa", "-in", "key.pem", "-text", "-noout"]
    ).decode().split('publicExponent: ')[1].split(' ')[0]
    exponent_int = int(exponent_hex)
    exponent_base64 = base64.b64encode(exponent_int.to_bytes((exponent_int.bit_length() + 7) // 8, byteorder='big')).decode('utf-8')
    
    return modulus_base64, exponent_base64

def insert_rsa_key_value(input_xml_path):
    # Read the input XML file
    with open(input_xml_path, 'r') as file:
        saml_string = file.read()
    
    # Parse the SAML string
    root = etree.fromstring(saml_string)

    # Get modulus and exponent
    modulus_base64, exponent_base64 = get_modulus_exponent()

    # Define the RSAKeyValue tag to insert
    rsa_key_value = etree.Element("RSAKeyValue")
    modulus = etree.SubElement(rsa_key_value, "Modulus")
    modulus.text = modulus_base64
    exponent = etree.SubElement(rsa_key_value, "Exponent")
    exponent.text = exponent_base64

    # Find the X509Data tag and insert the RSAKeyValue tag before it
    ns = {'ds': 'http://www.w3.org/2000/09/xmldsig#'}
    for x509_data in root.findall(".//ds:X509Data", namespaces=ns):
        parent = x509_data.getparent()
        parent.insert(parent.index(x509_data), rsa_key_value)

    # Convert the modified XML back to a string
    modified_saml_string = etree.tostring(root, pretty_print=True, encoding='unicode')

    # Print the modified XML
    print(modified_saml_string)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Wrong input. Correct usage: python script.py input.xml")
        sys.exit(1)
    
    input_xml_path = sys.argv[1]
    insert_rsa_key_value(input_xml_path)