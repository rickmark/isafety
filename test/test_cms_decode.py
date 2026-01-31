#!/usr/bin/env python

from OpenSSL.crypto import *

PROVISION_PATH = '/Users/rickmark/embedded.provisionprofile'

with open(PROVISION_PATH, "rb") as file:
    data = file.read()

    message = load_pkcs7_data(FILETYPE_ASN1, data)

    print(message)
