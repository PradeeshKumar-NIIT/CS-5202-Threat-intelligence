import requests
import re

WebUrl = 'https://bazaar.abuse.ch/browse/'
code = requests.get(WebUrl)
plain = code.text
sha = re.findall("[A-Fa-f0-9]{64}", plain)
sha_256 = set(sha)
#Open new data file
f = open("sha256.txt", "w")
for word in sha_256:
	f.write(word)
	f.write('\n')
f.close()
