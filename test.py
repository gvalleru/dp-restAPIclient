import requests
from requests.auth import HTTPBasicAuth
import json
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

res = requests.get("https://dmzdp3.mes1.prod.ce:5554/mgmt/domains/config/",
            auth=HTTPBasicAuth(username="admin", password="Cashedge1$"),
            proxies={"https": "http://localhost:3128"},
            verify=False)
j = json.loads(res.content)
# print j["domain"][0]["name"]
# print j["domain"].get("name")
for domains in j["domain"]:
    print domains["name"]
