import requests
from requests.auth import HTTPBasicAuth

res = requests.post('https://dmzdp3.mes1.prod.ce:5554/mgmt/actionqueue/default', data='{"SaveConfig":""}', auth=HTTPBasicAuth(username='admin', password='Cashedge1$'), proxies = {'https': 'http://localhost:3128'}, verify=False)
print res.content
print res.status_code
print res.text
