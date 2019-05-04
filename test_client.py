import dpRESTclient
import yaml

conf_yaml = 'config.yaml'
with open(conf_yaml, 'r') as c:
    config = yaml.load(c)

host = config['10.64.1.101']['hostname']
port = config['10.64.1.101']['port']
username = config['10.64.1.101']['username']
password = config['10.64.1.101']['password']
proxies = config['10.64.1.101']['proxies']

dp = dpRESTclient.DpRestClient(host, port, username, password, proxies)
print dp.get_domains_list()
print dp.get_object_status('WSProxyDomain', 'CryptoCertificate', 'aperio-cashedge-prod.adsyf.syfbank.com_08252020')