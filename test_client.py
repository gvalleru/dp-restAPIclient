import dpRESTclient
import yaml
from OpenSSL import crypto

with open("C:\Users\gvalleru\Documents\certs\star.gtefinancial.org_08022020.crt.cer") as f:
    my_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
print my_cert.get_notAfter()
x = my_cert.get_subject().get_components()
print x
y = {k:v for k, v in x}
cn = y['CN']
print cn
if '*' in cn:
    print "true"
    cn = cn.replace('*', 'star')
    print cn




conf_yaml = 'config.yaml'
with open(conf_yaml, 'r') as c:
    config = yaml.load(c)

host = config['10.64.1.101']['hostname']
port = config['10.64.1.101']['port']
username = config['10.64.1.101']['username']
password = config['10.64.1.101']['password']
proxies = config['10.64.1.101']['proxies']

dp = dpRESTclient.DpRestClient(host, port, username, password, proxies)
# print dp.get_domains_list()
print dp.get_object_status('WSProxyDomain', 'CryptoCertificate', 'aperio-cashedge-prod.adsyf.syfbank.com_08252020')