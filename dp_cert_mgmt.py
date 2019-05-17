import dpRESTclient
import certTool
import yaml

cert_file = "C:\Users\gvalleru\Documents\certs\clientssl.cashedge.com.crt"
key_file = "C:\Users\gvalleru\Documents\certs\clientssl.cashedge.com.key"
cert = certTool.CertTool(cert_file)
cn = cert.get_cn()
final_cn = cert.normalize_name(cn)
exp_date = cert.get_expiry_date()
cert_base64 = cert.pem_cert_to_base64(cert_file)
key_base64 = cert.pem_key_to_base64(key_file)
cert_name = final_cn + '_' + exp_date[:8]
conf_yaml = 'config.yaml'
with open(conf_yaml, 'r') as c:
    config = yaml.load(c)

host = config['10.24.64.71']['hostname']
port = config['10.24.64.71']['port']
username = config['10.24.64.71']['username']
password = config['10.24.64.71']['password']
# proxies = config['10.24.64.71']['proxies']

dp = dpRESTclient.DpRestClient(host, port, username, password)
print dp.get_domains_list()

cert_file_name = cert_name+".crt"
key_file_name = cert_name+".key"
create_cert_data = dp.gen_cert_obj(cert_file_name, cert_base64)
create_key_data = dp.gen_cert_obj(key_file_name, key_base64)
resp = dp.upload_cert("default", "sharedcert", create_cert_data)
print resp.content

resp = dp.upload_cert("default", "sharedcert", create_key_data)
print resp.content

# resp = dp.create_crypto_cert("FiservDomain", cert_name, "sharedcert:///"+cert_file_name)
# print resp.content
# print dp.get_object_status("FiservDomain", "CryptoCertificate", cert_name)
