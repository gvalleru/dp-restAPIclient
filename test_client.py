import dpRESTclient
import certTool
import yaml
import requests

# from OpenSSL import crypto


# testing certTool
cert_file = "C:\Users\gvalleru\Documents\certs\star.gtefinancial.org_08022020.crt.cer"
cert = certTool.CertTool(cert_file)
# print "subject name: {}".format(cert.get_subject())
cn = cert.get_cn()
# print "CN: {}".format(cn)
# print "CN using get_cert_object: {}".format(cert.get_cert_object("cn"))
final_cn = cert.normalize_name(cn)
# print "Normalized CN: {}".format(final_cn)
exp_date = cert.get_expiry_date()
# print "Expiry date: {}".format(exp_date)
cert_base64 = cert.pem_cert_to_base64(cert_file)
# print cert_base64
cert_name = final_cn + '_' + exp_date[:8]
conf_yaml = 'config.yaml'
with open(conf_yaml, 'r') as c:
    config = yaml.load(c)

host = config['10.24.64.71']['hostname']
port = config['10.24.64.71']['port']
username = config['10.24.64.71']['username']
password = config['10.24.64.71']['password']
proxies = config['10.24.64.71']['proxies']

dp = dpRESTclient.DpRestClient(host, port, username, password, proxies)
vcs = dp.get_valcreds_list("AllyDomain")
print vcs
for vc in vcs:
    print dp.get_certs_in_valcred("AllyDomain", vc)
# url = "https://"+host+":"+str(port)+"/mgmt/config/AllyDomain/CryptoValCred"
# x = dp._dp_api_resp(url)
# print x.content

# print dp.get_domains_list()
# cert_file_name = cert_name+".crt"
# create_cert_data = dp.gen_cert_obj(cert_file_name, cert_base64)
# resp = dp.upload_cert("STGWSProxyDomain", "cert", create_cert_data)
# print resp.content
# resp = dp.create_crypto_cert("STGWSProxyDomain", cert_name, "cert:///"+cert_file_name)
# print resp.content
# print dp.get_object_status("STGWSProxyDomain", "CryptoCertificate", cert_name)
