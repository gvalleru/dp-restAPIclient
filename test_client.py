import dpRESTclient
import certTool
import yaml
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
cert_base64 = cert.just_base64(cert_file)
# print cert_base64
cert_file_name = final_cn + '_' + exp_date[:8]
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
cert_create_me = dp.gen_cert_obj(cert_file_name, cert_base64)
