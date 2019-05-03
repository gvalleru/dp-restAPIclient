import requests
from requests.auth import HTTPBasicAuth
import json
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class DpRestClient:
    def __init__(self, host, port, username, password, proxies, verify=False):
        self.host = host
        self.port = str(port)
        self.username = username
        self.password = password
        self.proxies = proxies
        self.verify = verify

    def _dp_api_resp_dict(self, url):
        res = requests.get(
            url,
            auth=HTTPBasicAuth(username=self.username, password=self.password),
            proxies=self.proxies,
            verify=self.verify)

        return json.loads(res.content)

    def _get_cert_from_val_cred(self, domain, val_cred, cert_obj):
        crypto_val_cred = None
        certs = None

        if "Certificate" in val_cred:
            if isinstance(val_cred["Certificate"], list):
                for cert in val_cred["Certificate"]:
                    if cert["value"] == cert_obj:
                        val_cred["Certificate"].remove(cert)
                        certs = [i["value"] for i in val_cred["Certificate"]]
                        crypto_val_cred = val_cred["name"]
                        return crypto_val_cred, certs
            else:
                if val_cred["Certificate"]["value"] == cert_obj:
                    del val_cred["Certificate"]
                    certs = None
                    crypto_val_cred = val_cred["name"]
                    return crypto_val_cred, certs

            return crypto_val_cred, certs
        else:
            return crypto_val_cred, certs

    def _update_certs_in_val_cred(self, domain, val_cred, certs):
        url = "https://" + self.host + ":" + self.port + "/mgmt/config/" + domain + "/CryptoValCred/" + val_cred["name"]
        del val_cred['_links']
        val_cred['Certificate'] = certs
        data = json.dumps({"CryptoValCred": val_cred})
        r = requests.put(
            url,
            data=data,
            auth=HTTPBasicAuth(username=self.username, password=self.password),
            proxies=self.proxies,
            verify=self.verify)
        return r.status_code, json.loads(r.content)
        # print self._dp_api_resp_dict(url)

    def save_config(self, domain):
        url = "https://" + self.host + ":" + self.port + "/mgmt/actionqueue/" + domain
        data = '{"SaveConfig":""}'
        res = requests.post(url,
                            data=data,
                            auth=HTTPBasicAuth(username=self.username, password=self.password),
                            proxies=self.proxies,
                            verify=self.verify)
        if res.status_code == 200:
            print "configuration saved"

    def remove_cert_from_domain(self, domain, cert_obj):
        url = "https://" + self.host + ":" + self.port + "/mgmt/config/"+domain+"/CryptoCertificate/"+cert_obj
        res = requests.delete(url,
                              auth=HTTPBasicAuth(username=self.username, password=self.password),
                              proxies=self.proxies,
                              verify=self.verify)
        res_dict = json.loads(res.content)
        if res.status_code == 200:
            print "Certificate object {} deleted from {}".format(cert_obj, domain)
        else:
            print "Issue in removing Cert object {} from {}".format(cert_obj, domain)
            print "Error: {}".format(res_dict["error"])

    def remove_cert_in_crypto_val_cred(self, domain, cert_obj):
        url = "https://"+self.host+":"+self.port+"/mgmt/config/"+domain+"/CryptoValCred"
        res_dict = self._dp_api_resp_dict(url)
        if isinstance(res_dict["CryptoValCred"], list):
            for CryptoValCred in res_dict["CryptoValCred"]:
                final_crypto_val_cred, final_certs = self._get_cert_from_val_cred(domain, CryptoValCred, cert_obj)
                if final_crypto_val_cred is not None:
                    resp_code, resp_content = self._update_certs_in_val_cred(domain, CryptoValCred, final_certs)
                    if resp_code == 200:
                        print "Removed {} from {} on domain {}".format(cert_obj, final_crypto_val_cred,
                                                                       domain)

        else:
            final_crypto_val_cred, final_certs = self._get_cert_from_val_cred(domain,
                                                                              res_dict["CryptoValCred"],
                                                                              cert_obj)
            if final_certs is not None:
                resp_code, resp_content = self._update_certs_in_val_cred(domain, res_dict["CryptoValCred"], final_certs)
                print resp_code
                if resp_code == 200:
                    print "Removed {} from {} in domain {}".format(cert_obj, final_crypto_val_cred, domain)
