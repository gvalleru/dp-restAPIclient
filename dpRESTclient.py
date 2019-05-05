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

    def _dp_api_resp(self, url, method="get", params="", data=""):
        if method == "get":
            res = requests.get(
                url,
                auth=HTTPBasicAuth(username=self.username, password=self.password),
                proxies=self.proxies,
                verify=self.verify,
                params=params)
        elif method == "put":
            res = requests.put(
                url,
                data=data,
                auth=HTTPBasicAuth(username=self.username, password=self.password),
                proxies=self.proxies,
                verify=self.verify)
        elif method == "post":
            res = requests.post(
                url,
                data=data,
                auth=HTTPBasicAuth(username=self.username, password=self.password),
                proxies=self.proxies,
                verify=self.verify)
        elif method == "delete":
            res = requests.delete(
                url,
                auth=HTTPBasicAuth(username=self.username, password=self.password),
                proxies=self.proxies,
                verify=self.verify)

        return res

    def get_domains_list(self):
        url = "https://" + self.host + ":" + self.port + "/mgmt/domains/config/"
        response = self._dp_api_resp(url)
        domains_config = json.loads(response.content)
        domains = []
        for domain_config in domains_config["domain"]:
            domains.append(domain_config["name"])
        return domains

    def get_object_status(self, domain, class_name, object_name):
        path = "/mgmt/config/" + domain + "/" + class_name + "/" + object_name
        url = "https://" + self.host + ":" + self.port + path
        print url
        query = "state=1"
        response = self._dp_api_resp(url, params=query)
        return json.loads(response.content)

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
        response = self._dp_api_resp(url, method="put", data=data)
        return response.status_code, json.loads(response.content)

    def save_config(self, domain):
        url = "https://" + self.host + ":" + self.port + "/mgmt/actionqueue/" + domain
        data = '{"SaveConfig":""}'
        response = self._dp_api_resp(url, method="post", data=data)
        if response.status_code == 200:
            print "configuration saved"
        else:
            print "Unable to save configuration: " + response.content

    def remove_cert_from_domain(self, domain, cert_obj):
        url = "https://" + self.host + ":" + self.port + "/mgmt/config/"+domain+"/CryptoCertificate/"+cert_obj
        response = self._dp_api_resp(url, method="delete")
        res_dict = json.loads(response.content)
        if response.status_code == 200:
            print "Certificate object {} deleted from {}".format(cert_obj, domain)
        else:
            print "Issue in removing Cert object {} from {}".format(cert_obj, domain)
            print "Error: {}".format(res_dict["error"])

    def remove_cert_in_crypto_val_cred(self, domain, cert_obj):
        url = "https://"+self.host+":"+self.port+"/mgmt/config/"+domain+"/CryptoValCred"
        response = self._dp_api_resp(url)
        res_dict = json.loads(response.content)
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
