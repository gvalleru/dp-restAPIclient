import requests
from requests.auth import HTTPBasicAuth
import json
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class DpRestClient:
    """
    Datapower documentation:
    https://www.ibm.com/support/knowledgecenter/en/SS9H2Y_7.7.0/com.ibm.dp.doc/restmgtinterface.html
    """
    def __init__(self, host, port, username, password, proxies='{}', verify=False):
        self.host = host
        self.port = str(port)
        self.username = username
        self.password = password
        self.proxies = proxies
        self.verify = verify

    def _dp_api_resp(self, url, method="get", params="", data=""):
        """
        private method which will return http response. Default http method is
        get, if you want to different method then pass it to method parm. Also
        to pass query string use parms option, data to post or put data.
        """
        if self.proxies != "{}":
            if method.lower() == "get":
                res = requests.get(
                    url,
                    auth=HTTPBasicAuth(username=self.username, password=self.password),
                    proxies=self.proxies,
                    verify=self.verify,
                    params=params)
            elif method.lower() == "put":
                res = requests.put(
                    url,
                    data=data,
                    auth=HTTPBasicAuth(username=self.username, password=self.password),
                    proxies=self.proxies,
                    verify=self.verify)
            elif method.lower() == "post":
                res = requests.post(
                    url,
                    data=data,
                    auth=HTTPBasicAuth(username=self.username, password=self.password),
                    proxies=self.proxies,
                    verify=self.verify)
            elif method.lower() == "delete":
                res = requests.delete(
                    url,
                    auth=HTTPBasicAuth(username=self.username, password=self.password),
                    proxies=self.proxies,
                    verify=self.verify)
            else:
                res = "Method "+method+" not supported"
        else:
            if method.lower() == "get":
                res = requests.get(
                    url,
                    auth=HTTPBasicAuth(username=self.username, password=self.password),
                    verify=self.verify,
                    params=params)
            elif method.lower() == "put":
                res = requests.put(
                    url,
                    data=data,
                    auth=HTTPBasicAuth(username=self.username, password=self.password),
                    verify=self.verify)
            elif method.lower() == "post":
                res = requests.post(
                    url,
                    data=data,
                    auth=HTTPBasicAuth(username=self.username, password=self.password),
                    verify=self.verify)
            elif method.lower() == "delete":
                res = requests.delete(
                    url,
                    auth=HTTPBasicAuth(username=self.username, password=self.password),
                    verify=self.verify)
            else:
                res = "Method " + method + " not supported"

        return res

    def get_domains_list(self):
        """
        It will return all the domains in a list including default domain. Its up to user
        to ignore default domain.
        :return: list
        """
        url = "https://" + self.host + ":" + self.port + "/mgmt/domains/config/"
        response = self._dp_api_resp(url)
        domains_config = json.loads(response.content)
        domains = []
        for domain_config in domains_config["domain"]:
            domains.append(domain_config["name"])
        return domains

    def get_object_status(self, domain, class_name, object_name):
        """
        :param domain: name of the datapower domain
        :param class_name: class name. Ex: CryptoCertificate, CryptoIdentCred, CertMonitor, SSLProxyProfile, HTTPSSourceProtocolHandler
        :param object_name: name of the object with in the class name. Ex: cert obj name, https handler name
        :return: dict response about full status of object_name
        """
        path = "/mgmt/config/" + domain + "/" + class_name + "/" + object_name
        url = "https://" + self.host + ":" + self.port + path
        print url
        query = "state=1"
        response = self._dp_api_resp(url, params=query)
        return json.loads(response.content)

    def _return_val_cred_without_input_cert(self, val_cred, cert_obj):
        """
        This is a private method which will remove cert_obj with val_cred dict object. Returns name of
        crypto val cred and the new list of certs that are to be under crypto val cred by excluding
        cert_obj.
        :param val_cred: validation cred object
        :param cert_obj: cert_obj to be removed from validation cred object
        :return: Returns a tulip that contains val_cred_object and new list of cert of objects. If there
        is only one cert obj then a string is returned. If no cert_obj's left then None is returned.
        """
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

    def create_newcertlinks_val_cred(self, domain, val_cred):
        val_cred_name = val_cred['CryptoValCred']['name']
        print val_cred_name
        url = "https://"+self.host+ ":"+self.port+"/mgmt/config/"+domain+"/CryptoValCred/"+val_cred_name
        data = json.dumps(val_cred)
        resp = self._dp_api_resp(url, method="PUT", data=data)
        return json.loads(resp.content)

    # This is for internal purpose only
    def update_certs_in_val_cred(self, domain, val_cred, certs):
        """
        There is no add or remove operations for list of cert obj's under a val cred. So, to do this operation
        we its just to get list of certs obj's then added or remove cert to or from that list and then add
        that cert obj's lists to val cred.
        :param domain: domain under which you want to perform this operation.
        :param val_cred: val cred under which you want to update list of certs. These certs are new certs linked
        to this val cred.
        :param certs: list of cert obj's that will be new certs under val cred.
        :return: tulip with response code and dict obj with the response of putting new cert obj's to val cred.
        """
        url = "https://" + self.host + ":" + self.port + "/mgmt/config/" + domain + "/CryptoValCred/" + val_cred["name"]
        del val_cred['_links']
        val_cred['Certificate'] = certs
        data = json.dumps({"CryptoValCred": val_cred})
        response = self._dp_api_resp(url, method="put", data=data)
        return response.status_code, json.loads(response.content)

    def save_config(self, domain):
        """
        Save the configuration after making changes to a domain.
        :param domain: domain name
        :return: None
        """
        url = "https://" + self.host + ":" + self.port + "/mgmt/actionqueue/" + domain
        data = '{"SaveConfig":""}'
        response = self._dp_api_resp(url, method="post", data=data)
        if response.status_code == 200:
            print "configuration saved"
        else:
            print "Unable to save configuration: " + response.content

    def remove_cert_from_domain(self, domain, cert_obj):
        """
        Remove a cert obj from a domain.
        :param domain: domain in which you want to perform this change.
        :param cert_obj: cert obj you want to remove with in a domain.
        :return: None
        """
        url = "https://" + self.host + ":" + self.port + "/mgmt/config/"+domain+"/CryptoCertificate/"+cert_obj
        response = self._dp_api_resp(url, method="delete")
        res_dict = json.loads(response.content)
        if response.status_code == 200:
            print "Certificate object {} deleted from {}".format(cert_obj, domain)
        else:
            print "Issue in removing Cert object {} from {}".format(cert_obj, domain)
            print "Error: {}".format(res_dict["error"])

    def del_file(self, domain, file_path):
        url = "https://"+self.host+":"+self.port+"/mgmt/filestore/"+domain+"/"+file_path
        resp = self._dp_api_resp(url, method="delete")
        resp_dict = json.loads(resp.content)
        return resp_dict

    @staticmethod
    def gen_cert_obj(cert_name, content):
        """
        :param cert_name: Name of certificate file
        :param content: Content of the certificate in base64
        :return: dict object format to create cert file
        """
        cert_obj = {
                    "file": {
                            "name": "",
                            "content": ""
                            }
                    }
        cert_obj["file"]["name"] = cert_name
        cert_obj["file"]["content"] = content
        return cert_obj

    def upload_file(self, domain, _dir, file_dict):
        url = "https://"+self.host+":"+self.port+"/mgmt/filestore/"+domain+"/"+_dir
        file_json = json.dumps(file_dict)
        resp = self._dp_api_resp(url, method="post", data=file_json)
        return resp

    def upload_cert(self, domain, _dir, cert_file_dict):
        resp = self.upload_file(domain, _dir, cert_file_dict)
        return resp

    def get_file(self, domain, path):
        url = "https://"+self.host+":"+self.port+"/mgmt/filestore/"+domain+"/"+path
        resp = self._dp_api_resp(url)
        return resp

    def create_crypto_cert(self, domain, crypto_cert_name, cert_filename):

        url = "https://"+self.host+":"+self.port+"/mgmt/config/"+domain+"/CryptoCertificate"
        data = {"CryptoCertificate":
                    {"name": "",
                     "mAdminState": "enabled",
                     "Filename": "",
                     "Password": "",
                     "PasswordAlias": "off",
                     "Alias": "",
                     "IgnoreExpiration": "on"
                     }
                }
        data["CryptoCertificate"]["name"] = crypto_cert_name
        data["CryptoCertificate"]["Filename"] = cert_filename
        data_json = json.dumps(data)
        resp = self._dp_api_resp(url, method="POST", data=data_json)
        return resp

    def get_valcreds_list(self, domain):
        '''

        :param domain: Name of the datapower domain
        :return: Returns list of validation credentials
        '''
        valcreds = []
        url = "https://" + self.host + ":" + self.port + "/mgmt/config/" + domain + "/CryptoValCred"
        resp = self._dp_api_resp(url)
        resp_dict = json.loads(resp.content)
        vc = resp_dict["CryptoValCred"]
        if isinstance(vc, list):
            for CryptoValCred in vc:
                valcreds.append(CryptoValCred["name"])
        else:
            valcreds.append(vc["name"])
        return valcreds

    def get_certs_in_valcred(self, domain, val_cred):
        '''

        :param domain: Name of the datapower domain
        :param val_cred: Name of the validation cred.
        :return: Returns list of cert names from val_cred under domain
        '''
        certs = []
        url = "https://" + self.host + ":" + self.port + "/mgmt/config/" + domain + "/CryptoValCred/" + val_cred
        resp = self._dp_api_resp(url)
        # print resp.content
        resp_dict = json.loads(resp.content)
        if "error" in resp_dict.keys():
            return resp_dict["error"]
        elif "Certificate" in resp_dict['CryptoValCred'].keys():
            certs_obj = resp_dict['CryptoValCred']['Certificate']
            if isinstance(certs_obj, list):
                for cert in certs_obj:
                    certs.append(cert["value"])
            else:
                certs.append(certs_obj["value"])
            return certs
        else:
            return []

    def get_val_cred_obj(self, domain, valcred_name):
        url = "https://"+self.host+":"+self.port+"/mgmt/config/"+domain+"/CryptoValCred/"+valcred_name
        response = self._dp_api_resp(url)
        return json.loads(response.content)

    def remove_cert_in_crypto_val_cred(self, domain, cert_obj):
        """
        This method will remove a certificate object from any of the validation cred objects
        with in a provided domain.
        :param domain: domain in which you want to perform this operation.
        :param cert_obj: cert obj you want to remove from all the val cred's under a domain.
        :return: None
        """
        url = "https://"+self.host+":"+self.port+"/mgmt/config/"+domain+"/CryptoValCred"
        response = self._dp_api_resp(url)
        res_dict = json.loads(response.content)
        # Inconsistent response from datapower for CryptoValCred is that if there is only one
        # CryptoValCred in a domain the return type is string, if more than one CryptoValCred
        # then return type is list. Whats up with that IBM. Please be consistent with your 
        # data type. So, we are handing this inconsistency with isinstance builtin method.
        if isinstance(res_dict["CryptoValCred"], list):
            for CryptoValCred in res_dict["CryptoValCred"]:
                final_crypto_val_cred, final_certs = self._return_val_cred_without_input_cert(CryptoValCred, cert_obj)
                if final_crypto_val_cred is not None:
                    resp_code, resp_content = self.update_certs_in_val_cred(domain, CryptoValCred, final_certs)
                    if resp_code == 200:
                        print "Removed {} from {} on domain {}".format(cert_obj, final_crypto_val_cred,
                                                                       domain)
        else:
            final_crypto_val_cred, final_certs = self._return_val_cred_without_input_cert(
                                                                            res_dict["CryptoValCred"],
                                                                            cert_obj)
            if final_certs is not None:
                resp_code, resp_content = self.update_certs_in_val_cred(domain, res_dict["CryptoValCred"], final_certs)
                print resp_code
                if resp_code == 200:
                    print "Removed {} from {} in domain {}".format(cert_obj, final_crypto_val_cred, domain)
