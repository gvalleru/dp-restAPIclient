import dpRESTclient
import yaml


conf_yaml = 'config.template.yaml'
with open(conf_yaml, 'r') as c:
    config = yaml.load(c)

with open('delete_certs.txt') as f:
    delete_certs = f.readlines()
    for line in delete_certs:
        server = str(line.split()[0].replace("'", ""))
        cert = str(line.split()[1].replace("'", ""))
        domain = str(line.split()[2]).replace("'", "")

        if server in config:
            host = config[server]['hostname']
            port = config[server]['port']
            username = config[server]['username']
            password = config[server]['password']
            proxies = config[server]['proxies']
            print "Processing request to remove cert {} from domain {} on {} i.e {}". format(cert,
                                                                                             domain,
                                                                                             server,
                                                                                             host)
            dp = dpRESTclient.DpRestClient(host, port, username, password, proxies)
            dp.remove_cert_in_crypto_val_cred(domain, cert)
            dp.remove_cert_from_domain(domain, cert)
            dp.save_config(domain)

        else:
            print "{0} is not found in {1}. Cant remove {2} from domain {3} on {0}".format(server,
                                                                                           conf_yaml,
                                                                                           cert,
                                                                                           domain)
