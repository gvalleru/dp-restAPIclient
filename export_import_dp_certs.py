import dpRESTclient
import certTool
import yaml
import json
import base64
import xml.etree.ElementTree as ET
import os
from collections import defaultdict


def export_cert_files(conf_dp_yaml, certs_import_yaml, export_from_dp, c_dir):
    with open(conf_dp_yaml, 'r') as c:
        config_dp = yaml.load(c)

    with open(certs_import_yaml, 'r') as f:
        certs_to_import = yaml.load(f)

    if export_from_dp in config_dp:
        host = config_dp[export_from_dp]['hostname']
        port = config_dp[export_from_dp]['port']
        username = config_dp[export_from_dp]['username']
        password = config_dp[export_from_dp]['password']
        proxies = config_dp[export_from_dp]['proxies']
    else:
        print "Datapower server not in {}".format(conf_dp_yaml)
        exit(1)

    dp_from = dpRESTclient.DpRestClient(host, port, username, password, proxies=proxies)

    # CryptoExport is not active in version 7.5 yet. So, used CLI to
    # copy cert files to DP's temporary dir
    # os.makedirs(certs_dir)

    for domain in certs_to_import["domains_from"]:
        print "Changing dir to {}".format(c_dir)
        os.chdir(c_dir)
        print "domain name: {}".format(domain["name"])
        os.mkdir(domain['name'])
        print "Changing dir to {}".format(domain['name'])
        os.chdir(domain['name'])
        for cert in domain["certs"]:
            cert_path = "temporary/" + cert
            resp = dp_from.get_file(domain["name"], cert_path)
            resp_dict = json.loads(resp.content)

            if "error" in resp_dict.keys():
                print resp_dict["error"]
            elif "file" in resp_dict.keys():
                file_base64 = resp_dict["file"]
                file_decoded = base64.b64decode(file_base64)
                # print file_decoded
                root = ET.fromstring(file_decoded)
                cert_base64 = root.find('certificate').text
                with open(cert + ".crt", 'w') as f:
                    f.write("-----BEGIN CERTIFICATE-----\n")
                    f.write(cert_base64+"\n")
                    f.write("-----END CERTIFICATE-----\n")


def upload_create_certobjs(conf_yaml, certs_to_import_yaml, import_to, certs_dir):
    with open(conf_yaml, 'r') as f:
        config = yaml.load(f)

    if import_to in config:
        host = config[import_to]['hostname']
        port = config[import_to]['port']
        username = config[import_to]['username']
        password = config[import_to]['password']
        proxies = config[import_to]['proxies']
        dp = dpRESTclient.DpRestClient(host, port, username, password)
        # Start of uploading certs to JC DP and saving domain to certs mapping in dest_valcred_certs

        with open(certs_to_import_yaml) as f:
            my_dict = yaml.load(f)
            domain_mapping = my_dict["domains_src_dest_mapping"]
            for mapping in domain_mapping:
                src_domain = mapping['src']
                dest_domain = mapping['dest']
                src_dir = os.path.join(certs_dir, src_domain)
                for filename in os.listdir(src_dir):
                    if filename.endswith(".crt") or filename.endswith(".cer"):
                        certs_abs_path = os.path.join(src_dir, filename)
                        print "Domain: {}: Processing cert file: {}".format(dest_domain, certs_abs_path)
                        cert = certTool.CertTool(certs_abs_path)
                        cn = cert.get_cn()
                        final_cn = cert.normalize_name(cn)
                        exp_date = cert.get_expiry_date()
                        cert_base64 = cert.pem_cert_to_base64(certs_abs_path)
                        cert_name = final_cn + '_' + exp_date[:8]
                        cert_file_name = cert_name + ".crt"
                        create_cert_data = dp.gen_cert_obj(cert_file_name, cert_base64)
                        resp = dp.upload_cert(dest_domain, "cert", create_cert_data)
                        print resp.content
                        # resp = dp.create_crypto_cert(dest_domain, cert_name, "cert:///" + cert_file_name)
                        # print resp.content
                        dest_valcred_certs[dest_domain].append(cert_name)
                        ## dp.remove_cert_from_domain(dest_domain, cert_name)
                        ## print dp.del_file(dest_domain, "cert/"+cert_file_name)
        print dest_valcred_certs

        if dest_valcred_certs:
            print "valid dest_valcred_certs"
            # Start of adding certs to Val cred's. Not working
            #
            # for domain, certs_list in zip(dest_valcred_certs.keys(), dest_valcred_certs.values()):
            #     print domain
            #     val_cred_obj = dp.get_val_cred_obj(domain, 'CryptoValCred_CEClientsDigSigVal')
            #     del val_cred_obj['_links']
            #     # val_cred_obj['CryptoValCred']['Certificate'] = ['server_cert']
            #     certs_list.append('server_cert')
            #     val_cred_obj['CryptoValCred']['Certificate'] = certs_list
            #     print val_cred_obj
            #     print dp.create_newcertlinks_val_cred(domain, val_cred_obj)
            #     dp.save_config(domain)

            # End of adding certs to Val cred's. Not working

        # End of uploading certs to JC DP and saving domain to certs mapping in dest_valcred_certs
    else:
        print "Datapower server not in {}".format(conf_yaml)
        return False


conf_yaml = 'config.yaml'
certs_to_import_yaml = 'certs_in_temp.yaml'
certs_to_import_certenv_yaml = 'certs_in_temp_certenv.yaml'
export_from = "10.32.35.10"
export_from_cert = "10.64.1.101"
import_to = "10.24.64.74"
certs_dir = "C:\Users\gvalleru\Documents\datapower\clientcerts"
dest_valcred_certs = defaultdict(list)

# export_cert_files(conf_yaml, certs_to_import_yaml, export_from, certs_dir)
# export_cert_files(conf_yaml, certs_to_import_certenv_yaml, export_from_cert, certs_dir)

upload_create_certobjs(conf_yaml, certs_to_import_yaml, import_to, certs_dir)




# Tesing - Ignore below
# print certTool.CertTool('C:\Users\gvalleru\Documents\datapower\issue certs\WSProxyDomain\sms.fnb-online.mobi.com_10232020.crt')
# print certTool.CertTool('C:\Users\gvalleru\Documents\datapower\SMS.FNB-ONLINE.MOBI.cer')
# print dp.get_certs_in_valcred('CertCommonDomain', 'CryptoValCred_CEClientsDigSigVal')
# dest_valcred_certs = {'CapOneWSDomain': ['b2b-client.capitalone.com_20190811'], 'AllyCertDomain': ['bits-pay-ws-nonprod.ally.com_20191010'], 'CEDomainPod2': ['b2b-igw.efidelity.com_20200202', 'Charles Schwab & Co., Inc._20200917', 'IntelligentPortfolioFiservSigning.schwab.com_20191230', 'tiaa-cref-web-service-consumer.tiaa-cref.org_20210127', 'VerifyNow-Salem5-20061-prod.fivision.com_20200511', 'webservicesgateway.schwab.com_20190913', 'ws.ft.cashedge.com_20190802', 'xml-b2b-igw.efidelity.com_20191201', 'mub-ceclient-prd.purepoint.com_20191123', 'ubceclient.unionbank.com_20210107', 'oaofiserv.regions.com_20201021', 'rxpmobile.regions.com_20200318', 'cashedge.mynycb.com_20200308', 'cashedge.mynycb.com_20200314', 'cashedge.mynycb.com_20190601', 'mbprod.prkcorp.com_20201010', 'star.gtefinancial.org_20200802', 'tp.sdccu.com_20201103', 'VoyagerTP.comerica.com_20200209', 'ws.popmoney.bbtnet.com_20200119'], 'CEDomainPod1': ['aperio-cashedge-prod.adsyf.syfbank.com_20200825', 'apisvcs-gtwy-mauth.suntrust.com_20200320', 'apisvcs-gtwy-mauth.suntrust.com_20190719', 'bac-outbound.onefiserv.net_20191108', 'bbp-prod.associatedbank.com_20201001', 'builder.bankofthewest.com_20200311', 'builder.bankofthewest.com_20190818', 'cashedge-17.americafirst.com_20200829', 'cashedge.golden1.com_20201012', 'cashedge.mynycb.com_20200314', 'cashedge.mynycb.com_20190601', 'cashedgesigning.eastwestbank.com_20191219', 'cashedgesso.bfsfcu.org_20200117', 'cashedgesvc.fnb-onlinebankingcenter.com_20210122', 'cashedgesvc.fnb-onlinebankingcenter.com_20210122', 'ciam.bmo.com_20200508', 'citigroupsoa.dsig.citigroup.com_20200514', 'esb.compassbnk.com_20200418', 'ets.nationwide.com_20200611', 'ExternalTransferSvc.Becu.org_20191204', 'fiserv-ups-messagebroker-pi-prod.fmr.com_20190615', 'gtcrd-cblla01p.nam.nsroot.net_20191110', 'mwdal.app.syfbank.com_20191207', 'mwdal.app.syfbank.com_20191207', 'mwphx.app.syfbank.com_20200417', 'mxp.afcu.kivagroup.com_20210104', 'olb-uswiprap1.nam.nsroot.net_20191004', 'p2pservices.prd1.digitalinsight.com_20190803', 'pgw.53.com_20200507', 'pr-client.bmoharris.avoka-transact.com_20190917', 'pr-client.hsbc-na.transactcentral.com_20190521', 'pr-client.investorsbank.avoka-transact.com_20190909', 'prod.esb.corp.citizensbank.com_20190716', 'prodfnapidaa.firstrepublic.com_20210320', 'sfprod.valleynationalbank.com_20200906', 'soa.tdgroup.com_20191118', 'soa.tdgroup.com_20201230', 'transferapi.firstrepublic.com_20210509', 'VerifyNow-DimeCommBank-20074-prod.fivision.com_20200424', 'VerifyNow-Salem5-20061-prod.fivision.com_20200511', 'VoyagerTP.comerica.com_20200209', 'www.onlinebanking.pnc.com_20200621', 'citigroupsoa.dsig.citigroup.com_20200514'], 'AllyDomain': ['bits-pay-ws-prod.ally.com_20191210'], 'CertCommonDomain': ['aperio-cashedge-situat.adsyf.syfbank.com_20200804', 'apisvcs-gtwy-mauth-nonprod.suntrust.com_20200320', 'bits-pay-ws-nonprod.ally.com_20191010', 'cashedge-test-17.americafirst.com_20200818', 'cashedgeqa.golden1.com_20201002', 'ceclient.unionbank.com_20201205', 'certfnapidaa.frbnp3.com_20210320', 'certws.ft.cashedge.com_20191010', 'ExternalTransfersTest.Messaging.BECU.org_20210326', 'np-client.bmoharris.avoka-transact.com_20190917', 'qa.esb.corp.citizensbank.com_20190605', 'qa.esb.corp.citizensbank.com_20200429', 'sf.valleynationalbank.com_20200809', 'zelle.testqa.zionsbank.com_20200207', 'zellepro.santanderbank.com_20200206']}

