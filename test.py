
# string = "www_12-3.com"
# print ''.join(e for e in string if e.isalnum() or e in '._-')
x = {

        "_links" : {

        "self" : {"href" : "/mgmt/config/AllyDomain/CryptoValCred"},

        "doc" : {"href" : "/mgmt/docs/config/CryptoValCred"}},

        "CryptoValCred" : {"name" : "CryptoValCred_CEClientsDigSigVal",

        "_links" : {

        "self" : {"href" : "/mgmt/config/AllyDomain/CryptoValCred/CryptoValCred_CEClientsDigSigVal"},

        "doc" : {"href" : "/mgmt/docs/config/CryptoValCred"}},

        "mAdminState" : "enabled",

        "Certificate" : [{"value": "bits-pay-ws-prod.ally.com_20191210",

        "href" : "/mgmt/config/AllyDomain/CryptoCertificate/bits-pay-ws-prod.ally.com_20191210"}, {"value": "server_cert",

        "href" : "/mgmt/config/AllyDomain/CryptoCertificate/server_cert"}],

        "CertValidationMode" : "legacy",

        "UseCRL" : "on",

        "RequireCRL" : "off",

        "CRLDPHandling" : "ignore",

        "InitialPolicySet" : "2.5.29.32.0",

        "ExplicitPolicy" : "off",

        "CheckDates" : "on"}}

print x["CryptoValCred"]["Certificate"]
