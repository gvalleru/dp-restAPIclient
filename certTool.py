from OpenSSL import crypto
from datetime import datetime
import pytz


class CertTool:
    def __init__(self, cert):
        with open(cert) as f:
            self.cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
        self.my_tz = pytz.timezone('US/Pacific')

    def get_subject(self):
        """
        returns subject name as a dict
        :return: dict
        """
        subject_list = self.cert.get_subject().get_components()
        subject_dict = {k:v for k, v in subject_list}
        return subject_dict

    def get_cn(self):
        """
        returns certificate name as a string
        :return: string
        """
        subject_name = self.get_subject()
        return subject_name['CN']

    @staticmethod
    def normalize_name(_str):
        # Replacing * with star in certificate name
        if '*' in _str:
            _str = _str.replace('*', 'star')

        # Only keeping alphanumeric and . or _ or - in the provided string
        _str = ''.join(e for e in _str if e.isalnum() or e in '._-')
        return _str

    @staticmethod
    def pem_cert_to_base64(cert_file):
        with open(cert_file) as f:
            cert_b64 =f.read()
            cert_b64 = cert_b64.replace('-----BEGIN CERTIFICATE-----', '')
            cert_b64 = cert_b64.replace('-----END CERTIFICATE-----', '')
            cert_b64 = cert_b64.replace('\n', '')
        return cert_b64

    @staticmethod
    def pem_key_to_base64(key_file):
        with open(key_file) as f:
            key_b64 = f.read()
            key_b64 = key_b64.replace('-----BEGIN RSA PRIVATE KEY-----', '')
            key_b64 = key_b64.replace('-----END RSA PRIVATE KEY-----', '')
            key_b64 = key_b64.replace('\n', '')
        return key_b64

    def get_expiry_date(self):
        dt_utc = self.cert.get_notAfter()
        return dt_utc

    def get_cert_object(self, obj):
        if obj == "cn":
            return self.get_cn()
