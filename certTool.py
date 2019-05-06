from OpenSSL import crypto


class CertTool:
    def __init__(self, cert):
        with open(cert) as f:
            self.cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

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
        if '*' in _str:
            _str = _str.replace('*', 'star')
        return _str

    def get_cert_object(self, obj):
        if obj == "cn":
            return self.get_cn()