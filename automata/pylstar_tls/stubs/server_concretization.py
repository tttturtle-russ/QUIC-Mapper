from scapy.layers.tls.cert import Cert, PrivKey, PrivKeyRSA

from stubs.server import TLSServer


class InfererTools:
    def __init__(self, local_endpoint, crypto_material, timeout, accept_timeout):
        self.local_endpoint = local_endpoint
        self.crypto_material = crypto_material
        self.timeout = timeout
        self.accept_timeout = accept_timeout
        self.fresh_rsa_key = PrivKeyRSA()

    def initTLS13Connexion(self):
        """
        Start listening the TLS Client connexion
        """
        cert, key = self.crypto_material.default_material()
        host, port = self.local_endpoint.as_tuple()
        server = TLSServer(
            server=host,
            sport=port,
            mycert=cert,
            mykey=key,
            curve="secp256r1",
            timeout=self.timeout,
            accept_timeout=self.accept_timeout,
        )
        server.BIND()
        return server

    def concretize_server_messages(self, tls_session, symbols):
        for symbol in symbols:
            if symbol == "TLS12ServerHello":
                tls_session.tls12_ServerHello(is_rsa_export=False)
            elif symbol == "TLS12ServerHello_RSA_EXPORT":
                tls_session.tls12_ServerHello(is_rsa_export=True)
            elif symbol == "TLS12ServerKeyExchange":
                tls_session.tls12_ServerKeyExchange()
            elif symbol == "TLS12CertificateRequest":
                tls_session.tls12_CertificateRequest()
            elif symbol == "TLS12Certificate":
                cert, key = self.crypto_material.default_material()
                tls_session.tls12_Certificate("**default**", Cert(cert), PrivKey(key))
            elif symbol.startswith("TLS12Certificate_"):
                name = symbol.split("_", 1)[1]
                cert, key = self.crypto_material.get_material(name)
                tls_session.tls12_Certificate(name, Cert(cert), PrivKey(key))
            elif symbol == "TLS12EmptyCertificate":
                tls_session.tls12_Certificate("", None, self.fresh_rsa_key)
            elif symbol == "TLS12ServerHelloDone":
                tls_session.tls12_ServerHelloDone()
            elif symbol == "TLSChangeCipherSpec":
                tls_session.tls12_ChangeCipherSpec()
            elif symbol == "TLS13ServerHello":
                tls_session.tls13_ServerHello()
            elif symbol == "TLS13SH_WITH_00_RandBytes":
                tls_session.tls13_ServerHello(random_bytes=b"\x00" * 32)
            elif symbol == "TLS13HelloRetryRequest":
                tls_session.tls13_HelloRetryRequest()
            elif symbol == "TLS13EncryptedExtensions":
                tls_session.tls13_EncryptedExtensions()
            elif symbol == "TLS13CertificateRequest":
                tls_session.tls13_CertificateRequest()
            elif symbol == "TLS13Certificate":
                cert, key = self.crypto_material.default_material()
                tls_session.tls13_Certificate("**default**", Cert(cert), PrivKey(key))
            elif symbol.startswith("TLS13Certificate_"):
                name = symbol.split("_", 1)[1]
                cert, key = self.crypto_material.get_material(name)
                tls_session.tls13_Certificate(name, Cert(cert), PrivKey(key))
            elif symbol == "TLS13EmptyCertificate":
                tls_session.tls13_Certificate("", None, self.fresh_rsa_key)
            elif symbol == "TLS13CertificateVerify":
                tls_session.tls13_CertificateVerify()
            elif symbol == "TLS13InvalidCertificateVerify":
                tls_session.tls13_InvalidCertificateVerify()
            elif symbol == "TLSFinished":
                tls_session.tls13_Finished()
            elif symbol == "TLSApplicationData":
                tls_session.should_handle_ClientData(
                    "GET / HTTP/1.1\r\nHost: simple.org\r\n\r\n"
                )
                tls_session.should_send_ServerData()
            elif symbol == "TLSApplicationDataEmpty":
                tls_session.should_handle_ClientData()
                tls_session.should_send_ServerData()
            elif symbol == "TLSCloseNotify":
                tls_session.tls_fatal_alert(descr=0)
            elif symbol == "NoRenegotiation":
                tls_session.tls_fatal_alert(descr=100)
            else:
                print(f"Unknown vocabulary :: {symbol}")
                raise Exception(f"Unknown vocabulary :: {symbol}")
