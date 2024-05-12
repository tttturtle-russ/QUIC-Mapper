import os
import struct

from scapy.layers.tls.handshake import TLSClientHello
from scapy.layers.tls.basefields import _tls_version_options
from scapy.layers.tls.cert import Cert, PrivKey, PrivKeyRSA

from stubs.client import TLSClient
from stubs.cke_factory import CKEFactory


class InfererTools:
    def __init__(self, remote_endpoint, crypto_material, tls_version):
        self.remote_endpoint = remote_endpoint
        self.tls_version = tls_version
        self.crypto_material = crypto_material
        self.fresh_rsa_key = PrivKeyRSA()
        if self.tls_version in ["tls10", "tls11", "tls12"]:
            self.public_key = self._get_public_key()
            self.construct = CKEFactory(
                self.public_key, _tls_version_options[self.tls_version]
            )

    def get_tls_session(self):
        host, port = self.remote_endpoint.as_tuple()
        client = TLSClient(
            server=host,
            dport=port,
            version=self.tls_version,
        )
        client.init_tls()
        return client

    def _get_public_key(self):
        tls = self.get_tls_session()
        tls.client_hello = TLSClientHello(ciphers=[0x35])
        tls.ClientHello()
        tls.send_ClientHello()
        tls.get_next_msg()
        tls.buffer_in = tls.buffer_in[1:]
        tls.get_next_msg()
        cert = tls.buffer_in[0].certs[0][1]
        os.close(tls.socket.fileno())
        return cert.pubKey.pubkey

    def get_cke_content(self, cke_msg_type):
        enc_key = None
        if cke_msg_type == "TLS12CKE_ok":
            enc_key = self.construct.produce_valid_cke()
        elif cke_msg_type == "TLS12CKE_0002_modified":
            enc_key = self.construct.produce_cke_with_0002_modified()
        elif cke_msg_type == "TLS12CKE_padding_inf_8":
            enc_key = self.construct.produce_cke_with_small_padding()
        elif cke_msg_type == "TLS12CKE_key_null":
            enc_key = self.construct.produce_cke_with_no_msg()
        elif cke_msg_type == "TLS12CKE_wrong_tls_version":
            enc_key = self.construct.produce_cke_with_wrong_tls_version()
        elif cke_msg_type == "TLS12CKE_longer_pms":
            enc_key = self.construct.produce_cke_with_longer_pms()
        elif cke_msg_type == "TLS12CKE_shorten_pms":
            enc_key = self.construct.produce_cke_with_shorter_pms()
        else:
            print(f"Unknown vocabulary :: {cke_msg_type}")
            raise Exception(f"Unknown vocabulary :: {cke_msg_type}")

        enc_key = struct.pack("!H", len(enc_key)) + enc_key
        return enc_key

    def concretize_client_messages(self, tls_session, symbols):
        for symbol in symbols:
            if symbol == "TLS12ClientHelloRSA":
                tls_session.client_hello = TLSClientHello(ciphers=[0x35])
                tls_session.ClientHello()
            elif symbol == "TLS12ClientHelloDH":
                tls_session.client_hello = TLSClientHello(ciphers=0x39)
                tls_session.ClientHello()
            elif symbol == "TLS12CH_WITH_00_RandBytes":
                tls_session.client_hello = TLSClientHello(
                    ciphers=[0x35, 0x39], random_bytes=b"00" * 32
                )
                tls_session.ClientHello()
            elif symbol == "TLS12EmptyCertificate":
                tls_session.tls12_Certificate("", None, self.fresh_rsa_key)
            elif symbol.startswith("TLS12Certificate_"):
                name = symbol.split("_", 1)[1]
                cert, key = self.crypto_material.get_material(name)
                tls_session.tls12_Certificate(name, Cert(cert), PrivKey(key))
            elif symbol == "TLS12CertificateRequest":
                tls_session.tls12_CertificateRequest()
            elif symbol == "TLS12ClientKeyExchange":
                tls_session.ClientKeyExchange()
            elif symbol == "TLSChangeCipherSpec":
                tls_session.ChangeCipherSpec()
            elif symbol == "TLSHardCodedFinished":
                continue
            elif symbol == "TLSFinished":
                tls_session.ClientFinished()
            elif symbol == "TLSApplicationData":
                tls_session.ClientData("GET / HTTP/1.1\r\nHost: testserver.com\r\n\r\n")
            elif symbol == "TLSApplicationDataEmpty":
                tls_session.ClientData()
            elif symbol == "TLSCloseNotify":
                tls_session.tls_alert(descr=0)
            elif symbol == "NoRenegotiation":
                tls_session.tls_alert(descr=100)
            elif symbol == "TLS13ClientHello":
                tls_session.tls13_ClientHello()
            elif symbol == "TLS13ClientHelloRetry":
                tls_session.tls13_ClientHello_Retry()
            elif symbol.startswith("TLS13Certificate_"):
                name = symbol.split("_", 1)[1]
                cert, key = self.crypto_material.get_material(name)
                tls_session.tls13_Certificate(name, Cert(cert), PrivKey(key))
            elif symbol == "TLS13EmptyCertificate":
                tls_session.tls13_Certificate("", None, self.fresh_rsa_key)
            elif symbol == "TLSCertificateVerify":
                tls_session.TLSCertificateVerify()
            elif symbol == "TLSInvalidCertificateVerify":
                tls_session.tls13_InvalidCertificateVerify(
                    sig_alg="md5+anon",
                    sig_val=b"This is definitely NOT a valid signature",
                )
            elif symbol.startswith("TLS12CKE_"):
                tls_session.ClientKeyExchange(self.get_cke_content(symbol))
            else:
                print(f"Unknown vocabulary :: {symbol}")
                raise Exception(f"Unknown vocabulary :: {symbol}")