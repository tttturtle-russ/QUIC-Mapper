# This file is part of Scapy
# Copyright (C) 2007, 2008, 2009 Arnaud Ebalard
#               2015, 2016, 2017 Maxence Tury
#               2019 Romain Perez
# This program is published under a GPLv2 license

"""
TLS client automaton. This makes for a primitive TLS stack.
Obviously you need rights for network access.
"""

import socket
import struct
import threading
import sys
import traceback

from scapy.config import conf
from scapy.utils import repr_hex
from scapy.automaton import select_objects, Message, _ATMT_Command
from scapy.layers.tls.automaton import _TLSAutomaton
from scapy.layers.tls.basefields import _tls_version, _tls_version_options
from scapy.layers.tls.session import tlsSession
from scapy.layers.tls.extensions import (
    TLS_Ext_SupportedGroups,
    TLS_Ext_SupportedVersion_CH,
    TLS_Ext_SignatureAlgorithms,
    TLS_Ext_SupportedVersion_SH,
    TLS_Ext_ServerName,
    ServerName,
)
from scapy.layers.tls.handshake import (
    TLSCertificate,
    TLSCertificateRequest,
    TLSCertificateVerify,
    TLSClientHello,
    TLSClientKeyExchange,
    TLSEncryptedExtensions,
    TLSFinished,
    TLSServerHello,
    TLSServerHelloDone,
    TLSServerKeyExchange,
    TLS13Certificate,
    TLS13ClientHello,
    TLS13ServerHello,
    TLS13HelloRetryRequest,
    TLS13CertificateRequest,
    _ASN1CertAndExt,
)
from scapy.layers.tls.keyexchange_tls13 import (
    TLS_Ext_KeyShare_CH,
    KeyShareEntry,
    TLS_Ext_KeyShare_HRR,
)
from scapy.layers.tls.keyexchange import _TLSSignature
from scapy.layers.tls.record import TLSAlert, TLSChangeCipherSpec, TLSApplicationData
from scapy.layers.tls.crypto.suites import _tls_cipher_suites
from scapy.layers.tls.crypto.groups import _tls_named_groups
from scapy.modules import six
from scapy.packet import Raw
from scapy.compat import bytes_encode

# Added
from scapy.plist import PacketList
from scapy.layers.tls.basefields import _tls_type
from scapy.all import load_layer

load_layer("tls")


class TLSClient(_TLSAutomaton):
    """
    A simple TLS test client automaton. Try to overload some states or
    conditions and see what happens on the other side.

    Rather than with an interruption, the best way to stop this client is by
    typing 'quit'. This won't be a message sent to the server.

    :param server: the server IP or hostname. defaults to 127.0.0.1
    :param dport: the server port. defaults to 4433
    :param server_name: the SNI to use. It does not need to be set
    :param mycert:
    :param mykey: may be provided as filenames. They will be used in
        the handshake, should the server ask for client authentication.
    :param client_hello: may hold a TLSClientHello or SSLv2ClientHello to be
        sent to the server. This is particularly useful for extensions
        tweaking.
    :param version: is a quicker way to advertise a protocol version ("sslv2",
        "tls1", "tls12", etc.) It may be overridden by the previous
        'client_hello'.
    :param data: is a list of raw data to be sent to the server once the
        handshake has been completed. Both 'stop_server' and 'quit' will
        work this way.
    """

    def parse_args(
        self,
        server="127.0.0.1",
        dport=4433,
        server_name=None,
        mycert=None,
        mykey=None,
        client_hello=None,
        version=None,
        data=None,
        ciphersuite=None,
        curve=None,
        **kargs
    ):

        super().parse_args(mycert=mycert, mykey=mykey, **kargs)

        self.current_crypto_material_name = None

        tmp = socket.getaddrinfo(server, dport)
        self.remote_family = tmp[0][0]
        self.remote_ip = tmp[0][4][0]
        self.remote_port = dport
        self.server_name = server_name
        self.local_ip = None
        self.local_port = None
        self.socket = None

        if isinstance(client_hello, (TLSClientHello, TLS13ClientHello)):
            self.client_hello = client_hello
        else:
            self.client_hello = None
        self.advertised_tls_version = None
        if version:
            v = _tls_version_options.get(version, None)
            if not v:
                self.vprint("Unrecognized TLS version option.")
            else:
                self.advertised_tls_version = v

        if isinstance(data, bytes):
            self.data_to_send = [data]
        elif isinstance(data, six.string_types):
            self.data_to_send = [bytes_encode(data)]
        elif isinstance(data, list):
            self.data_to_send = list(bytes_encode(d) for d in reversed(data))
        else:
            self.data_to_send = []
        self.curve = None

        if self.advertised_tls_version == 0x0304:
            self.ciphersuite = 0x1301
            if ciphersuite is not None:
                cs = int(ciphersuite, 16)
                if cs in _tls_cipher_suites.keys():
                    self.ciphersuite = cs
            if conf.crypto_valid_advanced:
                # Default to x25519 if supported
                self.curve = 23  # 29
            else:
                # Or secp256r1 otherwise
                self.curve = 29  # 23
            if curve is not None:
                for (group_id, ng) in _tls_named_groups.items():
                    if ng == curve:
                        if curve == "x25519":
                            if conf.crypto_valid_advanced:
                                self.curve = group_id
                        else:
                            self.curve = group_id

    def _do_control(self, ready, *args, **kargs):
        with self.started:
            self.threadid = threading.currentThread().ident

            # Update default parameters
            a = args + self.init_args[len(args) :]
            k = self.init_kargs.copy()
            k.update(kargs)
            self.parse_args(*a, **k)

            self.packets = PacketList(
                name="session[%s]" % self.__class__.__name__
            )  # noqa: E501

            singlestep = True
            iterator = self._do_iter()
            self.debug(3, "Starting control thread [tid=%i]" % self.threadid)
            # Sync threads
            ready.set()
            try:
                while True:
                    c = self.cmdin.recv()
                    self.debug(5, "Received command %s" % c.type)
                    if c.type == _ATMT_Command.RUN:
                        singlestep = False
                    elif c.type == _ATMT_Command.NEXT:
                        singlestep = True
                    elif c.type == _ATMT_Command.FREEZE:
                        continue
                    elif c.type == _ATMT_Command.STOP:
                        break
                    while True:
                        state = next(iterator)
                        if isinstance(state, self.CommandMessage):
                            break
                        if isinstance(state, self.Breakpoint):
                            c = Message(
                                type=_ATMT_Command.BREAKPOINT, state=state
                            )  # noqa: E501
                            # self.cmdout.send(c)
                            break
                        if singlestep:
                            c = Message(
                                type=_ATMT_Command.SINGLESTEP, state=state
                            )  # noqa: E501
                            # self.cmdout.send(c)
                            break
            except (StopIteration, RuntimeError):
                c = Message(type=_ATMT_Command.END, result=self.final_state_output)
                # self.cmdout.send(c)
            except Exception as e:
                exc_info = sys.exc_info()
                self.debug(
                    3,
                    "Transferring exception from tid=%i:\n%s"
                    % (self.threadid, traceback.format_exception(*exc_info)),
                )  # noqa: E501
                m = Message(
                    type=_ATMT_Command.EXCEPTION, exception=e, exc_info=exc_info
                )  # noqa: E501
                # self.cmdout.send(m)
            self.debug(3, "Stopping control thread (tid=%i)" % self.threadid)
            self.threadid = None

    def get_next_msg(self, socket_timeout=2):
        if self.buffer_in:
            # A message is already available.
            return

        self.socket.settimeout(socket_timeout)
        still_getting_len = True
        grablen = 2
        while still_getting_len or len(self.remain_in) < grablen:
            if grablen == 5 and len(self.remain_in) >= 5:
                grablen = struct.unpack("!H", self.remain_in[3:5])[0] + 5
                still_getting_len = False
            elif grablen == 2 and len(self.remain_in) >= 2:
                byte0, byte1 = struct.unpack("BB", self.remain_in[:2])
                if (byte0 in _tls_type) and (byte1 in [0, 3, 0xFE]):
                    # Retry following TLS scheme. This will cause failure
                    # for SSLv2 packets with length 0x1{4-7}03.
                    grablen = 5
                else:
                    raise Exception("SSLv2 is not supported")
            elif grablen == 5 and len(self.remain_in) >= 5:  # noqa: E501
                grablen = struct.unpack("!H", self.remain_in[3:5])[0] + 5

            if grablen == len(self.remain_in):
                break

            tmp = self.socket.recv(grablen - len(self.remain_in))
            if not tmp:
                break
            else:
                self.remain_in += tmp

        if len(self.remain_in) < 2 or len(self.remain_in) != grablen:
            # Remote peer is not willing to respond
            return

        # gnutls and matrixssl sometimes send strange records with invalid version numbers
        if (
            self.remain_in[:3] == b"\x15\xfe\xfd"
            or self.remain_in[:3] == b"\x15\x00\x00"
        ):
            self.remain_in = b"\x15\x03\x01" + self.remain_in[3:]

        try:
            if byte0 == 0x17 and (
                self.cur_session.advertised_tls_version >= 0x0304
                or self.cur_session.tls_version >= 0x0304
            ):
                p = TLS13(self.remain_in, tls_session=self.cur_session)
                self.remain_in = b""
                self.buffer_in += p.inner.msg
            else:
                p = TLS(self.remain_in, tls_session=self.cur_session)
                self.cur_session = p.tls_session
                self.remain_in = b""
                if isinstance(p, SSLv2) and not p.msg:
                    p.msg = Raw("")
                if (
                    self.cur_session.tls_version is None
                    or self.cur_session.tls_version < 0x0304
                ):
                    self.buffer_in += p.msg
                else:
                    if isinstance(p, TLS13):
                        self.buffer_in += p.inner.msg
                    else:
                        # should be TLS13ServerHello only
                        self.buffer_in += p.msg
        except:
            t = _tls_type[self.remain_in[0]]
            v = _tls_version[struct.unpack(">H", self.remain_in[1:3])[0]]
            l = len(self.remain_in) - 5
            p = TLS(type=t, version=v, len=l)
            p.msg = Raw("")
            self.remain_in = b""
            self.buffer_in += p.msg

        while p.payload:
            if isinstance(p.payload, Raw):
                self.remain_in += p.payload.load
                p = p.payload
            elif isinstance(p.payload, TLS):
                p = p.payload
                if (
                    self.cur_session.tls_version is None
                    or self.cur_session.tls_version < 0x0304
                ):
                    self.buffer_in += p.msg
                else:
                    self.buffer_in += p.inner.msg

    def raise_on_packet(self, pkt_cls, state, get_next_msg=True):
        """
        If the next message to be processed has type 'pkt_cls', raise 'state'.
        If there is no message waiting to be processed, we try to get one with
        the default 'get_next_msg' parameters.
        """
        # Maybe we already parsed the expected packet, maybe not.
        if get_next_msg:
            self.get_next_msg()

        if not self.buffer_in or (
            not isinstance(self.buffer_in[0], pkt_cls)
            and not (
                isinstance(self.buffer_in[0], TLSClientHello)
                and self.cur_session.advertised_tls_version == 0x0304
            )
        ):
            return
        self.cur_pkt = self.buffer_in[0]
        self.buffer_in = self.buffer_in[1:]

    def vprint_sessioninfo(self):
        if self.verbose:
            s = self.cur_session
            v = _tls_version[s.tls_version]
            self.vprint("Version       : %s" % v)
            cs = s.wcs.ciphersuite.name
            self.vprint("Cipher suite  : %s" % cs)
            if s.tls_version >= 0x0304:
                ms = s.tls13_master_secret
            else:
                ms = s.master_secret
            self.vprint("Master secret : %s" % repr_hex(ms))
            if s.server_certs:
                self.vprint("Server certificate chain: %r" % s.server_certs)
            self.vprint()

    def flush_records(self):
        """
        Send all buffered records and update the session accordingly.
        """
        self.msg_to_send = b"".join(p.raw_stateful() for p in self.buffer_out)
        if self.msg_to_send is None or self.msg_to_send == "":
            return False
        self.socket.send_and_receive(self.msg_to_send)
        self.buffer_out = []
        return True

    def init_tls(self):
        self.cur_session = tlsSession(connection_end="client")
        s = self.cur_session
        s.client_certs = self.mycert
        s.client_key = self.mykey
        v = self.advertised_tls_version
        if v:
            s.advertised_tls_version = v
        else:
            default_version = s.advertised_tls_version
            self.advertised_tls_version = default_version

        s = socket.socket(self.remote_family, socket.SOCK_STREAM)
        self.socket = s
        self.socket.connect((self.remote_ip, self.remote_port))
        self.local_ip, self.local_port = self.socket.getsockname()[:2]

    #                           TLS handshake                                 #

    def ClientHello(self):
        self.add_record()
        if self.client_hello:
            p = self.client_hello
        else:
            p = TLSClientHello()
        ext = []
        # Add TLS_Ext_SignatureAlgorithms for TLS 1.2 ClientHello
        if self.cur_session.advertised_tls_version == 0x0303:
            ext += [TLS_Ext_SignatureAlgorithms(sig_algs=["sha256+rsa"])]
        # Add TLS_Ext_ServerName
        if self.server_name:
            ext += TLS_Ext_ServerName(
                servernames=[ServerName(servername=self.server_name)]
            )
        p.ext = ext
        self.add_msg(p)

    def send_ClientHello(self):
        self.flush_records()

    def get_server_responses1(self):
        self.get_next_msg()

    def handle_ServerHello(self):
        """
        XXX We should check the ServerHello attributes for discrepancies with
        our own ClientHello.
        """
        self.raise_on_packet(TLSServerHello, self.HANDLED_SERVERHELLO)

    def handle_ServerCertificate(self):
        if not self.cur_session.prcs.key_exchange.anonymous:
            self.raise_on_packet(TLSCertificate, self.HANDLED_SERVERCERTIFICATE)

    def handle_ServerKeyExchange_from_ServerCertificate(self):
        """
        XXX We should check the ServerKeyExchange attributes for discrepancies
        with our own ClientHello, along with the ServerHello and Certificate.
        """
        self.raise_on_packet(TLSServerKeyExchange, self.HANDLED_SERVERKEYEXCHANGE)

    def handle_CertificateRequest(self):
        """
        XXX We should check the CertificateRequest attributes for discrepancies
        with the cipher suite, etc.
        """
        self.raise_on_packet(TLSCertificateRequest, self.HANDLED_CERTIFICATEREQUEST)

    def handle_ServerHelloDone(self):
        self.raise_on_packet(TLSServerHelloDone, self.HANDLED_SERVERHELLODONE)

    def tls12_Certificate(self, name, cert, key):
        if name != self.current_crypto_material_name:
            self.current_crypto_material_name = name
            if cert:
                self.mycert = cert
                self.cur_session.client_certs = [cert]
            else:
                self.mycert = None
                self.cur_session.client_certs = []
            self.mykey = key
            self.cur_session.client_key = key
            self.current_asn1_certs = [
                _ASN1CertAndExt(cert=c) for c in self.cur_session.client_certs
            ]

        self.add_record()
        self.add_msg(TLSCertificate(certs=self.cur_session.client_certs))

    def tls12_CertificateRequest(self):
        #        if self.client_auth:
        self.add_record()
        self.add_msg(TLSCertificateRequest())

    def ClientKeyExchange(self, c=None):
        self.add_record()
        self.add_msg(TLSClientKeyExchange(exchkeys=c))

    def TLSCertificateVerify(self):
        """
        XXX Section 7.4.7.1 of RFC 5246 states that the CertificateVerify
        message is only sent following a client certificate that has signing
        capability (i.e. not those containing fixed DH params).
        We should verify that before adding the message. We should also handle
        the case when the Certificate message was empty.
        """
        self.add_record()
        # hs_msg = [type(m) for m in self.cur_session.handshake_messages_parsed]
        # if (TLSCertificateRequest not in hs_msg or
        #    self.mycert is None or
        #        self.mykey is None):
        #    return
        self.add_msg(TLSCertificateVerify())

    def ChangeCipherSpec(self):
        self.add_record()
        self.add_msg(TLSChangeCipherSpec())

    def ClientFinished(self):
        self.add_record()
        self.add_msg(TLSFinished())

    def should_send_ClientFlight2(self):
        self.flush_records()

    def get_server_responses2(self):
        self.get_next_msg()

    def handle_ChangeCipherSpec(self):
        self.raise_on_packet(TLSChangeCipherSpec, self.HANDLED_CHANGECIPHERSPEC)

    def handle_Finished(self):
        self.raise_on_packet(TLSFinished, self.HANDLED_SERVERFINISHED)

    #                       end of TLS handshake                              #

    def tls_alert(self, descr=None):
        self.add_record()
        self.add_msg(TLSAlert(level=1, descr=descr))

    def ClientData(self, tls_data=None):
        r"""
        The user may type in:
        GET / HTTP/1.1\r\nHost: testserver.com\r\n\r\n
        Special characters are handled so that it becomes a valid HTTP request.
        """
        if not self.data_to_send:
            data = ""
            if self.is_atmt_socket:
                # Socket mode
                fd = select_objects([self.ioin["tls"]], 0)
                if fd:
                    self.add_record()
                    self.add_msg(TLSApplicationData(data=fd[0].recv()))
                    # raise self.ADDED_CLIENTDATA()
                # raise self.WAITING_SERVERDATA()
            else:
                if tls_data is not None:
                    data = tls_data.encode()
        else:
            data = self.data_to_send.pop()

        self.add_record()
        if tls_data is None:
            self.add_msg(TLSApplicationData())
        else:
            self.add_msg(TLSApplicationData(data=data))

    def should_send_ClientData(self):
        self.flush_records()

    def WAITING_SERVERDATA(self):
        self.get_next_msg(0.3, 1)

    #                         TLS 1.3 handshake                               #

    def tls13_ClientHello(self):
        # we have to use the legacy, plaintext TLS record here
        supported_groups = ["secp256r1", "secp384r1", "x448"]
        if conf.crypto_valid_advanced:
            supported_groups.append("x25519")
        self.add_record(is_tls13=False)
        if self.client_hello:
            p = self.client_hello
        else:
            if self.ciphersuite is None:
                c = 0x1301
            else:
                c = self.ciphersuite
            p = TLS13ClientHello(ciphers=c)

        ext = []
        ext += TLS_Ext_SupportedVersion_CH(versions=["TLS 1.3"])

        ext += TLS_Ext_SupportedGroups(groups=supported_groups)
        ext += TLS_Ext_KeyShare_CH(client_shares=[KeyShareEntry(group=self.curve)])
        ext += TLS_Ext_SignatureAlgorithms(sig_algs=["sha256+rsaepss", "sha256+rsa"])
        # Add TLS_Ext_ServerName
        if self.server_name:
            ext += TLS_Ext_ServerName(
                servernames=[ServerName(servername=self.server_name)]
            )
        p.ext = ext
        self.add_msg(p)

    def tls13_send_ClientFlight1(self):
        self.flush_records()

    def tls13_WAITING_SERVERFLIGHT1(self):
        self.get_next_msg()

    def tls13_handle_ServerHello(self):
        """
        XXX We should check the ServerHello attributes for discrepancies with
        our own ClientHello.
        """
        self.raise_on_packet(TLS13ServerHello, self.TLS13_HANDLED_SERVERHELLO)

    def tls13_handle_HelloRetryRequest(self):
        """
        XXX We should check the ServerHello attributes for discrepancies with
        our own ClientHello.
        """
        self.raise_on_packet(TLS13HelloRetryRequest, self.TLS13_HELLO_RETRY_REQUESTED)

    def tls13_ClientHello_Retry(self):
        s = self.cur_session
        s.tls13_retry = True
        # we have to use the legacy, plaintext TLS record here
        self.add_record(is_tls13=False)
        # We retrieve the group to be used and the selected version from the
        # previous message
        hrr = s.handshake_messages_parsed[-1]
        if isinstance(hrr, TLS13HelloRetryRequest):
            pass
        ciphersuite = hrr.cipher
        if hrr.ext:
            for e in hrr.ext:
                if isinstance(e, TLS_Ext_KeyShare_HRR):
                    selected_group = e.selected_group
                if isinstance(e, TLS_Ext_SupportedVersion_SH):
                    selected_version = e.version

        ext = []
        ext += TLS_Ext_SupportedVersion_CH(versions=[_tls_version[selected_version]])

        ext += TLS_Ext_SupportedGroups(groups=[_tls_named_groups[selected_group]])
        ext += TLS_Ext_KeyShare_CH(client_shares=[KeyShareEntry(group=selected_group)])
        ext += TLS_Ext_SignatureAlgorithms(sig_algs=["sha256+rsaepss"])

        p = TLS13ClientHello(ciphers=ciphersuite, ext=ext)
        self.add_msg(p)

    def tls13_handle_encrytpedExtensions(self):
        self.raise_on_packet(
            TLSEncryptedExtensions, self.TLS13_HANDLED_ENCRYPTEDEXTENSIONS
        )

    def tls13_handle_ChangeCipherSpec(self):
        self.raise_on_packet(TLSChangeCipherSpec, self.TLS13_HANDLED_CHANGE_CIPHER_SPEC)

    def tls13_HANDLED_CHANGE_CIPHER_SPEC(self):
        self.cur_session.middlebox_compatibility = True

    def tls13_should_handle_certificateRequest_from_encryptedExtensions(self):
        """
        XXX We should check the CertificateRequest attributes for discrepancies
        with the cipher suite, etc.
        """
        self.raise_on_packet(
            TLS13CertificateRequest, self.TLS13_HANDLED_CERTIFICATEREQUEST
        )

    def tls13_should_handle_finished_from_encryptedExtensions(self):
        pass

    def tls13_handle_Certificate(self):
        self.raise_on_packet(TLS13Certificate, self.TLS13_HANDLED_CERTIFICATE)

    def tls13_handle_CertificateVerify(self):
        self.raise_on_packet(
            TLSCertificateVerify, self.TLS13_HANDLED_CERTIFICATE_VERIFY
        )

    def tls13_handle_finished(self):
        self.raise_on_packet(TLSFinished, self.TLS13_HANDLED_FINISHED)

    def tls13_PREPARE_CLIENTFLIGHT2(self):
        if self.cur_session.middlebox_compatibility:
            self.add_record(is_tls12=True)
            self.add_msg(TLSChangeCipherSpec())
        self.add_record(is_tls13=True)

    def tls13_Certificate(self, name, cert, key):
        if name != self.current_crypto_material_name:
            self.current_crypto_material_name = name
            if cert:
                self.mycert = cert
                self.cur_session.client_certs = [cert]
            else:
                self.mycert = None
                self.cur_session.client_certs = []
            self.mykey = key
            self.cur_session.client_key = key
            self.current_asn1_certs = [
                _ASN1CertAndExt(cert=c) for c in self.cur_session.client_certs
            ]
        self.add_msg(TLS13Certificate(certs=self.current_asn1_certs))

    def tls13_ClientCertificateVerify(self):
        """
        XXX Section 7.4.7.1 of RFC 5246 states that the CertificateVerify
        message is only sent following a client certificate that has signing
        capability (i.e. not those containing fixed DH params).
        We should verify that before adding the message. We should also handle
        the case when the Certificate message was empty.
        """
        # hs_msg = [type(m) for m in self.cur_session.handshake_messages_parsed]
        # if (TLS13CertificateRequest not in hs_msg or
        #        self.mycert is None or
        #        self.mykey is None):
        #    return self.tls13_should_add_ClientFinished()
        self.add_msg(TLSCertificateVerify())

    def tls13_InvalidCertificateVerify(self, sig_alg=None, sig_val=None):
        self.add_msg(
            TLSCertificateVerify(sig=_TLSSignature(sig_alg=sig_alg, sig_val=sig_val))
        )

    def tls13_ClientFinished(self):
        self.add_msg(TLSFinished())

    def tls13_send_ClientFlight2(self):
        self.flush_records()
