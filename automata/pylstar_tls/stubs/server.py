# This file is part of Scapy
# Copyright (C) 2007, 2008, 2009 Arnaud Ebalard
#               2015, 2016, 2017 Maxence Tury
#               2019 Romain Perez
# This program is published under a GPLv2 license

"""
TLS server automaton. This makes for a primitive TLS stack.
Obviously you need rights for network access.

We support versions SSLv2 to TLS 1.3, along with many features.

In order to run a server listening on tcp/4433:
> from scapy.all import *
> t = TLSServer(mycert='<cert.pem>', mykey='<key.pem>')
> t.run()
"""

from __future__ import print_function
import socket
import struct

import threading, sys, traceback

from scapy.packet import Raw
from scapy.pton_ntop import inet_pton
from scapy.utils import repr_hex
from scapy.layers.tls.automaton import _TLSAutomaton
from scapy.layers.tls.cert import PrivKeyRSA, PrivKeyECDSA
from scapy.layers.tls.basefields import _tls_version
from scapy.layers.tls.session import tlsSession
from scapy.layers.tls.crypto.groups import _tls_named_groups
from scapy.layers.tls.extensions import (
    TLS_Ext_SupportedVersion_SH,
    TLS_Ext_Cookie,
    TLS_Ext_SignatureAlgorithms,
)
from scapy.layers.tls.keyexchange import _TLSSignature
from scapy.layers.tls.keyexchange_tls13 import (
    TLS_Ext_KeyShare_SH,
    KeyShareEntry,
    TLS_Ext_KeyShare_HRR,
)
from scapy.layers.tls.handshake import (
    TLSCertificate,
    TLSCertificateRequest,
    TLSCertificateVerify,
    TLSClientHello,
    TLSClientKeyExchange,
    TLSFinished,
    TLSServerHello,
    TLSServerHelloDone,
    TLSServerKeyExchange,
    _ASN1CertAndExt,
    TLS13ServerHello,
    TLS13Certificate,
    TLS13ClientHello,
    TLSEncryptedExtensions,
    TLS13HelloRetryRequest,
    TLS13CertificateRequest,
)
from scapy.layers.tls.record import TLSAlert, TLSChangeCipherSpec, TLSApplicationData
from scapy.layers.tls.record_tls13 import TLS13
from scapy.layers.tls.crypto.suites import (
    get_usable_ciphersuites,
)

from scapy.plist import PacketList
from scapy.automaton import Message, _ATMT_Command
from scapy.layers.tls.basefields import _tls_type
from scapy.all import load_layer


load_layer("tls")


class TLSServer(_TLSAutomaton):
    """
    A simple TLS test server automaton. Try to overload some states or
    conditions and see what happens on the other side.

    Because of socket and automaton limitations, for now, the best way to
    interrupt the server is by sending him 'stop_server'. Interruptions with
    Ctrl-Z should work, but this might leave a loose listening socket behind.

    In case the server receives a TLSAlert (whatever its type), or a 'goodbye'
    message in a SSLv2 version, he will close the client session with a
    similar message, and start waiting for new client connections.

    _'mycert' and 'mykey' may be provided as filenames. They are needed for any
    server authenticated handshake.
    _'preferred_ciphersuite' allows the automaton to choose a cipher suite when
    offered in the ClientHello. If absent, another one will be chosen.
    _'is_echo_server' means that everything received will be sent back.
    _'max_client_idle_time' is the maximum silence duration from the client.
    Once this limit has been reached, the client (if still here) is dropped,
    and we wait for a new connection.
    """

    def parse_args(
        self,
        server="127.0.0.1",
        sport=4433,
        mycert=None,
        mykey=None,
        preferred_ciphersuite=None,
        is_echo_server=True,
        max_client_idle_time=60,
        curve=None,
        cookie=False,
        timeout=None,
        accept_timeout=None,
        **kargs
    ):

        super().parse_args(mycert=mycert, mykey=mykey, **kargs)

        self.current_crypto_material_name = None
        self.current_asn1_certs = None

        try:
            if ":" in server:
                inet_pton(socket.AF_INET6, server)
            else:
                inet_pton(socket.AF_INET, server)
            tmp = socket.getaddrinfo(server, sport)
        except Exception:
            tmp = socket.getaddrinfo(socket.getfqdn(server), sport)

        self.serversocket = None
        self.ip_family = tmp[0][0]
        self.local_ip = tmp[0][4][0]
        self.local_port = sport
        self.remote_ip = None
        self.remote_port = None

        self.preferred_ciphersuite = preferred_ciphersuite
        self.is_echo_server = is_echo_server
        self.max_client_idle_time = max_client_idle_time
        self.curve = None
        self.timeout = timeout
        self.accept_timeout = accept_timeout
        self.cookie = cookie
        for (group_id, ng) in _tls_named_groups.items():
            if ng == curve:
                self.curve = group_id
        self.selected_cipher_suite = None

    def _do_control(self, ready, *args, **kargs):
        with self.started:
            self.threadid = threading.currentThread().ident

            # Update default parameters
            a = args + self.init_args[len(args) :]
            k = self.init_kargs.copy()
            k.update(kargs)
            self.parse_args(*a, **k)

            # Start the automaton
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

    def get_next_msg(self):
        if self.buffer_in:
            # A message is already available.
            return

        still_getting_len = True
        grablen = 2
        while still_getting_len or len(self.remain_in) < grablen:
            if grablen == 5 and len(self.remain_in) >= 5:
                grablen = struct.unpack("!H", self.remain_in[3:5])[0] + 5
                still_getting_len = False
            elif grablen == 2 and len(self.remain_in) >= 2:
                byte0, byte1 = struct.unpack("BB", self.remain_in[:2])
                if (byte0 in _tls_type) and (byte1 == 3):
                    # Retry following TLS scheme. This will cause failure
                    # for SSLv2 packets with length 0x1{4-7}03.
                    grablen = 5
                else:
                    raise Exception("SSLv2 is not supported")
            elif grablen == 5 and len(self.remain_in) >= 5:
                grablen = struct.unpack("!H", self.remain_in[3:5])[0] + 5

            if grablen <= len(self.remain_in):
                break

            data = self.socket.recv(grablen - len(self.remain_in))
            if not data:
                break
            self.remain_in += data

        if len(self.remain_in) < 2 or len(self.remain_in) != grablen:
            # Remote peer is not willing to respond
            return

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
            else:
                p = p.payload
        # print(self.buffer_in)

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

    def flush_records(self, symbols=None):
        """
        Send all buffered records and update the session accordingly.
        """
        if not symbols:
            symbols = set()
        # self.msg_to_send = b"".join(p.raw_stateful() for p in self.buffer_out)
        msg = []
        for p in self.buffer_out:
            packet_constructed = p.raw_stateful()
            if "TLS13ServerHello" in symbols:
                packet_constructed = (
                    packet_constructed[0:1] + b"\x03\x03" + packet_constructed[3:]
                )
            msg.append(packet_constructed)
        self.msg_to_send = b"".join(msg)

        if self.selected_cipher_suite and "TLS12ServerHello_RSA_EXPORT" in symbols:
            self.socket.send(
                self.msg_to_send[:44]
                + struct.pack(">H", self.selected_cipher_suite)
                + self.msg_to_send[46:]
            )
        else:
            self.socket.send(self.msg_to_send)
        self.buffer_out = []

    def vprint_sessioninfo(self):
        if self.verbose:
            s = self.cur_session
            v = _tls_version[s.tls_version]
            self.vprint("Version       : %s" % v)
            cs = s.wcs.ciphersuite.name
            self.vprint("Cipher suite  : %s" % cs)
            if s.tls_version < 0x0304:
                ms = s.master_secret
            else:
                ms = s.tls13_master_secret
            self.vprint("Master secret : %s" % repr_hex(ms))
            if s.client_certs:
                self.vprint("Client certificate chain: %r" % s.client_certs)

            if s.tls_version >= 0x0304:
                res_secret = s.tls13_derived_secrets["resumption_secret"]
                self.vprint("Resumption master secret : %s" % repr_hex(res_secret))
            self.vprint()

    def http_sessioninfo(self):
        header = "HTTP/1.1 200 OK\r\n"
        header += "Server: Scapy TLS Extension\r\n"
        header += "Content-type: text/html\r\n"
        header += "Content-length: %d\r\n\r\n"
        s = "----- Scapy TLS Server Automaton -----\n\n"
        s += "Information on current TLS session:\n\n"
        s += "Local end     : %s:%d\n" % (self.local_ip, self.local_port)
        s += "Remote end    : %s:%d\n" % (self.remote_ip, self.remote_port)
        v = _tls_version[self.cur_session.tls_version]
        s += "Version       : %s\n" % v
        cs = self.cur_session.wcs.ciphersuite.name
        s += "Cipher suite  : %s\n" % cs
        if self.cur_session.tls_version < 0x0304:
            ms = self.cur_session.master_secret
        else:
            ms = self.cur_session.tls13_master_secret

        s += "Master secret : %s\n" % repr_hex(ms)
        body = "<html><body><pre>%s</pre></body></html>\r\n\r\n" % s
        answer = (header + body) % len(body)
        return answer

    def BIND(self):
        # self.vprint("Starting TLS server automaton.")
        # self.vprint("Receiving 'stop_server' will cause a graceful exit.")
        # self.vprint("Interrupting with Ctrl-Z might leave a loose socket hanging.")  # noqa: E501
        s = socket.socket(self.ip_family, socket.SOCK_STREAM)
        self.serversocket = s
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((self.local_ip, self.local_port))
            if self.accept_timeout:
                s.settimeout(self.accept_timeout)
            s.listen(10)
        except Exception as e:
            m = "Unable to bind on %s:%d! (%s)" % (self.local_ip, self.local_port, e)
            # self.vprint()
            # self.vprint(m)
            # self.vprint("Maybe some server is already listening there?")
            # self.vprint()
            # exit(1)

    def WAITING_CLIENT(self):
        self.buffer_out = []
        self.buffer_in = []
        # self.vprint()
        # self.vprint("Waiting for a new client on %s:%d" % (self.local_ip, self.local_port))
        self.socket, addr = self.serversocket.accept()
        if self.timeout:
            self.socket.settimeout(self.timeout)
        if not isinstance(addr, tuple):
            addr = self.socket.getpeername()
        if len(addr) > 2:
            addr = (addr[0], addr[1])
        self.remote_ip, self.remote_port = addr
        # self.vprint("Accepted connection from %s:%d" % (self.remote_ip, self.remote_port))
        # self.vprint()

    def INIT_TLS_SESSION(self):
        """
        XXX We should offer the right key according to the client's suites. For
        now server_rsa_key is only used for RSAkx, but we should try to replace
        every server_key with both server_rsa_key and server_ecdsa_key.
        """
        self.cur_session = tlsSession(connection_end="server")
        if self.mycert:
            self.cur_session.server_certs = [self.mycert]
        else:
            self.cur_session.server_certs = []
        self.cur_session.server_key = self.mykey
        self.selected_cipher_suite = None
        if isinstance(self.mykey, PrivKeyRSA):
            self.cur_session.server_rsa_key = self.mykey
        # elif isinstance(self.mykey, PrivKeyECDSA):
        #    self.cur_session.server_ecdsa_key = self.mykey

    #                           TLS handshake                                 #

    def tls12_handle_ClientHello(self):
        self.get_next_msg()
        self.raise_on_packet(TLSClientHello, self.HANDLED_CLIENTHELLO)

    def tls13_handle_ClientHello(self):
        self.get_next_msg()
        self.raise_on_packet(TLS13ClientHello, self.tls13_HANDLED_CLIENTHELLO)
        self.buffer_in = []

    #                           TLS handshake                                 #

    def HANDLED_CLIENTHELLO(self):
        pass

    def PREPARE_SERVERFLIGHT1(self):
        self.add_record()

    def tls12_ServerHello(self, is_rsa_export):
        """
        Selecting a cipher suite should be no trouble as we already caught
        the None case previously.

        Also, we do not manage extensions at all.
        """
        self.HANDLED_CLIENTHELLO()
        self.add_record()
        if isinstance(self.mykey, PrivKeyRSA):
            kx = "RSA"
        elif isinstance(self.mykey, PrivKeyECDSA):
            kx = "ECDSA"
        usable_suites = get_usable_ciphersuites(self.cur_pkt.ciphers, kx)
        c = usable_suites[0]
        if self.preferred_ciphersuite in usable_suites:
            c = self.preferred_ciphersuite

        self.selected_cipher_suite = c
        if is_rsa_export:
            # cipher suite = TLS_RSA_EXPORT_WITH_DES40_CBC_SHA
            self.add_msg(TLSServerHello(cipher=0x0008))
            return

        self.add_msg(TLSServerHello(cipher=c))

    def tls12_Certificate(self, name, cert, key):
        if name != self.current_crypto_material_name:
            self.current_crypto_material_name = name
            self.mycert = cert
            self.mykey = key
            if cert:
                self.cur_session.server_certs = [cert]
            else:
                self.cur_session.server_certs = []
            self.cur_session.server_key = key
            self.current_asn1_certs = [
                _ASN1CertAndExt(cert=c) for c in self.cur_session.server_certs
            ]

        self.add_record()
        self.add_msg(TLSCertificate(certs=self.cur_session.server_certs))

    def tls12_ServerKeyExchange(self):
        #        c = self.buffer_out[-1].msg[0].cipher
        #        if not _tls_cipher_suites_cls[c].kx_alg.no_ske:
        self.add_record()
        self.add_msg(TLSServerKeyExchange())

    def tls12_CertificateRequest(self):
        self.add_record()
        self.add_msg(TLSCertificateRequest())

    def tls12_ServerHelloDone(self):
        self.add_record()
        self.add_msg(TLSServerHelloDone())

    def should_send_ServerFlight1(self):
        self.flush_records()

    def WAITING_CLIENTFLIGHT2(self):
        self.get_next_msg()

    def should_handle_ClientCertificate(self):
        self.raise_on_packet(TLSCertificate, self.HANDLED_CLIENTCERTIFICATE)

    def should_handle_ClientKeyExchange(self):
        self.raise_on_packet(TLSClientKeyExchange, self.HANDLED_CLIENTKEYEXCHANGE)

    def should_handle_Alert_from_ClientCertificate(self):
        self.raise_on_packet(TLSAlert, self.HANDLED_ALERT_FROM_CLIENTCERTIFICATE)

    def should_handle_CertificateVerify(self):
        self.raise_on_packet(TLSCertificateVerify, self.HANDLED_CERTIFICATEVERIFY)

    def should_handle_ChangeCipherSpec(self):
        self.raise_on_packet(TLSChangeCipherSpec, self.HANDLED_CHANGECIPHERSPEC)

    def should_handle_ClientFinished(self):
        self.raise_on_packet(TLSFinished, self.HANDLED_CLIENTFINISHED)

    def PREPARE_SERVERFLIGHT2(self):
        self.add_record()

    def tls12_ChangeCipherSpec(self):
        is_tls12 = True
        if self.cur_session.tls_version and self.cur_session.tls_version < 0x0304:
            is_tls12 = False
        self.add_record(is_tls12=is_tls12)
        self.add_msg(TLSChangeCipherSpec())

    def tls12_ServerFinished(self):
        self.add_record()
        self.add_msg(TLSFinished())

    def should_send_ServerFlight2(self):
        self.flush_records()

    #                       TLS 1.3 handshake                                 #
    def tls13_HANDLED_CLIENTHELLO(self):
        pass

    def tls13_HelloRetryRequest(self):
        self.add_record(is_tls13=False)
        if isinstance(self.mykey, PrivKeyRSA):
            kx = "RSA"
        elif isinstance(self.mykey, PrivKeyECDSA):
            kx = "ECDSA"
        usable_suites = get_usable_ciphersuites(self.cur_pkt.ciphers, kx)
        c = usable_suites[0]
        ext = [
            TLS_Ext_SupportedVersion_SH(version="TLS 1.3"),
            TLS_Ext_KeyShare_HRR(selected_group=_tls_named_groups[self.curve]),
        ]  # noqa: E501
        if self.cookie:
            ext += TLS_Ext_Cookie()
        p = TLS13HelloRetryRequest(cipher=c, ext=ext)
        self.add_msg(p)
        # self.flush_records()

    def tls13_ServerHello(self, random_bytes=None):
        self.add_record(is_tls13=False)

        if isinstance(self.mykey, PrivKeyRSA):
            kx = "RSA"
        elif isinstance(self.mykey, PrivKeyECDSA):
            kx = "ECDSA"
        # try:
        usable_suites = get_usable_ciphersuites(self.cur_pkt.ciphers, kx)
        # except:
        #    self.cur_pkt.ciphers = [4866, 4867, 4865, 255]
        #    usable_suites = get_usable_ciphersuites(self.cur_pkt.ciphers, kx)
        c = usable_suites[0]
        group = next(iter(self.cur_session.tls13_client_pubshares))
        ext = [TLS_Ext_SupportedVersion_SH(version="TLS 1.3")]
        # Standard Handshake
        ext += TLS_Ext_KeyShare_SH(server_share=KeyShareEntry(group=group))

        if self.cur_session.sid is not None:
            p = TLS13ServerHello(
                cipher=c, random_bytes=random_bytes, sid=self.cur_session.sid, ext=ext
            )
        else:
            p = TLS13ServerHello(cipher=c, random_bytes=random_bytes, ext=ext)
        self.add_msg(p)

    def tls13_EncryptedExtensions(self):
        self.add_record(is_tls13=True)
        self.add_msg(TLSEncryptedExtensions(extlen=0))

    def tls13_CertificateRequest(self):
        ext = [TLS_Ext_SignatureAlgorithms(sig_algs=["sha256+rsaepss"])]
        p = TLS13CertificateRequest(ext=ext)
        self.add_msg(p)

    def tls13_Certificate(self, name, cert, key):
        if name != self.current_crypto_material_name:
            self.current_crypto_material_name = name
            self.mycert = cert
            self.mykey = key
            if cert:
                self.cur_session.server_certs = [cert]
            else:
                self.cur_session.server_certs = []
            self.cur_session.server_key = key
            self.current_asn1_certs = [
                _ASN1CertAndExt(cert=c) for c in self.cur_session.server_certs
            ]
        self.add_msg(TLS13Certificate(certs=self.current_asn1_certs))

    def tls13_CertificateVerify(self):
        self.add_msg(TLSCertificateVerify())

    def tls13_InvalidCertificateVerify(self):
        self.add_msg(
            TLSCertificateVerify(
                sig=_TLSSignature(
                    sig_alg="md5+anon",
                    sig_val=b"This is definitely NOT a valid signature",
                )
            )
        )

    def tls13_Finished(self):
        self.add_msg(TLSFinished())

    def tls13_should_send_ServerFlight1(self):
        self.flush_records()

    def tls13_WAITING_CLIENTFLIGHT2(self):
        self.get_next_msg()

    def TLS13_HANDLED_CLIENTCERTIFICATE(self):
        pass

    def TLS13_HANDLED_CLIENT_CERTIFICATEVERIFY(self):
        pass

    def tls13_should_handle_ClientCertificateVerify(self):
        self.raise_on_packet(
            TLSCertificateVerify, self.TLS13_HANDLED_CLIENT_CERTIFICATEVERIFY
        )

    def TLS13_MISSING_CLIENTCERTIFICATE(self):
        # self.vprint("Missing ClientCertificate!")
        self.add_record()
        self.add_msg(TLSAlert(level=2, descr=0x74))
        self.flush_records()
        # self.vprint("Sending TLSAlert 116")
        self.socket.close()

    def TLS13_HANDLED_CLIENTFINISHED(self):
        # self.vprint("TLS handshake completed!")
        ##self.vprint_sessioninfo()
        if self.is_echo_server:
            self.vprint("Will now act as a simple echo server.")

    #                       end of TLS 1.3 handshake                          #

    def WAITING_CLIENTDATA(self):
        self.get_next_msg(self.max_client_idle_time, 1)

    def should_handle_ClientData(self, tls_data=None):
        r"""
        The user may type in:
        GET / HTTP/1.1\r\nHost: testserver.com\r\n\r\n
        Special characters are handled so that it becomes a valid HTTP request.
        """
        self.add_record()
        if tls_data is None:
            self.add_msg(TLSApplicationData())
            return
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
        self.add_msg(TLSApplicationData(data=data))

    def should_send_ServerData(self):
        pass

    def tls_fatal_alert(self, descr=None):
        self.add_record()
        self.add_msg(TLSAlert(level=1, descr=descr))

    def FINAL(self):
        # self.vprint("Closing server socket...")
        self.serversocket.close()
        # self.vprint("Ending TLS server automaton.")
