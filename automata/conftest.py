# pylint: disable=redefined-outer-name

import os
import tempfile
from typing import List, Tuple, Set, Iterable
import pytest
from pylstar.Letter import Letter
from pylstar.automata.State import State
from pylstar.automata.Transition import Transition
import pylstar.automata
from automata.automata import load_automaton, Automaton


@pytest.fixture
def tls12_automaton_content() -> str:
    return """CH CKE CCS Fin AppData Close
0, 1, CH, SH+Cert+SHD
1, 2, CKE,
2, 3, CCS,
3, 4, Fin, CCS+Fin
4, 4, AppData, AppData
4, 5, Close, Close
0, 5, *, UnexpectedMsg
1, 5, *, UnexpectedMsg
2, 5, *, UnexpectedMsg
3, 5, *, UnexpectedMsg
4, 5, *, UnexpectedMsg
5, 5, *, UnexpectedMsg"""


@pytest.fixture
def tls12_automaton(tls12_automaton_content) -> Automaton:
    return load_automaton(tls12_automaton_content)


@pytest.fixture
def tls13_automaton() -> Automaton:
    content = """SH EE Cert CV Finished CloseNotify AppData
0, 1, SH,
1, 2, EE,
2, 3, Cert,
3, 4, CV,
4, 5, Finished, Finished+AppData
5, 6, AppData, CloseNotify
6, 6, *, EOF
0, 6, *, UnxpectedMsg
1, 6, *, UnxpectedMsg
2, 6, *, UnxpectedMsg
3, 6, *, UnxpectedMsg
4, 6, *, UnxpectedMsg
5, 6, *, UnxpectedMsg"""
    return load_automaton(content)


@pytest.fixture
def tls13_happy_path() -> List[Tuple[str, Set[str]]]:
    return [
        ("SH", set()),
        ("EE", set()),
        ("Cert", set()),
        ("CV", set()),
        ("Finished", {"Finished", "AppData"}),
    ]


@pytest.fixture
def flawed_tls13_automaton() -> Automaton:
    content = """SH EE Cert CV Finished CloseNotify AppData
0, 1, SH,
1, 2, EE,
2, 5, Finished, Finished+AppData
2, 3, Cert,
3, 4, CV,
4, 5, Finished, Finished+AppData
5, 6, AppData, CloseNotify
6, 6, *, EOF
0, 6, *, UnxpectedMsg
1, 6, *, UnxpectedMsg
2, 6, *, UnxpectedMsg
3, 6, *, UnxpectedMsg
4, 6, *, UnxpectedMsg
5, 6, *, UnxpectedMsg"""
    return load_automaton(content)


@pytest.fixture
def slightly_broken_tls13_automaton() -> Automaton:
    content = """SH EE Cert CV Finished CloseNotify AppData
0, 1, SH, UselessWarning
1, 2, EE,
2, 3, Cert,
3, 4, CV,
4, 5, Finished, Finished+AppData
5, 6, AppData,
6, 6, *, EOF
0, 6, *, UnxpectedMsg
1, 6, *, UnxpectedMsg
2, 6, *, UnxpectedMsg
3, 6, *, UnxpectedMsg
4, 6, *, UnxpectedMsg
5, 6, *, UnxpectedMsg"""
    return load_automaton(content)


@pytest.fixture
def tls13_client_automaton_file() -> Iterable[str]:
    # pylint: disable=line-too-long
    content = """TLS13Certificate TLS13CertificateRequest TLS13CertificateVerify TLS13EmptyCertificate TLS13EncryptedExtensions TLS13InvalidCertificateVerify TLS13ServerHello TLSApplicationData TLSApplicationDataEmpty TLSChangeCipherSpec TLSCloseNotify TLSFinished
0, 1, TLS13ServerHello, No RSP
0, 2, TLSChangeCipherSpec, FatalAlert(unexpected_message)
0, 2, TLS13EncryptedExtensions, FatalAlert(unexpected_message)
0, 2, TLS13CertificateRequest, FatalAlert(unexpected_message)
0, 2, TLS13Certificate, FatalAlert(unexpected_message)
0, 2, TLS13EmptyCertificate, FatalAlert(unexpected_message)
0, 2, TLS13CertificateVerify, FatalAlert(unexpected_message)
0, 2, TLS13InvalidCertificateVerify, FatalAlert(unexpected_message)
0, 2, TLSFinished, FatalAlert(unexpected_message)
0, 2, TLSApplicationData, FatalAlert(unexpected_message)
0, 2, TLSApplicationDataEmpty, FatalAlert(unexpected_message)
0, 2, TLSCloseNotify, FatalAlert(unexpected_message)
2, 2, TLS13ServerHello, EOF
2, 2, TLSChangeCipherSpec, EOF
2, 2, TLS13EncryptedExtensions, EOF
2, 2, TLS13CertificateRequest, EOF
2, 2, TLS13Certificate, EOF
2, 2, TLS13EmptyCertificate, EOF
2, 2, TLS13CertificateVerify, EOF
2, 2, TLS13InvalidCertificateVerify, EOF
2, 2, TLSFinished, EOF
2, 2, TLSApplicationData, EOF
2, 2, TLSApplicationDataEmpty, EOF
2, 2, TLSCloseNotify, EOF
1, 3, TLS13EncryptedExtensions, No RSP
1, 2, TLS13ServerHello, FatalAlert(unexpected_message)
1, 2, TLS13CertificateRequest, FatalAlert(unexpected_message)
1, 2, TLS13Certificate, FatalAlert(unexpected_message)
1, 2, TLS13EmptyCertificate, FatalAlert(unexpected_message)
1, 2, TLS13CertificateVerify, FatalAlert(unexpected_message)
1, 2, TLS13InvalidCertificateVerify, FatalAlert(unexpected_message)
1, 2, TLSFinished, FatalAlert(unexpected_message)
1, 2, TLSApplicationData, FatalAlert(unexpected_message)
1, 2, TLSApplicationDataEmpty, FatalAlert(unexpected_message)
1, 2, TLSChangeCipherSpec, FatalAlert(illegal_parameter)
1, 2, TLSCloseNotify, No RSP
3, 4, TLS13CertificateRequest, No RSP
3, 5, TLS13Certificate, No RSP
3, 2, TLS13ServerHello, UnknownPacket
3, 2, TLSChangeCipherSpec, UnknownPacket
3, 2, TLS13EncryptedExtensions, UnknownPacket
3, 2, TLS13EmptyCertificate, UnknownPacket
3, 2, TLS13CertificateVerify, UnknownPacket
3, 2, TLS13InvalidCertificateVerify, UnknownPacket
3, 2, TLSFinished, UnknownPacket
3, 2, TLSApplicationData, UnknownPacket
3, 2, TLSApplicationDataEmpty, UnknownPacket
3, 2, TLSCloseNotify, No RSP
5, 6, TLS13CertificateVerify, No RSP
5, 2, TLS13ServerHello, UnknownPacket
5, 2, TLSChangeCipherSpec, UnknownPacket
5, 2, TLS13EncryptedExtensions, UnknownPacket
5, 2, TLS13CertificateRequest, UnknownPacket
5, 2, TLS13Certificate, UnknownPacket
5, 2, TLS13EmptyCertificate, UnknownPacket
5, 2, TLS13InvalidCertificateVerify, UnknownPacket
5, 2, TLSFinished, UnknownPacket
5, 2, TLSApplicationData, UnknownPacket
5, 2, TLSApplicationDataEmpty, UnknownPacket
5, 2, TLSCloseNotify, No RSP
6, 2, TLSFinished, TLS13Certificate+TLSFinished+Warning(close_notify)
6, 2, TLS13ServerHello, UnknownPacket
6, 2, TLSChangeCipherSpec, UnknownPacket
6, 2, TLS13EncryptedExtensions, UnknownPacket
6, 2, TLS13CertificateRequest, UnknownPacket
6, 2, TLS13Certificate, UnknownPacket
6, 2, TLS13EmptyCertificate, UnknownPacket
6, 2, TLS13CertificateVerify, UnknownPacket
6, 2, TLS13InvalidCertificateVerify, UnknownPacket
6, 2, TLSApplicationData, UnknownPacket
6, 2, TLSApplicationDataEmpty, UnknownPacket
6, 2, TLSCloseNotify, No RSP
4, 5, TLS13Certificate, No RSP
4, 2, TLS13ServerHello, UnknownPacket
4, 2, TLSChangeCipherSpec, UnknownPacket
4, 2, TLS13EncryptedExtensions, UnknownPacket
4, 2, TLS13CertificateRequest, UnknownPacket
4, 2, TLS13EmptyCertificate, UnknownPacket
4, 2, TLS13CertificateVerify, UnknownPacket
4, 2, TLS13InvalidCertificateVerify, UnknownPacket
4, 2, TLSFinished, UnknownPacket
4, 2, TLSApplicationData, UnknownPacket
4, 2, TLSApplicationDataEmpty, UnknownPacket
4, 2, TLSCloseNotify, No RSP"""
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="UTF-8", delete=False
    ) as open_file:
        open_file.write(content)
        filename = open_file.name
    yield filename
    os.unlink(filename)


# pylint: disable=too-many-locals
@pytest.fixture
def pylstar_automaton():
    l_a = Letter("a")
    l_b = Letter("b")
    l_0 = Letter(0)
    l_1 = Letter(1)
    s_0 = State("0")
    s_1 = State("1")
    s_2 = State("2")
    s_3 = State("3")
    t_1 = Transition("T1", s_3, l_a, l_0)
    t_2 = Transition("T2", s_1, l_b, l_0)
    s_0.transitions = [t_1, t_2]
    t_3 = Transition("T3", s_0, l_a, l_1)
    t_4 = Transition("T4", s_2, l_b, l_1)
    s_1.transitions = [t_3, t_4]
    t_5 = Transition("T5", s_3, l_a, l_0)
    t_6 = Transition("T6", s_0, l_b, l_0)
    s_2.transitions = [t_5, t_6]
    t_7 = Transition("T7", s_3, l_a, l_1)
    t_8 = Transition("T8", s_3, l_b, l_1)
    s_3.transitions = [t_7, t_8]

    input_vocabulary = ["a", "b"]

    content = """a b
0, 3, a, 0
0, 1, b, 0
1, 0, a, 1
1, 2, b, 1
2, 3, a, 0
2, 0, b, 0
3, 3, a, 1
3, 3, b, 1"""

    return (
        pylstar.automata.Automata.Automata(s_0),
        input_vocabulary,
        load_automaton(content),
    )
